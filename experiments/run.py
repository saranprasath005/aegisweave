"""Evaluate synthetic episode generalization, ablations and stress behavior."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
from pathlib import Path
from time import perf_counter, process_time
import json
import platform

import numpy as np
import psutil
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from threadpoolctl import threadpool_limits

from aegisweave.demo import generate_episodes
from aegisweave.detection import DetectionConfig
from aegisweave.ml import (FUSION_VARIANTS, choose_threshold, create_splits, episodes_to_matrix,
                           evaluate_bundle, evaluate_decisions, fit_bundle, metrics)


@threadpool_limits.wrap(limits=1)
def run_experiment(output: Path, seed=42, model_path: Path | None = None) -> dict:
    started, cpu_started = perf_counter(), process_time()
    parts = create_splits(seed)
    bundle = fit_bundle(parts, seed)
    train, tuning, test = (parts[name] for name in ("train", "tuning", "test"))
    baseline = make_pipeline(StandardScaler(), LogisticRegression(max_iter=1200, random_state=seed))
    baseline.fit(train.flow, train.binary)
    unweighted = GradientBoostingClassifier(**bundle.supervised.get_params()).fit(train.flow, train.labels)
    test_components = bundle.components(test.flow, test.behavior, test.history)
    tune_components = bundle.components(tuning.flow, tuning.behavior, tuning.history)
    test_scores = {"baseline_logistic": baseline.predict_proba(test.flow)[:, 1],
                   "supervised": test_components["supervised"], "anomaly_only": test_components["anomaly"],
                   "temporal_only": test_components["temporal"],
                   "supervised_unweighted": 1 - unweighted.predict_proba(test.flow)[:, np.where(unweighted.classes_ == "normal")[0][0]]}
    tune_scores = {"baseline_logistic": baseline.predict_proba(tuning.flow)[:, 1],
                   "supervised": tune_components["supervised"], "anomaly_only": tune_components["anomaly"],
                   "temporal_only": tune_components["temporal"],
                   "supervised_unweighted": 1 - unweighted.predict_proba(tuning.flow)[:, np.where(unweighted.classes_ == "normal")[0][0]]}
    variants = {}
    thresholds = {}
    for name, score in test_scores.items():
        threshold = choose_threshold(tuning.binary, tune_scores[name])
        thresholds[name] = threshold
        variants[name] = metrics(test.binary, score, threshold)
    for name in FUSION_VARIANTS:
        score = bundle.score_components(test_components, name)
        test_scores[name] = score
        thresholds[name] = bundle.thresholds[name]
        variants[name] = metrics(test.binary, score, bundle.thresholds[name])
    # The without-fusion ablation is the exact supervised branch, not a second
    # hand-picked threshold or a made-up surrogate.
    variants["without_fusion"] = dict(variants["supervised"])
    variants["without_fusion"]["equivalent_to"] = "supervised"
    bundle.metadata["metrics"] = evaluate_bundle(bundle, test)
    unknown = episodes_to_matrix(generate_episodes(24, seed + 6001, unknown=True))
    shifted = episodes_to_matrix(generate_episodes(24, seed + 7001, shift=True))
    u = bundle.components(unknown.flow, unknown.behavior, unknown.history)
    u_scores = bundle.score_components(u)
    heldout = unknown.labels == "unknown_beacon"
    unknown_metrics = metrics(unknown.binary, u_scores, bundle.thresholds["full"])
    unknown_metrics.update({"withheld_family": "unknown_beacon", "withheld_from_all_training_and_validation": True,
                            "withheld_rows": int(heldout.sum()),
                            "withheld_family_alert_recall": float((u_scores[heldout] >= bundle.thresholds["full"]).mean()),
                            "withheld_anomaly_rate": float((u["anomaly"][heldout] >= DetectionConfig().anomaly_threshold).mean()),
                            "interpretation": "Synthetic unknown-pattern stress only, not evidence of zero-day detection."})
    shift_values = bundle.components(shifted.flow, shifted.behavior, shifted.history)
    stress = {"heldout_unknown": unknown_metrics,
              "covariate_shift": metrics(shifted.binary, bundle.score_components(shift_values), bundle.thresholds["full"])}
    # Benign-looking manipulation stress changes inputs only, not labels. This
    # is NOT a gradient-based adversarial attack or a security guarantee.
    mutated = test.flow.copy()
    attack = test.binary == 1
    manipulated_columns = [5, 6, 14, 15, 16]
    for column in manipulated_columns:
        mutated[attack, column] = bundle.flow_center[column]
    manipulated = bundle.components(mutated, test.behavior, test.history)
    stress["feature_manipulation"] = metrics(test.binary, bundle.score_components(manipulated), bundle.thresholds["full"])
    stress["feature_manipulation"]["description"] = "Attack flow rate/port/failure/SYN coordinates replaced with frozen benign medians; original causal host windows preserved. Not necessarily realizable packet traces."
    # Analyst-facing outcomes: every held-out flow through predict -> decide -> attribute.
    # The ablation removes only the class-support layer; everything else is identical.
    decisions = {"test": evaluate_decisions(bundle, test), "withheld_unknown": evaluate_decisions(bundle, unknown)}
    support_layer, bundle.class_support = bundle.class_support, None
    try:
        decisions["ablation_without_class_support"] = {"test": evaluate_decisions(bundle, test)["summary"],
                                                       "withheld_unknown": evaluate_decisions(bundle, unknown)}
    finally:
        bundle.class_support = support_layer
    bundle.metadata["decision_metrics"] = decisions["test"]
    latency = []
    for flow, context in list(zip(test.flows, test.contexts))[:100]:
        start = perf_counter()
        bundle.predict(flow, context)
        latency.append((perf_counter() - start) * 1000)
    batch_latency = {}
    for name, fn in {"baseline_logistic": lambda: baseline.predict_proba(test.flow),
                     "supervised": lambda: bundle._probabilities(test.flow),
                     "anomaly_only": lambda: bundle.anomaly_model.score_samples(test.flow),
                     "temporal_only": lambda: bundle.temporal_model.predict_proba(test.behavior),
                     "full_components_and_fusion": lambda: bundle.score_components(bundle.components(test.flow, test.behavior, test.history))}.items():
        start = perf_counter()
        fn()
        batch_latency[name] = (perf_counter() - start) * 1000 / len(test.labels)
    # Paired bootstrap resamples whole host episodes rather than correlated rows.
    rng = np.random.default_rng(seed + 818)
    episode_ids = np.unique(test.episode_ids)
    deltas = []
    for _ in range(250):
        ids = rng.choice(episode_ids, len(episode_ids), replace=True)
        indexes = np.concatenate([np.where(test.episode_ids == group)[0] for group in ids])
        from sklearn.metrics import f1_score
        full_f1 = f1_score(test.binary[indexes], test_scores["full"][indexes] >= thresholds["full"], zero_division=0)
        supervised_f1 = f1_score(test.binary[indexes], test_scores["supervised"][indexes] >= thresholds["supervised"], zero_division=0)
        deltas.append(full_f1 - supervised_f1)
    result = {"experiment": "AegisWeave independent synthetic episode research", "simulated": True,
              "generated_at": datetime.now(timezone.utc).isoformat(), "seed": seed,
              "warning": "These measured synthetic results cannot establish network deployment effectiveness or scientific novelty.",
              "protocol": {"split": "independent host episodes; train/calibration/fusion/threshold-tuning/test",
                           "fit": "Train only; temperature and benign rank calibration on calibration; stacking on fusion; FPR-budget threshold on tuning",
                           "threshold_objective": "maximize binary F1 subject to validation FPR <= 0.05; test FPR may be higher",
                           "temporal": "causal windows reset at each independent episode; no future events",
                           "baseline_selection": "All architecture parameters fixed before final test; no test-driven tuning"},
              "leakage": bundle.metadata["leakage_checks"], "variants": variants,
              "multiclass": bundle.metadata["metrics"]["per_class"], "stress": stress,
              "decisions": decisions,
              "paired_episode_bootstrap": {"resamples": 250, "metric": "full F1 minus supervised F1",
                                            "observed_delta": variants["full"]["f1"] - variants["supervised"]["f1"],
                                            "percentile_95_interval": list(map(float, np.quantile(deltas, [.025, .975])))},
              "performance": {"single_event_model_and_local_explanation_ms_p50": float(np.median(latency)),
                              "single_event_model_and_local_explanation_ms_p95": float(np.quantile(latency, .95)),
                              "single_event_samples": len(latency), "batch_inference_ms_per_flow": batch_latency,
                              "process_rss_bytes_at_end": psutil.Process().memory_info().rss,
                              "cpu_seconds": process_time() - cpu_started, "wall_seconds": perf_counter() - started,
                              "platform": platform.platform(), "processor": platform.processor(), "threads": 1},
              "model": bundle.metadata}
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, allow_nan=False), encoding="utf-8")
    if model_path is not None:
        bundle.save(Path(model_path))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("experiments/results/synthetic.json"))
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--model", type=Path)
    args = parser.parse_args()
    result = run_experiment(args.output, args.seed, args.model)
    print(json.dumps({"output": str(args.output), "variants": {name: {k: value[k] for k in ("f1", "false_positive_rate", "roc_auc")} for name, value in result["variants"].items()},
                      "decisions": {"test": result["decisions"]["test"]["summary"],
                                    "withheld_unknown": result["decisions"]["withheld_unknown"]["per_label"].get("unknown_beacon"),
                                    "withheld_counts": result["decisions"]["withheld_unknown"]["decision_counts"].get("unknown_beacon"),
                                    "ablation_withheld_counts": result["decisions"]["ablation_without_class_support"]["withheld_unknown"]["decision_counts"].get("unknown_beacon")},
                      "performance": result["performance"]}, indent=2))


if __name__ == "__main__":
    main()
