"""Train and evaluate the full live pipeline on real IoT-23 Zeek traffic.

Three fits, all through the serving collector/behaviour/feature code:
  A temporal_blocks        every class; the deployable research model (--model)
  B temporal_blocks        attack_attempt withheld from every fitting partition (open-set test)
  C leave_capture_out      captures 8-1 and honeypot 5-1 never used for fitting
Protocol constants below were fixed before any IoT-23 result was observed.
"""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import platform
from time import perf_counter

import joblib
import numpy as np
import psutil
from threadpoolctl import threadpool_limits

from aegisweave.corpus import IOT23, build_split, capture_name, file_sha256, load_capture
from aegisweave.ml import FUSION_VARIANTS, choose_threshold, evaluate_decisions, fit_bundle, metrics

HELD_OUT = ("CTU-IoT-Malware-Capture-8-1", "CTU-Honeypot-Capture-5-1")
WITHHELD = ("attack_attempt",)
MAX_LATENESS = 300.
RESERVOIR = 1000
WARNING = ("IoT-23 is a set of 2018-2019 lab captures of a few IoT devices and malware samples on one research network. "
           "These measurements do not establish performance on other networks. Temporal-block tests share hosts and "
           "capture periods with training; leave-capture-out is the stronger generalization evidence.")


def load_corpus(paths, seed, cache_dir: Path | None):
    sources = {name: hashlib.sha256((Path(__file__).parents[1] / "aegisweave" / name).read_bytes()).hexdigest()
               for name in ("collectors.py", "behavior.py", "features.py", "corpus.py", "schema.py")}
    hashes = {capture_name(p): file_sha256(p) for p in paths}
    key = hashlib.sha256(json.dumps({"files": hashes, "sources": sources, "seed": seed, "reservoir": RESERVOIR,
                                     "lateness": MAX_LATENESS, "held_out": HELD_OUT}, sort_keys=True).encode()).hexdigest()[:20]
    cached = cache_dir / f"iot23-{key}.joblib" if cache_dir else None
    if cached and cached.exists():
        print(f"Loading cached corpus {cached.name}", flush=True)
        return joblib.load(cached), True
    captures = []
    for path in paths:
        started = perf_counter()
        capture = load_capture(path, held_out=capture_name(path) in HELD_OUT, seed=seed, reservoir=RESERVOIR, max_lateness=MAX_LATENESS)
        print(f"  {capture.name}: {len(capture.kept)} records in {perf_counter() - started:.1f}s", flush=True)
        captures.append(capture)
    if cached:
        cached.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(captures, cached)
        # Caches are keyed by data and source hashes; older keys can never be loaded again.
        for stale in cached.parent.glob("iot23-*.joblib"):
            if stale != cached:
                stale.unlink()
    return captures, False


def _layer_scores(bundle, part):
    values = bundle.components(part.flow, part.behavior, part.history)
    return values, {"supervised": values["supervised"], "anomaly_only": values["anomaly"], "temporal_only": values["temporal"]}


@threadpool_limits.wrap(limits=1)
def evaluate(bundle, split) -> dict:
    test, tuning = split.parts["test"], split.parts["tuning"]
    started = perf_counter()
    values, layers = _layer_scores(bundle, test)
    batch_ms = (perf_counter() - started) * 1000 / len(test.labels)
    _, tuning_layers = _layer_scores(bundle, tuning)
    names = bundle.supervised.classes_[np.argmax(values["probabilities"], axis=1)]
    score = bundle.score_components(values)
    threshold = bundle.thresholds["full"]
    result = {"binary_all_test_rows": metrics(test.binary, score, threshold, test.labels, names)}
    if len(np.unique(test.binary[split.unseen_test])) == 2:
        result["binary_unseen_flow_vectors"] = metrics(test.binary[split.unseen_test], score[split.unseen_test], threshold)
    result["fusion_variants"] = {name: metrics(test.binary, bundle.score_components(values, name), bundle.thresholds[name])
                                 for name in FUSION_VARIANTS}
    result["single_layers"] = {name: metrics(test.binary, layer, choose_threshold(tuning.binary, tuning_layers[name]))
                               for name, layer in layers.items()}
    per_capture = {}
    for capture in sorted(set(test.episode_ids.tolist())):
        mask = test.episode_ids == capture
        y, predicted = test.binary[mask], score[mask] >= threshold
        per_capture[capture] = {"rows": int(mask.sum()), "attack_rows": int(y.sum()),
                                "detection_rate": float(predicted[y == 1].mean()) if y.any() else None,
                                "false_positive_rate": float(predicted[y == 0].mean()) if (y == 0).any() else None}
    result["per_capture"] = per_capture
    result["decisions"] = evaluate_decisions(bundle, split.decision_sample)
    result["batch_components_and_fusion_ms_per_flow"] = batch_ms
    return result


def fit(split, seed, protocol_name, captures):
    dataset = {"id_prefix": "aegisweave-iot23", "name": f"IoT-23 Zeek conn logs ({len(captures)} captures), {protocol_name}",
               "simulated": False, "status": "research-real-data",
               "implementation_files": ("corpus.py", "collectors.py", "schema.py"),
               "provenance": {**IOT23, "captures": {c.name: c.sha256 for c in captures}, "protocol": protocol_name,
                              "max_lateness_seconds": MAX_LATENESS, "warning": WARNING}}
    started = perf_counter()
    bundle = fit_bundle(split.parts, seed, dataset=dataset, isolation=split.report)
    return bundle, perf_counter() - started


def _attach_evaluation(bundle, experiment, protocol, output):
    bundle.metadata["metrics"] = experiment["binary_all_test_rows"]
    bundle.metadata["decision_metrics"] = experiment["decisions"]
    bundle.metadata["evaluation"] = {"protocol": protocol, "results_file": str(output), "warning": WARNING,
                                     "coverage_gaps": experiment["split"]["coverage_gaps"],
                                     "held_out_captures": experiment["split"]["held_out_captures"]}


def run(paths, output: Path, seed=42, model_path: Path | None = None, cache_dir: Path | None = None,
        lco_model_path: Path | None = None) -> dict:
    started, cpu = perf_counter(), __import__("time").process_time()
    captures, from_cache = load_corpus(paths, seed, cache_dir)
    corpus = {c.name: {"records": int(len(c.kept)), "represented": int(c.kept.sum()), "labels": dict(Counter(c.labels.tolist())),
                       "excluded": c.excluded, "reordered_within_tolerance": int(c.reordered),
                       "isolated_beyond_tolerance": int(c.isolated), "sha256": c.sha256} for c in captures}
    experiments = {}

    split = build_split(captures, "temporal_blocks", seed=seed)
    bundle, seconds = fit(split, seed, "temporal_blocks", captures)
    experiments["A_temporal_blocks"] = {"split": split.report, "fit_seconds": seconds, **evaluate(bundle, split)}
    deployable = bundle
    print("A fitted and evaluated", flush=True)

    split = build_split(captures, "temporal_blocks", withheld_classes=WITHHELD, seed=seed)
    bundle, seconds = fit(split, seed, "temporal_blocks_withheld_attack_attempt", captures)
    open_set = {"split": split.report, "fit_seconds": seconds, **evaluate(bundle, split)}
    support, bundle.class_support = bundle.class_support, None
    try:
        open_set["ablation_without_class_support"] = evaluate_decisions(bundle, split.decision_sample)
    finally:
        bundle.class_support = support
    experiments["B_open_set_withheld_attack_attempt"] = open_set
    print("B fitted and evaluated", flush=True)

    try:
        split = build_split(captures, "leave_capture_out", held_out=HELD_OUT, seed=seed)
    except ValueError as exc:
        experiments["C_leave_capture_out"] = {"status": "not_evaluable", "reason": str(exc)}
    else:
        bundle, seconds = fit(split, seed, "leave_capture_out", captures)
        experiments["C_leave_capture_out"] = {"split": split.report, "fit_seconds": seconds, **evaluate(bundle, split)}
        if lco_model_path is not None:
            _attach_evaluation(bundle, experiments["C_leave_capture_out"], "leave_capture_out", output)
            bundle.save(lco_model_path)
    print("C:", experiments["C_leave_capture_out"].get("status", "fitted and evaluated"), flush=True)

    result = {"experiment": "IoT-23 real Zeek traffic through the live AegisWeave pipeline", "simulated": False,
              "generated_at": datetime.now(timezone.utc).isoformat(), "seed": seed, "warning": WARNING, "dataset": IOT23,
              "protocol": {"held_out_captures": HELD_OUT, "withheld_classes": WITHHELD, "behaviour_reordering_tolerance_seconds": MAX_LATENESS,
                           "blocks_per_capture": 20, "boundary_purge_seconds": 60, "caps_per_capture_label": split.report["caps_per_capture_label"],
                           "threshold_selection": "tuning partition only (FPR budget 0.05)", "fixed_before_results": True,
                           "corpus_cache_used": from_cache},
              "corpus": corpus, "experiments": experiments,
              "performance": {"wall_seconds": perf_counter() - started, "cpu_seconds": __import__("time").process_time() - cpu,
                              "process_rss_bytes_at_end": psutil.Process().memory_info().rss, "platform": platform.platform(), "threads": 1}}
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, allow_nan=False, default=str), encoding="utf-8")
    if model_path is not None:
        _attach_evaluation(deployable, experiments["A_temporal_blocks"], "temporal_blocks", output)
        deployable.metadata["evaluation"]["leave_capture_out_binary"] = experiments["C_leave_capture_out"].get(
            "binary_all_test_rows", experiments["C_leave_capture_out"])
        deployable.save(model_path)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--data", type=Path, default=Path("var/datasets/iot23"))
    parser.add_argument("--output", type=Path, default=Path("experiments/results/iot23.json"))
    parser.add_argument("--model", type=Path, help="Save fit A as a verified deployable artifact, e.g. var/models/iot23")
    parser.add_argument("--model-lco", type=Path, help="Save fit C (never saw the held-out captures), e.g. var/models/iot23-lco, "
                                                       "for replaying truly unseen real traffic through the live API")
    parser.add_argument("--cache", type=Path, default=Path("var/datasets/iot23/cache"))
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()
    paths = sorted(args.data.glob("*.conn.log.labeled"))
    if not paths:
        raise SystemExit(f"No *.conn.log.labeled files in {args.data}")
    result = run(paths, args.output, args.seed, args.model, args.cache, args.model_lco)
    summary = {}
    for name, experiment in result["experiments"].items():
        if "binary_all_test_rows" not in experiment:
            summary[name] = experiment
            continue
        binary = experiment["binary_all_test_rows"]
        summary[name] = {"test_rows": binary["samples"], **{k: round(binary[k], 4) for k in ("precision", "recall", "f1", "false_positive_rate")},
                         "roc_auc": binary["roc_auc"], "decisions": experiment["decisions"]["summary"]}
    print(json.dumps({"output": str(args.output), "summary": summary, "wall_seconds": round(result["performance"]["wall_seconds"], 1)}, indent=2))


if __name__ == "__main__":
    main()
