"""Official-split UNSW-NB15 reduced-feature benchmark, optional external CIC test.

The saved public benchmark is deliberately not a deployable streaming bundle:
its CSVs do not carry the causal identity/time context required by the live model.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
from pathlib import Path
from time import perf_counter, process_time
import json
import platform

import numpy as np
import psutil
from scipy.optimize import minimize_scalar
from scipy.special import softmax
from sklearn.ensemble import HistGradientBoostingClassifier, IsolationForest
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import log_loss
from sklearn.model_selection import GroupShuffleSplit, train_test_split
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.utils.class_weight import compute_sample_weight
from threadpoolctl import threadpool_limits

from aegisweave.datasets import UNSW_MIRROR, load_cic, load_unsw
from aegisweave.detection import DetectionConfig
from aegisweave.features import COMMON_FEATURES
from aegisweave.ml import ClassSupport, _logit, _percentile, choose_threshold, metrics

# Chosen before any open-set result was observed: the four smallest UNSW-NB15 attack
# families stand in for attack types absent from training.
DEFAULT_WITHHELD_FAMILIES = ("analysis", "backdoor", "shellcode", "worms")


def _attribution_outcomes(classes, probabilities, support, labels, known_attacks, config):
    """Count what an analyst would be told about attack TYPE, with and without the support check."""
    predicted = classes[np.argmax(probabilities, axis=1)]
    confidence = probabilities.max(axis=1)
    support_of_predicted = np.asarray([support[c][i] if c in support else 0. for i, c in enumerate(predicted)])
    is_attack_class = np.isin(predicted, list(known_attacks))
    confident = confidence >= config.minimum_confidence
    supported = support_of_predicted <= config.attribution_percentile
    attributed = is_attack_class & confident & supported
    without_support_check = is_attack_class & confident

    def rates(mask):
        n = int(mask.sum())
        if not n:
            return {"rows": 0}
        return {"rows": n,
                "attributed_correct_type": float((attributed & (predicted == labels))[mask].mean()),
                "attributed_wrong_type": float((attributed & (predicted != labels))[mask].mean()),
                "withheld_outside_class_support": float((is_attack_class & confident & ~supported)[mask].mean()),
                "withheld_low_confidence": float((is_attack_class & ~confident)[mask].mean()),
                "predicted_normal": float((~is_attack_class)[mask].mean()),
                "ablation_without_support_wrong_type": float((without_support_check & (predicted != labels))[mask].mean()),
                "ablation_without_support_correct_type": float((without_support_check & (predicted == labels))[mask].mean())}
    return rates


def open_set_attribution(train_data, test_data, families, seed=42, max_train=60000):
    """Leave-families-out attribution test on real flows (reduced counters, no temporal context).

    Withheld families are removed from EVERY training-derived partition. Measures how often
    their test flows receive a confident, supported, WRONG known attack type, and the cost of
    the support check on known families (correct types withheld).
    """
    config = DetectionConfig()
    families = sorted(set(families))
    missing = set(families) - set(train_data.labels)
    if missing:
        raise ValueError(f"Unknown UNSW families: {sorted(missing)}")
    keep = np.flatnonzero(~np.isin(train_data.labels, families))
    if 0 < max_train < len(keep):
        keep, _ = train_test_split(keep, train_size=max_train, stratify=train_data.labels[keep], random_state=seed)
    x, labels, hashes = train_data.x[keep], train_data.labels[keep], train_data.hashes[keep]
    train_idx, cal_idx = next(GroupShuffleSplit(n_splits=1, train_size=.8, random_state=seed).split(x, labels, hashes))
    if set(hashes[train_idx]) & set(hashes[cal_idx]):
        raise AssertionError("Duplicate normalized rows crossed the calibration boundary")
    classifier = HistGradientBoostingClassifier(max_iter=95, max_leaf_nodes=15, learning_rate=.09, min_samples_leaf=30,
                                                l2_regularization=2., early_stopping=False, random_state=seed)
    classifier.fit(x[train_idx], labels[train_idx], sample_weight=compute_sample_weight("balanced", labels[train_idx]))
    raw_cal = np.clip(classifier.predict_proba(x[cal_idx]), 1e-9, 1.)
    temp = float(minimize_scalar(lambda t: log_loss(labels[cal_idx], softmax(np.log(raw_cal) / t, axis=1), labels=classifier.classes_),
                                 bounds=(.4, 4.), method="bounded").x)
    support_model = ClassSupport(seed=seed).fit(x[train_idx], labels[train_idx], x[cal_idx], labels[cal_idx])
    started = perf_counter()
    probabilities = softmax(np.log(np.clip(classifier.predict_proba(test_data.x), 1e-9, 1.)) / temp, axis=1)
    support = support_model.percentiles(test_data.x)
    support_ms = (perf_counter() - started) * 1000 / len(test_data.labels)
    known_attacks = set(map(str, classifier.classes_)) - {"normal"}
    rates = _attribution_outcomes(classifier.classes_, probabilities, support, test_data.labels, known_attacks, config)
    withheld = np.isin(test_data.labels, families)
    known_attack_rows = ~withheld & (test_data.labels != "normal")
    return {"withheld_families": families, "selection": "four smallest families, fixed before results were observed",
            "training_rows": int(len(train_idx)), "calibration_rows": int(len(cal_idx)), "temperature": temp,
            "attribution_rule": {"minimum_confidence": config.minimum_confidence, "attribution_percentile": config.attribution_percentile,
                                 "method": support_model.describe()},
            "withheld_family_test_rows": rates(withheld),
            "per_withheld_family": {family: rates(test_data.labels == family) for family in families},
            "known_attack_family_test_rows": rates(known_attack_rows),
            "benign_test_rows": rates(test_data.labels == "normal"),
            "classifier_and_support_ms_per_flow_batch": support_ms,
            "interpretation": "Reduced generic counters only; UNSW families overlap heavily in these features, so this measures the support check's value under hard conditions, not zero-day detection."}


@threadpool_limits.wrap(limits=1)
def run_public(train_path: Path, test_path: Path, output: Path, seed=42, max_train=60000,
               external_cic: Path | None = None, withheld_families=DEFAULT_WITHHELD_FAMILIES) -> dict:
    started, cpu_started = perf_counter(), process_time()
    train_data, test_data = load_unsw(train_path), load_unsw(test_path)
    if train_data.provenance["sha256"] == test_data.provenance["sha256"]:
        raise ValueError("Training and testing files are identical")
    # All designated training rows are considered for split grouping; optional
    # sampling is stratified and performed ONLY inside the training file.
    all_indexes = np.arange(len(train_data.labels))
    if 0 < max_train < len(all_indexes):
        all_indexes, _ = train_test_split(all_indexes, train_size=max_train, stratify=train_data.labels, random_state=seed)
    x, labels, hashes = train_data.x[all_indexes], train_data.labels[all_indexes], train_data.hashes[all_indexes]
    # Exact normalized duplicates share a group so they cannot contaminate any
    # training-derived calibration, stacking, or threshold-selection partition.
    splitter = GroupShuffleSplit(n_splits=1, train_size=.7, random_state=seed)
    train_idx, held_idx = next(splitter.split(x, labels, hashes))
    splitter = GroupShuffleSplit(n_splits=1, train_size=1 / 3, random_state=seed + 1)
    cal_local, rest_local = next(splitter.split(x[held_idx], labels[held_idx], hashes[held_idx]))
    cal_idx, rest_idx = held_idx[cal_local], held_idx[rest_local]
    splitter = GroupShuffleSplit(n_splits=1, train_size=.5, random_state=seed + 2)
    fusion_local, tune_local = next(splitter.split(x[rest_idx], labels[rest_idx], hashes[rest_idx]))
    fusion_idx, tune_idx = rest_idx[fusion_local], rest_idx[tune_local]
    groups = {"train": train_idx, "calibration": cal_idx, "fusion": fusion_idx, "tuning": tune_idx}
    for name, indexes in groups.items():
        if len(np.unique(labels[indexes])) < 2:
            raise ValueError(f"Insufficient classes in {name}; use larger training input")
    hashes_by_part = {name: set(hashes[indexes]) for name, indexes in groups.items()}
    for a in hashes_by_part:
        for b in hashes_by_part:
            if a != b and hashes_by_part[a] & hashes_by_part[b]:
                raise AssertionError("Duplicate normalized rows crossed validation boundary")
    binary = (labels != "normal").astype(int)
    classifier = HistGradientBoostingClassifier(max_iter=95, max_leaf_nodes=15, learning_rate=.09,
                                                min_samples_leaf=30, l2_regularization=2.,
                                                early_stopping=False, random_state=seed)
    classifier.fit(x[train_idx], labels[train_idx], sample_weight=compute_sample_weight("balanced", labels[train_idx]))
    normal_index = int(np.where(classifier.classes_ == "normal")[0][0])
    raw_cal = np.clip(classifier.predict_proba(x[cal_idx]), 1e-9, 1.)
    temp = float(minimize_scalar(lambda t: log_loss(labels[cal_idx], softmax(np.log(raw_cal) / t, axis=1), labels=classifier.classes_),
                                 bounds=(.4, 4.), method="bounded").x)
    anomaly_model = IsolationForest(n_estimators=80, max_samples=256, random_state=seed, n_jobs=1).fit(x[train_idx][binary[train_idx] == 0])
    anomaly_reference = np.sort(-anomaly_model.score_samples(x[cal_idx][binary[cal_idx] == 0]))
    baseline = make_pipeline(StandardScaler(), LogisticRegression(max_iter=1200, random_state=seed)).fit(x[train_idx], binary[train_idx])

    def components(matrix):
        p = softmax(np.log(np.clip(classifier.predict_proba(matrix), 1e-9, 1.)) / temp, axis=1)
        known = 1 - p[:, normal_index]
        anomaly = np.maximum(0, 2 * _percentile(anomaly_reference, -anomaly_model.score_samples(matrix)) - 1)
        entropy = -(p * np.log(np.clip(p, 1e-9, 1.))).sum(axis=1) / np.log(p.shape[1])
        return {"p": p, "supervised": known, "anomaly_only": anomaly, "evidence": np.column_stack([_logit(known), anomaly, entropy])}

    fusion_values, tuning_values = components(x[fusion_idx]), components(x[tune_idx])
    fusion = make_pipeline(StandardScaler(), LogisticRegression(C=.5, max_iter=1000, random_state=seed)).fit(fusion_values["evidence"], binary[fusion_idx])
    tuning_scores = {"baseline_logistic": baseline.predict_proba(x[tune_idx])[:, 1],
                     "supervised": tuning_values["supervised"], "anomaly_only": tuning_values["anomaly_only"],
                     "reduced_hybrid": fusion.predict_proba(tuning_values["evidence"])[:, 1]}
    thresholds = {name: choose_threshold(binary[tune_idx], score) for name, score in tuning_scores.items()}
    # Preserve the designated test file. Report its complete score separately
    # from the stricter subset excluding any normalized vector seen in any
    # training-derived partition. Test features are not used to fit/select anything.
    designated_training_hashes = set(train_data.hashes)
    overlap = np.asarray([h in designated_training_hashes for h in test_data.hashes])
    unknown_classes = sorted(set(test_data.labels) - set(classifier.classes_))
    test_start = perf_counter()
    tested = components(test_data.x)
    inference_seconds = perf_counter() - test_start
    test_scores = {"baseline_logistic": baseline.predict_proba(test_data.x)[:, 1],
                   "supervised": tested["supervised"], "anomaly_only": tested["anomaly_only"],
                   "reduced_hybrid": fusion.predict_proba(tested["evidence"])[:, 1]}
    all_results, uncontaminated = {}, {}
    for name, score in test_scores.items():
        all_results[name] = metrics(test_data.binary, score, thresholds[name])
        if (~overlap).any():
            uncontaminated[name] = metrics(test_data.binary[~overlap], score[~overlap], thresholds[name])
    predicted = classifier.classes_[np.argmax(tested["p"], axis=1)]
    multiclass = metrics(test_data.binary, tested["supervised"], thresholds["supervised"], test_data.labels, predicted)["per_class"]
    external = {"status": "not_run", "reason": "CIC capture CSV not supplied; no cross-dataset effectiveness claim."}
    if external_cic is not None:
        other = load_cic(external_cic)
        other_values = components(other.x)
        external = {"status": "measured", "training_dataset": "UNSW-NB15", "test_dataset": other.provenance,
                    "no_refit": True, "class_semantics": "binary attack vs benign; attack categories are not equated across corpora",
                    "metrics": metrics(other.binary, fusion.predict_proba(other_values["evidence"])[:, 1], thresholds["reduced_hybrid"])}
    # Measured transformed-feature model latency; excludes CSV parsing/window
    # construction because neither belongs to this reduced offline interface.
    single_latency = []
    for row in test_data.x[:80]:
        tick = perf_counter()
        fusion.predict_proba(components(row[None, :])["evidence"])
        single_latency.append((perf_counter() - tick) * 1000)
    result = {"experiment": "UNSW-NB15 reduced generic-counter public benchmark", "simulated": False,
              "generated_at": datetime.now(timezone.utc).isoformat(), "seed": seed,
              "warning": "A lab-generated public dataset is not live deployment evidence. Full causal AegisWeave temporal architecture is not evaluated here.",
              "provenance": {"train": train_data.provenance, "test": test_data.provenance,
                             "download_mirror": UNSW_MIRROR, "mirror_authenticity": "Primary SharePoint download timed out; mirror bytes hashed, not independently authenticated by the authors",
                             "expected_official_rows": {"train": 175341, "test": 82332}},
              "protocol": {"features": list(COMMON_FEATURES), "seeded_training_sample": len(all_indexes),
                           "designated_split_preserved": True, "validation_group": "exact normalized feature SHA256",
                           "training_partitions": {name: {"rows": len(indexes), "class_counts": {str(c): int((labels[indexes] == c).sum()) for c in np.unique(labels[indexes])}} for name, indexes in groups.items()},
                           "preprocessing": "fixed log1p/rate features; scalers fit on their own training partitions only",
                           "imbalance": "balanced supervised sample weights; no oversampling; validation FPR budget 0.05",
                           "temperature": temp, "unknown_test_classes": unknown_classes,
                           "temporal_available": False, "behavior_profile_available": False},
              "leakage": {"train_validation_duplicate_groups_disjoint": True,
                          "test_rows_matching_any_designated_train_normalized_vector": int(overlap.sum()),
                          "test_rows_without_train_feature_overlap": int((~overlap).sum()),
                          "interpretation": "Some collisions may be independent flows with identical reduced counters; filtering is conservative. Official test itself is never reshuffled."},
              "official_test_all_rows": all_results, "test_without_train_feature_overlap": uncontaminated,
              "supervised_multiclass_official_test": multiclass,
              "external_validation": external,
              "open_set_attribution": open_set_attribution(train_data, test_data, withheld_families, seed, max_train) if withheld_families else {"status": "not_run"},
              "hyperparameters": {"supervised": classifier.get_params(), "anomaly": anomaly_model.get_params(), "fusion_C": .5},
              "performance": {"components_batch_ms_per_flow": inference_seconds * 1000 / len(test_data.labels),
                              "reduced_hybrid_single_flow_ms_p50": float(np.median(single_latency)),
                              "reduced_hybrid_single_flow_ms_p95": float(np.quantile(single_latency, .95)),
                              "process_rss_bytes_at_end": psutil.Process().memory_info().rss,
                              "cpu_seconds": process_time() - cpu_started, "wall_seconds": perf_counter() - started,
                              "platform": platform.platform(), "threads": 1},
              "deployment": "benchmark-only: never loaded into streaming production interface"}
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, allow_nan=False), encoding="utf-8")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--train", type=Path, required=True)
    parser.add_argument("--test", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=Path("experiments/results/unsw.json"))
    parser.add_argument("--max-train", type=int, default=60000, help="Training-file-only stratified sample; 0 means every designated training row")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--external-cic", type=Path)
    parser.add_argument("--withhold-families", default=",".join(DEFAULT_WITHHELD_FAMILIES),
                        help="Comma-separated UNSW families removed from training for the open-set attribution test; empty disables it")
    args = parser.parse_args()
    families = tuple(x.strip().lower() for x in args.withhold_families.split(",") if x.strip())
    result = run_public(args.train, args.test, args.output, args.seed, args.max_train, args.external_cic, families)
    print(json.dumps({"output": str(args.output), "leakage": result["leakage"], "unseen_feature_test": result["test_without_train_feature_overlap"],
                      "open_set_attribution": {k: result["open_set_attribution"].get(k) for k in ("withheld_family_test_rows", "known_attack_family_test_rows", "benign_test_rows")},
                      "performance": result["performance"]}, indent=2))


if __name__ == "__main__":
    main()
