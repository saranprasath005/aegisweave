"""Capture-separated binary CIC2017 benchmark; never a live Zeek model artifact.

Fixed protocol: fit Tuesday/Wednesday, calibrate FPR on Thursday benign flows,
evaluate Friday and the separate Monday benign capture. No test-set threshold tuning.
"""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
from time import perf_counter

import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier, IsolationForest
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.utils.class_weight import compute_sample_weight
from threadpoolctl import threadpool_limits

from aegisweave.corpus import file_sha256
from aegisweave.datasets import load_cic
from aegisweave.ml import metrics

FIT_DAYS = ("tuesday", "wednesday")
CALIBRATION_DAY = "thursday"
TEST_DAYS = ("friday", "monday")


def benign_threshold(scores, max_fpr=.01):
    scores = np.asarray(scores, dtype=float)
    if not len(scores) or not np.isfinite(scores).all() or not 0 <= max_fpr < 1:
        raise ValueError("Finite benign calibration scores and an FPR budget in [0,1) are required")
    return float(np.nextafter(np.quantile(scores, 1 - max_fpr, method="higher"), np.inf))


def load_staged(root, day):
    folder = Path(root) / day
    manifest = json.loads((folder / "manifest.json").read_text(encoding="utf-8"))
    path = folder / "capture.csv"
    if manifest.get("capture_id") != "cic2017-improved-" + day or manifest.get("attempted_flow_policy") != "benign":
        raise ValueError("Unexpected capture identity or attempted-flow policy")
    if file_sha256(path) != manifest["output_sha256"]:
        raise ValueError("Staged capture checksum mismatch")
    data = load_cic(path)
    if len(data.labels) != manifest["rows_retained"]:
        raise ValueError("Staged row count differs from manifest")
    return data, manifest


@threadpool_limits.wrap(limits=1)
def run(root, output, seed=42, cap_per_class=200000):
    output = Path(output)
    if output.exists():
        raise FileExistsError("Preserve prior evaluation; choose a new output path")
    if cap_per_class < 1:
        raise ValueError("cap_per_class must be positive")
    started = perf_counter()
    training = [load_staged(root, day) for day in FIT_DAYS]
    calibration, cal_manifest = load_staged(root, CALIBRATION_DAY)
    x = np.vstack([d.x for d, _ in training])
    y = np.concatenate([d.binary for d, _ in training])
    fitting_hashes = set(np.concatenate([d.hashes for d, _ in training]))
    # Calibration uses only vectors not present anywhere in the fitting captures.
    cal_unseen = np.fromiter((h not in fitting_hashes for h in calibration.hashes), dtype=bool)
    benign = (calibration.binary == 0) & cal_unseen
    if benign.sum() < 100:
        raise ValueError("Insufficient independent benign calibration vectors")
    rng = np.random.default_rng(seed)
    indices = np.concatenate([rng.choice(np.flatnonzero(y == label), min(cap_per_class, int((y == label).sum())), replace=False) for label in (0, 1)])
    x, y = x[indices], y[indices]
    if len(np.unique(y)) != 2:
        raise ValueError("Fitting captures require both benign and attack rows")
    weights = compute_sample_weight("balanced", y)
    logistic = make_pipeline(StandardScaler(), LogisticRegression(max_iter=1000, random_state=seed))
    logistic.fit(x, y, logisticregression__sample_weight=weights)
    boosted = HistGradientBoostingClassifier(max_iter=100, max_leaf_nodes=15, min_samples_leaf=30,
                                             l2_regularization=2., early_stopping=False, random_state=seed)
    boosted.fit(x, y, sample_weight=weights)
    anomaly = IsolationForest(n_estimators=100, max_samples=256, random_state=seed, n_jobs=1).fit(x[y == 0])
    # IsolationForest scores are mapped monotonically to [0,1], not called probabilities.
    scorers = {"logistic": lambda a: logistic.predict_proba(a)[:, 1],
               "boosted_trees": lambda a: boosted.predict_proba(a)[:, 1],
               "benign_isolation": lambda a: np.clip(-anomaly.score_samples(a), 0, 1)}
    thresholds = {name: benign_threshold(score(calibration.x[benign])) for name, score in scorers.items()}
    print("Fitted baselines and froze thresholds before test scoring", flush=True)
    seen = fitting_hashes | set(calibration.hashes)
    results = {}
    manifests = {day: m for day, (_, m) in zip(FIT_DAYS, training)}
    manifests[CALIBRATION_DAY] = cal_manifest
    for day in TEST_DAYS:
        data, manifest = load_staged(root, day)
        manifests[day] = manifest
        unseen = np.fromiter((h not in seen for h in data.hashes), dtype=bool)
        result = {"rows": len(data.labels), "unseen_vectors": int(unseen.sum()), "models": {}}
        for name, score in scorers.items():
            values = score(data.x)
            result["models"][name] = {"all_rows": metrics(data.binary, values, thresholds[name]),
                                      "unseen_vectors": metrics(data.binary[unseen], values[unseen], thresholds[name]) if unseen.any() else None}
            result["models"][name]["per_label_detection"] = {
                label: {"rows": int((data.labels == label).sum()),
                        "flagged": int(((data.labels == label) & (values >= thresholds[name])).sum()),
                        "flagged_rate": float((values[data.labels == label] >= thresholds[name]).mean())}
                for label in sorted(set(data.labels.tolist()))}
        results[day] = result
        print(f"Evaluated {day}: {len(data.labels)} rows", flush=True)
    report = {"experiment": "CICIDS2017 corrected capture-separated numeric-counter baselines", "simulated": False,
              "generated_at": datetime.now(timezone.utc).isoformat(), "seed": seed,
              "protocol": {"fit_days": FIT_DAYS, "calibration_day": CALIBRATION_DAY, "test_days": TEST_DAYS,
                           "test_used_for_selection": False, "cap_per_binary_class": cap_per_class,
                           "fitting_rows": len(y), "calibration_benign_unseen_rows": int(benign.sum()),
                           "threshold_rule": "strictly above 99th percentile of independent benign calibration scores",
                           "attempted_policy": "benign per correction authors' recommendation"},
              "thresholds": thresholds, "captures": manifests, "results": results,
              "wall_seconds": perf_counter() - started,
              "limitations": ["Same experimental network across days; not an office-network pilot",
                              "Reduced numeric counters only; no behavior history or attack attribution",
                              "Byte-count equivalence with live Zeek counters is unverified",
                              "Calibration/test duplicate vectors are excluded only in separately reported unseen subsets",
                              "Isolation scores are not calibrated probabilities; their Brier score is descriptive only"],
              "deployable_artifact": False}
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, allow_nan=False), encoding="utf-8")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", type=Path, default=Path("var/datasets/cicids2017-improved/staged"))
    parser.add_argument("--output", type=Path, default=Path("experiments/results/cic2017-baseline-v1.json"))
    args = parser.parse_args()
    result = run(args.data, args.output)
    print(json.dumps({"output": str(args.output), "wall_seconds": result["wall_seconds"]}))
