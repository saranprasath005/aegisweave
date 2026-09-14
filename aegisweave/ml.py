"""Reproducible complementary models and validation-learned evidence fusion."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from time import perf_counter
import hashlib
import io
import json
import os
import platform
import tempfile

import joblib
import numpy as np
import sklearn
from scipy.optimize import minimize_scalar
from scipy.special import expit, softmax
from sklearn.ensemble import GradientBoostingClassifier, HistGradientBoostingClassifier, IsolationForest
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (accuracy_score, average_precision_score, brier_score_loss,
                            classification_report, confusion_matrix, f1_score, log_loss,
                            precision_score, recall_score, roc_auc_score)
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.utils.class_weight import compute_sample_weight
from threadpoolctl import threadpool_limits

from .behavior import BehaviorEngine
from .demo import generate_episodes
from .features import BEHAVIOR_FEATURES, FEATURE_SCHEMA, FLOW_FEATURES, behavior_features, flow_features

MODEL_VERSION = "1.1.0"
ATTRIBUTION_METHOD = "class-conditional 5-NN robust-scaled distance, percentile among held-out calibration flows of the same class"
META_FEATURES = ("supervised_log_odds", "anomaly_evidence", "temporal_log_odds", "profile_evidence",
                 "class_entropy", "model_disagreement", "history_reliability")
FUSION_VARIANTS = {"full": (0, 1, 2, 3, 4, 5, 6), "hybrid": (0, 1, 4),
                   "without_anomaly": (0, 2, 3, 4, 6), "without_temporal": (0, 1, 3, 4),
                   "without_profile": (0, 1, 2, 4, 5, 6)}


@dataclass
class MatrixSet:
    flow: np.ndarray
    behavior: np.ndarray
    labels: np.ndarray
    history: np.ndarray
    episode_ids: np.ndarray
    flows: list
    contexts: list[dict]

    @property
    def binary(self):
        return (self.labels != "normal").astype(int)


def episodes_to_matrix(episodes) -> MatrixSet:
    rows, behavior, labels, histories, groups, flows, contexts = [], [], [], [], [], [], []
    for episode in episodes:
        engine = BehaviorEngine()
        for flow, label in zip(episode.flows, episode.labels):
            context = engine.observe(flow)
            rows.append(flow_features(flow))
            behavior.append(behavior_features(context))
            histories.append(float(context["available"]) * min(1., context["history_count"] / 8))
            labels.append(label)
            groups.append(episode.episode_id)
            flows.append(flow)
            contexts.append(context)
    return MatrixSet(np.asarray(rows), np.asarray(behavior), np.asarray(labels), np.asarray(histories),
                     np.asarray(groups), flows, contexts)


def check_split_isolation(partitions: dict[str, MatrixSet]) -> dict:
    """Identifiers/groups and exact model-input rows must not cross any split."""
    known_groups, known_rows, known_events = {}, {}, {}
    report = {}
    for name, part in partitions.items():
        for group in set(part.episode_ids):
            if group in known_groups:
                raise ValueError(f"Episode leakage between {known_groups[group]} and {name}")
            known_groups[group] = name
        row_hashes = set(hashlib.sha256(row.tobytes()).hexdigest() for row in part.flow)
        overlap = row_hashes.intersection(known_rows)
        if overlap:
            raise ValueError(f"Exact normalized feature leakage into {name}: {len(overlap)} rows")
        known_rows.update({h: name for h in row_hashes})
        for flow in part.flows:
            if flow.event_id in known_events:
                raise ValueError("Duplicate event identifier across partitions")
            known_events[flow.event_id] = name
        report[name] = {"rows": len(part.labels), "episodes": len(set(part.episode_ids)),
                        "class_counts": {str(c): int((part.labels == c).sum()) for c in np.unique(part.labels)}}
    return {"passed": True, "checks": ["episode disjointness", "event identity", "exact normalized feature hash"], "partitions": report}


def metrics(y, score, threshold=.5, labels=None, predictions=None) -> dict:
    y, score = np.asarray(y, dtype=int), np.asarray(score, dtype=float)
    predicted = score >= threshold
    tn, fp, fn, tp = confusion_matrix(y, predicted, labels=[0, 1]).ravel()
    out = {"accuracy": float(accuracy_score(y, predicted)), "precision": float(precision_score(y, predicted, zero_division=0)),
           "recall": float(recall_score(y, predicted, zero_division=0)), "f1": float(f1_score(y, predicted, zero_division=0)),
           "false_positive_rate": float(fp / max(1, fp + tn)), "false_negative_rate": float(fn / max(1, fn + tp)),
           "roc_auc": float(roc_auc_score(y, score)) if len(np.unique(y)) == 2 else None,
           "pr_auc": float(average_precision_score(y, score)) if y.any() else None,
           "brier_score": float(brier_score_loss(y, score)), "threshold": float(threshold),
           "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)}, "samples": len(y)}
    if labels is not None and predictions is not None:
        out["per_class"] = classification_report(labels, predictions, output_dict=True, zero_division=0)
    return out


def choose_threshold(y, score, max_fpr=.05) -> float:
    # Selection exclusively uses the threshold-tuning validation partition.
    y, score = np.asarray(y), np.asarray(score, dtype=float)
    if not len(y) or y.shape != score.shape or not np.isfinite(score).all() or not 0 <= max_fpr <= 1:
        raise ValueError("Threshold tuning needs matching finite scores and a valid FPR budget")
    # Rank-based anomaly evidence can saturate at exactly 1 for benign flows.
    # An explicit all-negative operating point must always be available.
    all_negative = np.nextafter(max(1., float(score.max())), np.inf)
    choices = np.unique(np.r_[np.linspace(.05, .95, 37), score, all_negative])
    best = (-1., -1., .5)
    for threshold in choices:
        predicted = score >= threshold
        fp = ((predicted == 1) & (y == 0)).sum() / max(1, (y == 0).sum())
        if fp <= max_fpr:
            objective = float(f1_score(y, predicted, zero_division=0))
            candidate = (objective, -float(fp), float(threshold))
            if candidate > best:
                best = candidate
    return float(best[2])


def _percentile(reference, values):
    return np.searchsorted(reference, values, side="right") / max(1, len(reference))


def _logit(values):
    values = np.clip(values, 1e-5, 1 - 1e-5)
    return np.log(values / (1 - values))


def _attack_log_odds(normal_probability):
    # Computed from the normal-class probability so saturated attack probabilities
    # (1 - 1e-9) still produce measurable sensitivity differences.
    p = np.clip(normal_probability, 1e-15, 1 - 1e-15)
    return np.log1p(-p) - np.log(p)


class ClassSupport:
    """Open-set attribution evidence: does a flow resemble TRAINING flows of a class?

    Distance is the mean Euclidean distance to the k nearest training flows of that
    class after a robust scaling fitted on training flows only. It is ranked against
    the same distance for held-out calibration flows of the class, so a percentile of
    1.0 means the flow is farther from the class than every held-out example.
    Support is necessary, not sufficient, for attribution; it is not a class probability.
    """

    def __init__(self, k=5, max_reference=2500, min_calibration=10, seed=42):
        self.k, self.max_reference, self.min_calibration, self.seed = k, max_reference, min_calibration, seed

    def fit(self, train_x, train_labels, calibration_x, calibration_labels):
        train_x, calibration_x = np.asarray(train_x, dtype=float), np.asarray(calibration_x, dtype=float)
        self.center = np.median(train_x, axis=0)
        self.scale = np.maximum(np.subtract(*np.percentile(train_x, [75, 25], axis=0)), .15)
        rng = np.random.default_rng(self.seed)
        self.references, self.calibration = {}, {}
        for label in np.unique(train_labels):
            rows = self._scaled(train_x[train_labels == label])
            if len(rows) > self.max_reference:
                rows = rows[np.sort(rng.choice(len(rows), self.max_reference, replace=False))]
            self.references[str(label)] = rows
            held = calibration_x[calibration_labels == label]
            # Classes without enough held-out examples get no support estimate
            # rather than an overconfident one.
            if len(held) >= self.min_calibration and len(rows) >= self.k:
                self.calibration[str(label)] = np.sort(self._distance(self._scaled(held), str(label)))
        return self

    def _scaled(self, rows):
        return (np.asarray(rows, dtype=float) - self.center) / self.scale

    def _distance(self, scaled, label, chunk=512):
        reference = self.references[label]
        reference_norm = np.einsum("ij,ij->i", reference, reference)
        k = min(self.k, len(reference))
        out = np.empty(len(scaled))
        for start in range(0, len(scaled), chunk):
            block = scaled[start:start + chunk]
            squared = np.einsum("ij,ij->i", block, block)[:, None] + reference_norm[None, :] - 2 * block @ reference.T
            nearest = np.partition(np.maximum(squared, 0), k - 1, axis=1)[:, :k]
            out[start:start + chunk] = np.sqrt(nearest).mean(axis=1)
        return out

    def percentiles(self, rows) -> dict[str, np.ndarray]:
        scaled = self._scaled(rows)
        return {label: _percentile(reference, self._distance(scaled, label)) for label, reference in self.calibration.items()}

    def describe(self) -> dict:
        return {"method": ATTRIBUTION_METHOD, "k": self.k,
                "reference_rows": {label: len(rows) for label, rows in self.references.items()},
                "calibration_rows": {label: len(rows) for label, rows in self.calibration.items()},
                "unsupported_classes": sorted(set(self.references) - set(self.calibration))}


class ModelBundle:
    def __init__(self):
        self.metadata = {}

    def _probabilities(self, rows):
        raw = np.clip(self.supervised.predict_proba(rows), 1e-9, 1.)
        return softmax(np.log(raw) / self.temperature, axis=1)

    def _profile_distance(self, rows):
        return np.mean(np.minimum(np.abs((rows - self.profile_center) / self.profile_scale), 20), axis=1)

    @threadpool_limits.wrap(limits=1)
    def components(self, flow_rows, behavior_rows, history):
        probs = self._probabilities(flow_rows)
        supervised = 1 - probs[:, self.normal_index]
        raw_anomaly = -self.anomaly_model.score_samples(flow_rows)
        anomaly = np.maximum(0., 2 * _percentile(self.anomaly_reference, raw_anomaly) - 1)
        temporal = self.temporal_model.predict_proba(behavior_rows)[:, 1]
        profile = np.maximum(0., 2 * _percentile(self.profile_reference, self._profile_distance(behavior_rows)) - 1)
        entropy = -(probs * np.log(np.clip(probs, 1e-9, 1))).sum(axis=1) / np.log(probs.shape[1])
        reliability = self.reliabilities
        evidence = np.column_stack([
            _logit(supervised) * reliability["supervised"], anomaly * reliability["anomaly"],
            _logit(temporal) * history * reliability["temporal"], profile * history * reliability["profile"],
            entropy, np.std(np.column_stack([supervised, anomaly, temporal * history]), axis=1), history,
        ])
        return {"probabilities": probs, "supervised": supervised, "anomaly": anomaly,
                "temporal": temporal, "profile": profile, "entropy": entropy, "evidence": evidence,
                "history": history, "raw_anomaly": raw_anomaly}

    def score_components(self, components, variant="full"):
        columns = FUSION_VARIANTS[variant]
        return self.fusers[variant].predict_proba(components["evidence"][:, columns])[:, 1]

    def predict(self, flow, context: dict, variant="full") -> dict:
        if variant not in FUSION_VARIANTS:
            raise ValueError("Unknown fusion configuration")
        x = flow_features(flow)[None, :]
        b = behavior_features(context)[None, :]
        missing = list(getattr(flow, "missing_features", []))
        affected = set()
        for field in missing:
            if field in ("syn_ratio", "failed"):
                affected.add(FLOW_FEATURES.index(field))
            if field == "reverse_packets":
                affected.update((3, 5, 7, 8))
            if field == "reverse_bytes":
                affected.update((4, 6, 7, 9))
        for index in affected:
            x[0, index] = self.flow_center[index]
        incomplete_behavior = set(context.get("incomplete_features", []))
        for index, feature in enumerate(BEHAVIOR_FEATURES):
            if feature in incomplete_behavior:
                b[0, index] = self.profile_center[index]
        history = np.array([float(context.get("available", False)) * min(1., context.get("history_count", 0) / 8)
                            * (1 - len(incomplete_behavior) / len(BEHAVIOR_FEATURES))])
        values = self.components(x, b, history)
        probabilities = values["probabilities"][0]
        best = int(np.argmax(probabilities))
        label = str(self.supervised.classes_[best])
        anomaly_score, profile = float(values["anomaly"][0]), float(values["profile"][0])
        # Local sensitivity evaluates the actual model after replacing one measured
        # input with its benign training median. Every measured feature is tried and
        # ranked by effect. The counterfactual vector may not be a realizable flow;
        # never present this as a causal explanation or an additive SHAP attribution.
        deviations = np.abs((x[0] - self.flow_center) / self.flow_scale)
        indexes = np.asarray([i for i in range(len(FLOW_FEATURES)) if i not in affected])
        changed = np.repeat(x, len(indexes), axis=0)
        changed[np.arange(len(indexes)), indexes] = self.flow_center[indexes]
        anomaly_changed = -self.anomaly_model.score_samples(changed)
        changed_normal = self._probabilities(changed)[:, self.normal_index]
        log_odds = float(_attack_log_odds(probabilities[self.normal_index]))
        log_odds_delta = log_odds - _attack_log_odds(changed_normal)
        anomaly_delta = values["raw_anomaly"][0] - anomaly_changed
        by_class = np.lexsort((-deviations[indexes], -np.abs(log_odds_delta)))[:3]
        by_anomaly = np.lexsort((-deviations[indexes], -np.abs(anomaly_delta)))[:2]
        ranked = list(dict.fromkeys([*by_class.tolist(), *by_anomaly.tolist()]))
        contributions = [{"feature": FLOW_FEATURES[indexes[row]], "value": float(x[0, indexes[row]]),
                          "benign_median": float(self.flow_center[indexes[row]]),
                          "robust_deviation": float(deviations[indexes[row]]),
                          "anomaly_score_delta": float(anomaly_delta[row]),
                          "attack_probability_delta": float(values["supervised"][0] - (1 - changed_normal[row])),
                          "attack_log_odds_delta": float(log_odds_delta[row]),
                          "method": "one-feature replacement sensitivity (not causal)"}
                         for row in ranked]
        columns = FUSION_VARIANTS[variant]
        fuser = self.fusers[variant]
        scaled = fuser.named_steps["standardscaler"].transform(values["evidence"][:, columns])[0]
        terms = scaled * fuser.named_steps["logisticregression"].coef_[0]
        fusion_contributions = {META_FEATURES[column]: float(terms[i]) for i, column in enumerate(columns)}
        fusion_contributions["intercept"] = float(fuser.named_steps["logisticregression"].intercept_[0])
        score = float(self.score_components(values, variant)[0])
        # Reliability of the EVIDENCE: calibration quality, host history and measurement
        # completeness. Class entropy is deliberately excluded; it describes which attack
        # type, which the confidence gate already governs, and must not block benign calls.
        reliability = float(np.clip(self.reliabilities["supervised"] * (.7 + .3 * history[0]) * (1 - len(affected) / len(FLOW_FEATURES)), 0, 1))
        support = self.class_support.percentiles(x) if getattr(self, "class_support", None) is not None else {}
        class_support = {name: float(value[0]) for name, value in support.items()}
        attribution = {"model_class": label, "support_percentile": class_support.get(label),
                       "class_support": class_support,
                       "method": ATTRIBUTION_METHOD if class_support else "unavailable for this model artifact"}
        explanations = [f"Supervised model assigned {label} probability {probabilities[best]:.3f}; normalized class entropy {values['entropy'][0]:.3f}.",
                        f"Benign-only isolation model anomaly evidence {anomaly_score:.3f} (calibrated against held-out benign flows)."]
        if attribution["support_percentile"] is not None:
            explanations.append(f"Class-support check: this flow is farther from training '{label}' flows than {100 * attribution['support_percentile']:.1f}% of held-out '{label}' flows.")
        strongest = contributions[0] if contributions else None
        if strongest and abs(strongest["attack_log_odds_delta"]) >= .05:
            direction = "raises" if strongest["attack_log_odds_delta"] > 0 else "lowers"
            explanations.append(f"Most influential measured feature: {strongest['feature']}={strongest['value']:.2f} (benign median {strongest['benign_median']:.2f}) "
                                f"{direction} supervised attack log-odds by {abs(strongest['attack_log_odds_delta']):.2f} versus the benign median; one-feature sensitivity, not causation.")
        elif strongest:
            explanations.append("No single measured feature changes the supervised attack log-odds by 0.05 or more when reset to its benign median; the class decision depends on several features jointly.")
        if contributions and anomaly_score >= .5:
            unusual = max(contributions, key=lambda c: c["anomaly_score_delta"])
            if unusual["anomaly_score_delta"] > 0:
                explanations.append(f"Largest anomaly sensitivity: resetting {unusual['feature']} ({unusual['value']:.2f}, {unusual['robust_deviation']:.1f} robust deviations from benign median) "
                                    f"reduces the raw isolation score by {unusual['anomaly_score_delta']:.3f}.")
        top_terms = sorted(((k, v) for k, v in fusion_contributions.items() if k != "intercept"), key=lambda kv: -abs(kv[1]))[:2]
        explanations.append("Largest fusion evidence terms (standardized log-odds): " + ", ".join(f"{k.replace('_', ' ')} {v:+.2f}" for k, v in top_terms) + f"; fused attack score {score:.3f}.")
        if context.get("available"):
            explanations.extend(context.get("evidence", []))
            explanations.append(f"Learned temporal attack probability {values['temporal'][0]:.3f}; benign-window profile evidence {profile:.3f}.")
        else:
            explanations.append("Temporal evidence is discounted: insufficient ordered host history.")
        if context.get("history_truncated"):
            explanations.append("Host history reached its event cap; window counts are lower bounds.")
        if missing:
            explanations.append(f"Unmeasured fields {', '.join(missing)} use frozen training-benign feature medians; evidence reliability is discounted.")
        return {"prediction": {"class": label, "confidence": float(probabilities[best]),
                               "probabilities": {str(c): float(p) for c, p in zip(self.supervised.classes_, probabilities)},
                               "entropy": float(values["entropy"][0])},
                "anomaly": {"score": anomaly_score, "is_anomalous": anomaly_score >= .95, "contributions": contributions},
                "attribution": attribution,
                "behavior": {"deviation": profile * float(history[0]), "temporal_score": float(values["temporal"][0]),
                             "temporal_consistency": float(context.get("temporal_consistency", 0)),
                             "available": bool(context.get("available", False)), "history_reliability": float(history[0])},
                "fusion": {"score": score, "reliability": reliability, "contributions": fusion_contributions,
                           "contribution_units": "log-odds", "variant": variant,
                           "validation_threshold": self.thresholds[variant]},
                "explanation": explanations,
                "model": {**{key: self.metadata[key] for key in ("id", "version", "dataset", "simulated_training", "feature_schema")},
                          "training_fingerprint": self.metadata.get("training_fingerprint"),
                          "artifact_sha256": getattr(self, "artifact_sha256", None)}}

    def save(self, path: Path):
        path = Path(path)
        path.mkdir(parents=True, exist_ok=True)
        # The digest cannot be part of its own serialized input. Each save hashes
        # the final artifact; predictions expose it once saved or loaded.
        self.__dict__.pop("artifact_sha256", None)
        temporary = []
        try:
            with tempfile.NamedTemporaryFile(dir=path, prefix=".bundle-", suffix=".tmp", delete=False) as handle:
                temporary.append(Path(handle.name))
                joblib.dump(self, handle, compress=3)
                handle.flush()
                os.fsync(handle.fileno())
            digest = hashlib.sha256(temporary[0].read_bytes()).hexdigest()
            manifest = {"format": 1, "sha256": digest,
                        "feature_schema": FEATURE_SCHEMA, "sklearn_version": sklearn.__version__, "metadata": self.metadata}
            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path, prefix=".manifest-", suffix=".tmp", delete=False) as handle:
                temporary.append(Path(handle.name))
                handle.write(json.dumps(manifest, indent=2, allow_nan=False))
                handle.flush()
                os.fsync(handle.fileno())
            # Each rename is atomic. A reload between the two replacements fails
            # its digest check safely; an already-loaded model stays usable.
            os.replace(temporary[0], path / "bundle.joblib")
            os.replace(temporary[1], path / "manifest.json")
            self.artifact_sha256 = digest
        finally:
            for temporary_file in temporary:
                temporary_file.unlink(missing_ok=True)

    @classmethod
    def load(cls, path: Path):
        """Load only administrator-owned local artifacts, never telemetry uploads.

        SHA-256 detects corruption, not an attacker able to replace BOTH files.
        Joblib is executable serialization; OS access control is the trust boundary.
        """
        path = Path(path)
        manifest = json.loads((path / "manifest.json").read_text(encoding="utf-8"))
        payload = path / "bundle.joblib"
        if manifest.get("format") != 1 or manifest.get("feature_schema") != FEATURE_SCHEMA:
            raise ValueError("Model manifest or feature schema mismatch")
        if manifest.get("sklearn_version") != sklearn.__version__:
            raise ValueError("Model sklearn version mismatch; retrain in current environment")
        payload_bytes = payload.read_bytes()
        if hashlib.sha256(payload_bytes).hexdigest() != manifest.get("sha256"):
            raise ValueError("Model payload hash mismatch")
        # Deserialize the exact bytes verified above, not a second filesystem read.
        result = joblib.load(io.BytesIO(payload_bytes))
        if not isinstance(result, cls) or result.metadata != manifest["metadata"]:
            raise ValueError("Model metadata mismatch")
        result.artifact_sha256 = manifest["sha256"]
        return result


def create_splits(seed=42, scale=1.) -> dict[str, MatrixSet]:
    sizes = {"train": 80, "calibration": 24, "fusion": 24, "tuning": 24, "test": 40}
    return {name: episodes_to_matrix(generate_episodes(max(12, int(count * scale)), seed + i * 1009))
            for i, (name, count) in enumerate(sizes.items())}


@threadpool_limits.wrap(limits=1)
def fit_bundle(parts: dict[str, MatrixSet], seed=42) -> ModelBundle:
    start = perf_counter()
    isolation = check_split_isolation(parts)
    train, calibration, fusion, tuning = (parts[key] for key in ("train", "calibration", "fusion", "tuning"))
    bundle = ModelBundle()
    bundle.supervised = GradientBoostingClassifier(n_estimators=65, learning_rate=.075, max_depth=2,
                                                   min_samples_leaf=12, random_state=seed)
    bundle.supervised.fit(train.flow, train.labels, sample_weight=compute_sample_weight("balanced", train.labels))
    bundle.normal_index = int(np.where(bundle.supervised.classes_ == "normal")[0][0])
    raw_probabilities = np.clip(bundle.supervised.predict_proba(calibration.flow), 1e-9, 1.)
    bundle.temperature = float(minimize_scalar(lambda t: log_loss(calibration.labels, softmax(np.log(raw_probabilities) / t, axis=1),
                                                                 labels=bundle.supervised.classes_), bounds=(.4, 4.), method="bounded").x)
    normal_rows = train.flow[train.binary == 0]
    bundle.anomaly_model = IsolationForest(n_estimators=80, max_samples=min(256, len(normal_rows)),
                                           contamination="auto", random_state=seed, n_jobs=1).fit(normal_rows)
    bundle.anomaly_reference = np.sort(-bundle.anomaly_model.score_samples(calibration.flow[calibration.binary == 0]))
    normal_behavior = train.behavior[train.binary == 0]
    bundle.profile_center = np.median(normal_behavior, axis=0)
    bundle.profile_scale = np.maximum(np.subtract(*np.percentile(normal_behavior, [75, 25], axis=0)), .15)
    bundle.profile_reference = np.sort(bundle._profile_distance(calibration.behavior[calibration.binary == 0]))
    bundle.flow_center = np.median(normal_rows, axis=0)
    bundle.flow_scale = np.maximum(np.subtract(*np.percentile(normal_rows, [75, 25], axis=0)), .15)
    bundle.class_support = ClassSupport(seed=seed).fit(train.flow, train.labels, calibration.flow, calibration.labels)
    bundle.temporal_model = HistGradientBoostingClassifier(max_iter=65, max_leaf_nodes=12, learning_rate=.075,
                                                         min_samples_leaf=16, l2_regularization=1., early_stopping=False,
                                                         random_state=seed)
    bundle.temporal_model.fit(train.behavior, train.binary, sample_weight=compute_sample_weight("balanced", train.binary))
    bundle.reliabilities = dict.fromkeys(("supervised", "anomaly", "temporal", "profile"), 1.)
    calibrated = bundle.components(calibration.flow, calibration.behavior, calibration.history)
    bundle.reliabilities = {key: float(max(.1, 1 - brier_score_loss(calibration.binary, calibrated[key]))) for key in bundle.reliabilities}
    fused = bundle.components(fusion.flow, fusion.behavior, fusion.history)
    tuned = bundle.components(tuning.flow, tuning.behavior, tuning.history)
    bundle.fusers, bundle.thresholds = {}, {}
    for name, columns in FUSION_VARIANTS.items():
        classifier = make_pipeline(StandardScaler(), LogisticRegression(C=.5, max_iter=1200, random_state=seed))
        classifier.fit(fused["evidence"][:, columns], fusion.binary)
        bundle.fusers[name] = classifier
        bundle.thresholds[name] = choose_threshold(tuning.binary, bundle.score_components(tuned, name))
    importances = bundle.supervised.feature_importances_
    implementation = {name: hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
                      for name in ("ml.py", "features.py", "behavior.py", "demo.py")}
    identity = hashlib.sha256(json.dumps({"implementation": implementation, "seed": seed, "sklearn": sklearn.__version__}, sort_keys=True).encode())
    for partition in (train, calibration, fusion, tuning):
        identity.update(partition.flow.astype("<f8").tobytes())
        identity.update(partition.behavior.astype("<f8").tobytes())
        identity.update(partition.labels.astype("U").tobytes())
    fingerprint = identity.hexdigest()
    bundle.metadata = {"id": f"aegisweave-synthetic-{seed}-{fingerprint[:12]}", "version": MODEL_VERSION,
                       "training_fingerprint": fingerprint, "implementation_sha256": implementation,
                       "dataset": "AegisWeave synthetic independent host episodes v1", "simulated_training": True,
                       "feature_schema": FEATURE_SCHEMA, "trained_at": datetime.now(timezone.utc).isoformat(),
                       "training_seconds": perf_counter() - start, "status": "demo-only",
                       "training_rows": len(train.labels), "leakage_checks": isolation,
                       "feature_importance": [{"feature": f, "importance": float(v), "method": "training impurity (global)"}
                                              for f, v in sorted(zip(FLOW_FEATURES, importances), key=lambda pair: -pair[1])],
                       "metrics": {}, "thresholds": bundle.thresholds, "reliabilities": bundle.reliabilities,
                       "temperature": bundle.temperature, "attribution": bundle.class_support.describe(),
                       "hyperparameters": {"supervised": bundle.supervised.get_params(), "temporal": bundle.temporal_model.get_params(),
                                           "anomaly": bundle.anomaly_model.get_params(), "fusion_C": .5},
                       "versions": {"python": platform.python_version(), "sklearn": sklearn.__version__, "numpy": np.__version__},
                       "provenance": {"generator": "aegisweave.demo.generate_episodes", "seed": seed,
                                      "warning": "Synthetic evaluation validates implementation only; it is not real-world efficacy."}}
    return bundle


def evaluate_bundle(bundle, test: MatrixSet) -> dict:
    components = bundle.components(test.flow, test.behavior, test.history)
    names = bundle.supervised.classes_[np.argmax(components["probabilities"], axis=1)]
    return metrics(test.binary, bundle.score_components(components), bundle.thresholds["full"], test.labels, names)


def evaluate_decisions(bundle, part: MatrixSet, config=None) -> dict:
    """Analyst-facing outcomes through the exact serving path: predict -> decide -> attribute.

    Binary score metrics cannot show abstention, unattributed novelty or invented attack
    types; this evaluation counts every final decision and attribution per true label.
    """
    from dataclasses import asdict
    from .detection import DECISIONS, DetectionConfig, attribute, decide
    config = config or DetectionConfig()
    known_attacks = {str(c) for c in bundle.supervised.classes_} - {"normal"}
    counts, per_label, latencies = {}, {}, []
    for flow, context, label in zip(part.flows, part.contexts, part.labels):
        label = str(label)
        start = perf_counter()
        result = bundle.predict(flow, context)
        decision = decide(result, config)
        attributed = attribute(result, decision, config)["label"]
        latencies.append((perf_counter() - start) * 1000)
        counts.setdefault(label, dict.fromkeys(DECISIONS, 0))[decision] += 1
        stats = per_label.setdefault(label, {"flows": 0, "correct_attribution": 0, "wrong_attack_attribution": 0})
        stats["flows"] += 1
        stats["correct_attribution"] += attributed == label
        stats["wrong_attack_attribution"] += attributed in known_attacks and attributed != label
    for label, stats in per_label.items():
        n = stats["flows"]
        stats.update({"flagged_rate": 1 - counts[label]["normal"] / n,
                      "correct_attribution_rate": stats["correct_attribution"] / n,
                      "wrong_attack_attribution_rate": stats["wrong_attack_attribution"] / n})
    benign = counts.get("normal", dict.fromkeys(DECISIONS, 0))
    n_benign = sum(benign.values())
    attack_labels = [label for label in counts if label != "normal"]
    n_attack = sum(per_label[label]["flows"] for label in attack_labels)
    summary = {"benign_flows": n_benign, "attack_flows": n_attack}
    if n_benign:
        summary.update({"benign_normal_rate": benign["normal"] / n_benign,
                        "benign_abstention_rate": benign["unknown"] / n_benign,
                        "benign_alert_rate": (benign["suspicious"] + benign["anomalous"] + benign["malicious"]) / n_benign,
                        "benign_malicious_rate": benign["malicious"] / n_benign})
    if n_attack:
        summary.update({"attack_flagged_rate": sum(per_label[l]["flows"] - counts[l]["normal"] for l in attack_labels) / n_attack,
                        "attack_malicious_rate": sum(counts[l]["malicious"] for l in attack_labels) / n_attack,
                        "attack_correct_attribution_rate": sum(per_label[l]["correct_attribution"] for l in attack_labels) / n_attack,
                        "attack_wrong_attribution_rate": sum(per_label[l]["wrong_attack_attribution"] for l in attack_labels) / n_attack})
    return {"decision_counts": counts, "per_label": per_label, "summary": summary, "config": asdict(config),
            "known_attack_classes": sorted(known_attacks),
            "latency_ms": {"p50": float(np.median(latencies)), "p95": float(np.quantile(latencies, .95)), "samples": len(latencies)} if latencies else {},
            "definitions": {"flagged": "any decision other than normal (includes unknown abstention)",
                            "wrong_attack_attribution": "analyst-facing label is a known attack class that differs from the true label"}}


def train_demo(path: Path, seed=42) -> ModelBundle:
    parts = create_splits(seed)
    bundle = fit_bundle(parts, seed)
    bundle.metadata["metrics"] = evaluate_bundle(bundle, parts["test"])
    bundle.metadata["decision_metrics"] = evaluate_decisions(bundle, parts["test"])
    bundle.save(Path(path))
    return bundle
