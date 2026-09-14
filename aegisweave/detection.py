"""Evidence decisions, independent asset risk, drift surveillance and traceable inference."""
from __future__ import annotations

import math
import threading
import time
from collections import Counter, OrderedDict, deque
from dataclasses import asdict, dataclass
from typing import Any

from aegisweave.schema import Flow


class ModelUnavailableError(RuntimeError):
    pass


def bounded(value: Any, default: float = 0.0) -> float:
    try:
        result = float(value)
        return max(0.0, min(1.0, result)) if math.isfinite(result) else default
    except (ValueError, TypeError):
        return default


@dataclass(frozen=True)
class DetectionConfig:
    malicious_threshold: float = 0.78
    suspicious_threshold: float = 0.42
    minimum_confidence: float = 0.70
    minimum_reliability: float = 0.50
    anomaly_threshold: float = 0.95
    behavior_threshold: float = 0.85
    # Flows farther from the predicted class than this fraction of held-out flows of
    # that class are outside its training support: no attack type is attributed.
    attribution_percentile: float = 0.99

    def __post_init__(self):
        if not 0 < self.suspicious_threshold < self.malicious_threshold < 1:
            raise ValueError("Decision thresholds must be ordered within (0, 1)")
        if any(not 0 <= v <= 1 for v in asdict(self).values()):
            raise ValueError("Decision settings must lie within [0, 1]")


@dataclass(frozen=True)
class RiskConfig:
    medium_threshold: int = 40
    high_threshold: int = 70
    critical_threshold: int = 85

    def __post_init__(self):
        if not 0 < self.medium_threshold < self.high_threshold < self.critical_threshold <= 100:
            raise ValueError("Risk severity thresholds must be ordered within (0, 100]")


DECISIONS = ("normal", "suspicious", "anomalous", "malicious", "unknown")
NORMAL_LABELS = {"normal", "benign"}


def _signals(result: dict, config: DetectionConfig) -> dict:
    prediction, anomaly, behavior = result["prediction"], result["anomaly"], result["behavior"]
    label = str(prediction.get("class", "unknown")).lower()
    attribution = result.get("attribution") or {}
    support = attribution.get("support_percentile")
    # A model with class-support estimates but none for this attack class (too few held-out
    # calibration flows) cannot verify the attribution; it is never treated as supported.
    unverifiable = bool(attribution.get("class_support")) and support is None and label not in NORMAL_LABELS
    return {"label": label, "score": bounded(result["fusion"].get("score")),
            "confidence": bounded(prediction.get("confidence")),
            "reliability": bounded(result["fusion"].get("reliability")),
            "novelty": bounded(anomaly.get("score")) >= config.anomaly_threshold,
            "deviation": bool(behavior.get("available", True)) and bounded(behavior.get("deviation")) >= config.behavior_threshold,
            "predicted_normal": label in NORMAL_LABELS,
            "support": None if support is None else bounded(support, 1.0), "unverifiable": unverifiable,
            "unsupported": unverifiable or (support is not None and bounded(support, 1.0) > config.attribution_percentile)}


def decide(result: dict, config: DetectionConfig) -> str:
    """Separate detection (is it an attack?) from attribution (which known attack?).

    malicious  = known attack: fused detection, confident class, flow inside that class's training support
    suspicious = detected or deviating, but evidence or attribution is below the known-attack bar
    anomalous  = unlike benign traffic AND no supported known class: attack type uncertain
    unknown    = explicit abstention: unreliable measurements or conflicting evidence layers
    normal     = no corroborated evidence; class confidence is not required to call benign traffic normal
    """
    s = _signals(result, config)
    if s["label"] in {"unknown", "uncertain"} or s["reliability"] < config.minimum_reliability:
        return "unknown"
    # Without a class-support estimate (older artifacts), a novel flow the classifier
    # calls normal is still anomalous; with one, the flow must also be unsupported.
    if s["novelty"] and (s["unsupported"] or (s["predicted_normal"] and s["support"] is None)):
        return "anomalous"
    if s["predicted_normal"]:
        if s["deviation"]:
            return "unknown"
        return "suspicious" if s["score"] >= config.suspicious_threshold else "normal"
    low_confidence = s["confidence"] < config.minimum_confidence
    if s["score"] < config.suspicious_threshold and not (s["novelty"] or s["deviation"]):
        # The validated fused detector does not corroborate the class vote.
        return "unknown" if not (low_confidence or s["unsupported"]) else "normal"
    if low_confidence:
        return "unknown"
    if s["unsupported"]:
        return "suspicious"
    return "malicious" if s["score"] >= config.malicious_threshold else "suspicious"


def attribute(result: dict, decision: str, config: DetectionConfig) -> dict:
    """The analyst-facing label. Only a malicious or suspicious decision with a supported,
    confident class carries an attack type; otherwise the type is explicitly withheld."""
    s = _signals(result, config)
    model_class = result["prediction"].get("class", "unknown")
    support_text = "" if s["support"] is None else f" (class-support percentile {s['support']:.3f})"
    class_support = (result.get("attribution") or {}).get("class_support") or {}
    supporting = {name: bounded(value, 1.0) for name, value in class_support.items() if bounded(value, 1.0) <= config.attribution_percentile}
    # Ties at percentile 1.0 carry no ordering information, so only supporting classes are named.
    nearest = min(supporting, key=supporting.get) if supporting else None
    outside_all = bool(class_support) and not supporting
    if decision == "normal":
        status, label, statement = "not_applicable", "normal", "No corroborated attack evidence; no attack type is attributed."
    elif decision == "malicious":
        status, label = "attributed", model_class
        support_statement = f"within training support{support_text}" if s["support"] is not None else "class-support evidence is unavailable in this legacy artifact"
        statement = f"Known attack pattern '{model_class}': fused score {s['score']:.3f}, class confidence {s['confidence']:.3f}, {support_statement}."
    elif decision == "anomalous":
        status, label = "withheld_novel", "unattributed"
        if s["unverifiable"]:
            reason = f"the classifier's label '{model_class}' has no held-out calibration flows, so it cannot be verified"
        elif outside_all:
            reason = f"outside the training support of every known class, including the classifier's label '{model_class}'{support_text}"
        elif s["unsupported"]:
            reason = f"outside the training support of the classifier's label '{model_class}'{support_text}"
        else:
            reason = "the flow classifier did not match any known attack class"
        statement = f"Anomalous behavior detected, attack type uncertain: unlike benign training traffic and {reason}."
    elif decision == "suspicious" and not s["predicted_normal"] and not s["unsupported"]:
        status, label = "tentative", model_class
        statement = f"Suspicious activity resembling '{model_class}'{support_text}; evidence is below the known-attack threshold."
    elif decision == "suspicious":
        status, label = "withheld_no_supported_class", "unattributed"
        if s["unverifiable"]:
            statement = (f"Suspicious activity; the classifier's label '{model_class}' has no held-out calibration flows to verify "
                         "its training support, so no attack type is attributed.")
        elif s["unsupported"]:
            statement = "Suspicious activity; the classifier's label is outside that class's training support, so no attack type is attributed."
        else:
            statement = "Suspicious activity from fused or behavioral evidence; the flow classifier did not identify a known attack class."
    else:
        status, label = "withheld_uncertain", "uncertain"
        reasons = []
        if s["reliability"] < config.minimum_reliability:
            reasons.append(f"evidence reliability {s['reliability']:.2f} is below {config.minimum_reliability:.2f}")
        if s["confidence"] < config.minimum_confidence and not s["predicted_normal"]:
            reasons.append(f"class confidence {s['confidence']:.2f} is below {config.minimum_confidence:.2f}")
        if not reasons:
            reasons.append("the evidence layers disagree")
        statement = "Uncertain: " + "; ".join(reasons) + ". The system abstains from attack attribution."
    return {**(result.get("attribution") or {}), "status": status, "label": label, "model_class": model_class,
            "statement": statement, "support_threshold": config.attribution_percentile,
            "nearest_supported_class": nearest, "outside_all_known_classes": outside_all}


def assess_risk(result: dict, asset_importance: float = 0.5, config: RiskConfig | None = None) -> dict:
    """Risk uses corroboration and trusted asset context, separate from confidence."""
    config = config or RiskConfig()
    decision = result["fusion"]["decision"]
    # The impact prior follows the analyst-facing attribution, never a withheld raw class.
    label = str((result.get("attribution") or {}).get("label") or result["prediction"]["class"]).lower()
    # Configured impact priors are analyst policy, not inferred ground truth.
    impact = {"dos": 0.8, "dos_like": 0.8, "brute_force": 0.7, "brute_force_like": 0.7,
              "scan": 0.45, "scanning": 0.45, "reconnaissance": 0.45,
              "exploits": 0.95, "exfiltration": 0.95, "normal": 0.0, "benign": 0.0}.get(label, 0.65)
    components = {
        "fused_evidence": 0.42 * bounded(result["fusion"].get("score")),
        "anomaly": 0.14 * bounded(result["anomaly"].get("score")),
        "behavioral_deviation": 0.13 * bounded(result["behavior"].get("deviation")),
        "persistent_deviation": 0.12 * bounded(result["behavior"].get("temporal_consistency")) * bounded(result["behavior"].get("deviation")),
        "class_impact_prior": 0.09 * impact,
        "asset_importance": 0.10 * bounded(asset_importance),
    }
    score = round(100 * sum(components.values()))
    # Abstention, suspicion and unattributed novelty cannot silently trigger a high-impact policy tier.
    cap = {"normal": 24, "unknown": 59, "suspicious": 69, "anomalous": 69, "malicious": 100}[decision]
    score = min(cap, max(0, score))
    severity = "critical" if score >= config.critical_threshold else "high" if score >= config.high_threshold else "medium" if score >= config.medium_threshold else "low"
    response = {"normal": "Continue monitoring", "unknown": "Investigate and collect more evidence",
                "suspicious": "Review related flows and host history",
                "anomalous": "Investigate novel behavior; attack type is unattributed, so collect host and packet evidence before any containment",
                "malicious": "Review evidence and request simulated containment"}[decision]
    return {"score": score, "severity": severity, "reasoning": [
        f"{key.replace('_', ' ')} contributed {100 * value:.1f} risk points"
        for key, value in components.items() if value > 0.01
    ] + ([f"Risk cap is {cap} for {'an' if decision[0] in 'aeiou' else 'a'} {decision} decision"] if decision != "malicious" else []),
        "components": {k: round(v * 100, 2) for k, v in components.items()},
        "recommended_response": response, "asset_importance": bounded(asset_importance), "severity_thresholds": asdict(config)}


class DriftMonitor:
    """Bounded observation-only shift monitor; never updates a deployed model.

    Compare disjoint live windows, with PSI for log-byte/log-rate/confidence and
    total-variation distance for decisions. A signal is a request for review,
    not a statistical declaration of concept drift or maliciousness.
    """
    def __init__(self, window_size: int = 100):
        self.window_size = window_size
        self.reference: list[dict] = []
        self.current: deque[dict] = deque(maxlen=window_size)

    def observe(self, flow: Flow, result: dict):
        entry = {"log_bytes": math.log1p(flow.bytes),
                 "log_packet_rate": math.log1p(flow.packets / max(flow.duration, .001)),
                 "confidence": bounded(result["prediction"].get("confidence")),
                 "anomaly": bounded(result["anomaly"].get("score")),
                 "decision": result["fusion"]["decision"],
                 "class": (result.get("attribution") or {}).get("label", result["prediction"]["class"])}
        if len(self.reference) < self.window_size:
            self.reference.append(entry)
        else:
            self.current.append(entry)

    @staticmethod
    def _psi(reference: list[float], current: list[float]) -> float:
        ordered = sorted(reference)
        edges = sorted(set(ordered[min(len(ordered) - 1, int(len(ordered) * q / 5))] for q in range(1, 5)))
        def histogram(values):
            counts = [0.5] * (len(edges) + 1)
            for value in values:
                counts[sum(value > edge for edge in edges)] += 1
            return [c / sum(counts) for c in counts]
        a, b = histogram(reference), histogram(current)
        return sum((x - y) * math.log(x / y) for x, y in zip(a, b))

    def snapshot(self) -> dict:
        recent = list(self.current) or self.reference
        base = {"window_size": self.window_size, "reference_count": len(self.reference),
                "current_count": len(self.current), "baseline": "First live window; observational, not trusted normal",
                "automatic_retraining": False, "signals": [], "status": "warming_up",
                "anomaly_rate": sum(x["anomaly"] >= .95 for x in recent) / len(recent) if recent else None,
                "mean_confidence": sum(x["confidence"] for x in recent) / len(recent) if recent else None,
                "message": f"Compares the first {self.window_size} live observations with the most recent {self.window_size}; signals request human review and never retrain the model."}
        if len(self.current) < self.window_size:
            return base
        signals = []
        for feature in ("log_bytes", "log_packet_rate", "confidence", "anomaly"):
            value = self._psi([x[feature] for x in self.reference], [x[feature] for x in self.current])
            signals.append({"name": feature, "metric": "population_stability_index", "value": round(value, 4), "threshold": .25, "shift": value > .25})
        for feature in ("decision", "class"):
            a, b = Counter(x[feature] for x in self.reference), Counter(x[feature] for x in self.current)
            value = sum(abs(a[k] / self.window_size - b[k] / self.window_size) for k in a.keys() | b.keys()) / 2
            signals.append({"name": feature, "metric": "total_variation", "value": round(value, 4), "threshold": .25, "shift": value > .25})
        return {**base, "status": "review_required" if any(s["shift"] for s in signals) else "stable",
                "signals": signals, "recommended_action": "Collect labeled representative telemetry; retrain offline, evaluate, approve and reload"}


class DriftRegistry:
    """Separate sensor populations and synthetic demonstrations before measuring shift.

    The main card shows the most recently observed real sensor, falling back to a
    simulated stream only when no real telemetry exists. Every stream's status is
    returned separately so a quiet sensor is not masked by a busier population.
    """
    def __init__(self, window_size=100, max_streams=128):
        self.window_size, self.max_streams = window_size, max_streams
        self.streams: OrderedDict[tuple[str, bool], DriftMonitor] = OrderedDict()

    def observe(self, flow: Flow, result: dict):
        key = (flow.sensor_id, flow.simulated)
        if key not in self.streams:
            self.streams[key] = DriftMonitor(self.window_size)
        self.streams.move_to_end(key)
        self.streams[key].observe(flow, result)
        while len(self.streams) > self.max_streams:
            self.streams.popitem(last=False)

    def snapshot(self):
        if not self.streams:
            return {**DriftMonitor(self.window_size).snapshot(), "streams": [], "scope": None,
                    "monitored_streams": 0, "max_streams": self.max_streams}
        keys = list(reversed(self.streams))
        selected = next((key for key in keys if not key[1]), keys[0])
        snapshot = self.streams[selected].snapshot()
        summaries = []
        for key in keys:
            stream = self.streams[key].snapshot()
            summaries.append({"sensor_id": key[0], "simulated": key[1],
                              **{name: stream[name] for name in ("status", "reference_count", "current_count", "window_size")}})
        return {**snapshot, "scope": {"sensor_id": selected[0], "simulated": selected[1]},
                "streams": summaries, "monitored_streams": len(summaries), "max_streams": self.max_streams,
                "message": snapshot["message"] + f" Showing sensor {selected[0]} ({'simulated' if selected[1] else 'real'} telemetry). Each sensor and simulation stream has independent windows."}


class DetectionEngine:
    def __init__(self, model, store=None, config: DetectionConfig | None = None, asset_importance: dict[str, float] | None = None, risk_config: RiskConfig | None = None):
        from aegisweave.behavior import BehaviorEngine
        self.model = model
        self.config = config or DetectionConfig()
        self.risk_config = risk_config or RiskConfig()
        self.assets = dict(asset_importance or {})
        self.behavior = BehaviorEngine()
        self.drift = DriftRegistry()
        self.lock = threading.RLock()
        self.processed = 0
        self.errors = 0
        self.last_error: str | None = None
        self.latencies: deque[float] = deque(maxlen=1000)

    def process(self, flow: Flow) -> dict:
        if not isinstance(flow, Flow):
            flow = Flow.model_validate(flow)
        with self.lock:
            if self.model is None:
                self.errors += 1
                self.last_error = "Model unavailable"
                raise ModelUnavailableError("No validated model is loaded")
            start = time.perf_counter()
            context = self.behavior.observe(flow)
            try:
                result = self.model.predict(flow, context)
                for key in ("prediction", "anomaly", "behavior", "fusion", "model", "explanation"):
                    if key not in result:
                        raise ValueError(f"Model result missing {key}")
                decision = decide(result, self.config)
                result["fusion"]["decision"] = decision
                result["fusion"]["decision_config"] = asdict(self.config)
                result["anomaly"]["threshold"] = self.config.anomaly_threshold
                result["anomaly"]["is_anomalous"] = bounded(result["anomaly"].get("score")) >= self.config.anomaly_threshold
                result["attribution"] = attribute(result, decision, self.config)
                result["risk"] = assess_risk(result, self.assets.get(flow.destination, .5), self.risk_config)
                result["behavior"]["context"] = context
                result["explanation"] = [*result["explanation"], result["attribution"]["statement"]]
                assumption_evidence = {
                    "single_tcp_packet_zero_payload": "Collector assumption: an unset payload counter for a single TCP packet was estimated as zero; a one-packet connection can carry data.",
                    "fixed_ip_transport_headers": "Collector assumption: payload bytes were estimated using fixed IP and transport header sizes; IP options or extension headers can change the actual payload length.",
                }
                for assumption in flow.measurement_assumptions:
                    result["explanation"].insert(-1, assumption_evidence[assumption])
                elapsed = (time.perf_counter() - start) * 1000
                event = {**flow.model_dump(mode="json"), **result, "telemetry": flow.model_dump(mode="json"),
                         "inference_ms": round(elapsed, 3)}
                self.drift.observe(flow, result)
                self.processed += 1
                self.latencies.append(elapsed)
                self.last_error = None
                return event
            except Exception as exc:
                self.errors += 1
                self.last_error = type(exc).__name__
                raise ModelUnavailableError("Inference failed; no detection or response was produced") from exc

    def health(self) -> dict:
        with self.lock:
            return {"status": "degraded" if self.last_error or self.model is None else "ok",
                    "model": "loaded" if self.model is not None else "unavailable", "processed": self.processed,
                    "errors": self.errors, "last_error": self.last_error,
                    "inference_latency_ms": round(sum(self.latencies) / len(self.latencies), 3) if self.latencies else 0,
                    "behavior_hosts": len(self.behavior.snapshot()),
                    "decision_config": asdict(self.config)}

    def drift_snapshot(self) -> dict:
        with self.lock:
            return self.drift.snapshot()

    def replace_model(self, model):
        """Called only after offline artifact verification and admin authorization."""
        if model is None:
            raise ValueError("Cannot deploy an unavailable model")
        with self.lock:
            self.model = model
            self.behavior.reset()
            self.drift = DriftRegistry(self.drift.window_size)
            self.last_error = None
