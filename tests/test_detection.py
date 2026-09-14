from copy import deepcopy
from datetime import datetime, timezone, timedelta

import pytest
from pydantic import ValidationError

from aegisweave.schema import Flow
from aegisweave.detection import DetectionConfig, DetectionEngine, DriftMonitor, ModelUnavailableError, RiskConfig, assess_risk, attribute, decide


def flow(**changes):
    return Flow.model_validate(dict(timestamp=datetime.now(timezone.utc), source="10.0.0.2", destination="10.0.0.3",
        protocol="TCP", destination_port=443, duration=.5, packets=20, bytes=4000, **changes))


def evidence(**changes):
    result = {"prediction": {"class": "dos", "confidence": .98, "entropy": .1},
              "anomaly": {"score": .99, "is_anomalous": True},
              "behavior": {"deviation": .95, "temporal_consistency": .9, "available": True},
              "fusion": {"score": .95, "reliability": .9},
              "model": {"id": "test", "version": "test-1"}, "explanation": ["Measured test evidence"]}
    for key, value in changes.items():
        result[key].update(value)
    return result


@pytest.mark.parametrize("change", [
    {"source": "10.0.0.1;rm"}, {"source": "fe80::1%eth0"}, {"bytes": -1},
    {"bytes": "4000"}, {"duration": float("inf")}, {"syn_ratio": float("nan")},
    {"destination_port": 70000}, {"event_id": "a\nforged"}, {"attack_label": "normal"},
    {"asset_importance": 1}, {"packets": True}, {"timestamp": "2026-01-01T12:00:00"},
])
def test_malformed_and_injected_evidence_is_rejected(change):
    data = flow().model_dump()
    data.update(change)
    with pytest.raises(ValidationError):
        Flow.model_validate(data)


def test_canonical_addresses_and_utc():
    data = flow().model_dump()
    data.update(source="2001:0db8:0:0:0:0:0:1", timestamp="2026-01-01T12:00:00+05:30")
    result = Flow.model_validate(data)
    assert result.source == "2001:db8::1"
    assert result.timestamp.hour == 6 and result.timestamp.minute == 30


def test_known_attack_requires_confidence_and_agreement():
    assert decide(evidence(), DetectionConfig()) == "malicious"
    assert decide(evidence(prediction={"confidence": .4}), DetectionConfig()) == "unknown"
    assert decide(evidence(fusion={"reliability": .2}), DetectionConfig()) == "unknown"


def test_unknown_anomaly_is_not_claimed_as_known_attack():
    result = evidence(prediction={"class": "normal"})
    decision = decide(result, DetectionConfig())
    assert decision == "anomalous"
    assert attribute(result, decision, DetectionConfig())["label"] == "unattributed"


def supported(percentile, **changes):
    result = evidence(**changes)
    result["attribution"] = {"support_percentile": percentile, "class_support": {"dos": percentile}}
    return result


def test_novel_flow_outside_class_support_is_anomalous_not_invented_attack():
    result = supported(1.0)
    decision = decide(result, DetectionConfig())
    attributed = attribute(result, decision, DetectionConfig())
    assert decision == "anomalous"
    assert attributed["label"] == "unattributed" and attributed["model_class"] == "dos"
    assert "attack type uncertain" in attributed["statement"]


def test_flow_unlike_every_known_class_names_no_nearest_class():
    result = supported(1.0)
    result["attribution"]["class_support"] = {"normal": 1.0, "dos": 1.0, "scan": 1.0}
    attributed = attribute(result, decide(result, DetectionConfig()), DetectionConfig())
    assert attributed["outside_all_known_classes"] is True and attributed["nearest_supported_class"] is None
    assert "every known class" in attributed["statement"]
    result["attribution"]["class_support"]["scan"] = .4
    assert attribute(result, "anomalous", DetectionConfig())["nearest_supported_class"] == "scan"


def test_attack_class_without_support_calibration_is_never_attributed():
    # Real corpora can leave a rare class with no held-out calibration flows (IoT-23 DoS).
    result = evidence(anomaly={"score": .2})
    result["attribution"] = {"support_percentile": None, "class_support": {"normal": .4, "scan": .3}}
    decision = decide(result, DetectionConfig())
    attributed = attribute(result, decision, DetectionConfig())
    assert decision == "suspicious" and attributed["label"] == "unattributed"
    assert "no held-out calibration flows" in attributed["statement"]
    novel = evidence()
    novel["attribution"] = {"support_percentile": None, "class_support": {"normal": .4}}
    assert decide(novel, DetectionConfig()) == "anomalous"
    assert "cannot be verified" in attribute(novel, "anomalous", DetectionConfig())["statement"]
    # Artifacts without any class-support layer keep their previous behaviour.
    assert decide(evidence(anomaly={"score": .2}), DetectionConfig()) == "malicious"


def test_supported_confident_attack_is_attributed():
    result = supported(.4)
    assert decide(result, DetectionConfig()) == "malicious"
    assert attribute(result, "malicious", DetectionConfig())["label"] == "dos"


def test_unsupported_class_is_never_malicious_even_without_novelty():
    result = supported(1.0, anomaly={"score": .1})
    assert decide(result, DetectionConfig()) == "suspicious"
    assert attribute(result, "suspicious", DetectionConfig())["label"] == "unattributed"


def test_benign_flow_does_not_need_class_confidence_to_be_normal():
    quiet = supported(.3, prediction={"class": "normal", "confidence": .55}, anomaly={"score": .2},
                      behavior={"deviation": .1}, fusion={"score": .03})
    assert decide(quiet, DetectionConfig()) == "normal"
    weak_vote = supported(.3, prediction={"class": "brute_force", "confidence": .5}, anomaly={"score": .2},
                          behavior={"deviation": .1}, fusion={"score": .03})
    assert decide(weak_vote, DetectionConfig()) == "normal"


def test_confident_class_vote_contradicted_by_fused_detector_abstains():
    conflict = supported(.3, anomaly={"score": .2}, behavior={"deviation": .1}, fusion={"score": .05})
    decision = decide(conflict, DetectionConfig())
    assert decision == "unknown"
    assert attribute(conflict, decision, DetectionConfig())["label"] == "uncertain"


def test_novel_but_class_supported_benign_flow_with_low_fused_score_is_not_alerted():
    result = supported(.5, prediction={"class": "normal", "confidence": .9}, anomaly={"score": .97},
                       behavior={"deviation": .1}, fusion={"score": .05})
    assert decide(result, DetectionConfig()) == "normal"


def test_anomalous_decision_risk_is_capped_below_containment():
    result = supported(1.0, fusion={"decision": "anomalous"})
    result["attribution"]["label"] = "unattributed"
    risk = assess_risk(result, 1)
    assert risk["score"] <= 69 and "unattributed" in risk["recommended_response"]


def test_normal_and_subthreshold_suspicion():
    quiet = evidence(prediction={"class": "normal"}, anomaly={"score": .2}, behavior={"deviation": .2}, fusion={"score": .1})
    assert decide(quiet, DetectionConfig()) == "normal"
    quiet["fusion"]["score"] = .5
    assert decide(quiet, DetectionConfig()) == "suspicious"


def test_asset_priority_changes_risk_without_changing_ml():
    result = evidence(fusion={"decision": "malicious"})
    before = deepcopy(result)
    assert assess_risk(result, 1)["score"] > assess_risk(result, 0)["score"]
    assert result == before


@pytest.mark.parametrize("decision,maximum", [("normal", 24), ("unknown", 59), ("suspicious", 69)])
def test_uncertainty_cannot_gain_containment_risk(decision, maximum):
    assert assess_risk(evidence(fusion={"decision": decision}), 1)["score"] <= maximum


def test_benign_activity_persistence_does_not_add_threat_risk():
    result = evidence(fusion={"decision": "normal"}, behavior={"deviation": 0, "temporal_consistency": 1})
    assert assess_risk(result)["components"].get("persistent_deviation") == 0


def test_configuration_invariants():
    with pytest.raises(ValueError):
        DetectionConfig(malicious_threshold=.2)
    with pytest.raises(ValueError):
        RiskConfig(high_threshold=90, critical_threshold=70)


def test_missing_model_and_inference_failure_are_visible():
    engine = DetectionEngine(None)
    with pytest.raises(ModelUnavailableError):
        engine.process(flow())
    assert engine.health()["status"] == "degraded"
    class Failing:
        def predict(self, flow, context):
            raise RuntimeError("unavailable")
    engine = DetectionEngine(Failing())
    with pytest.raises(ModelUnavailableError):
        engine.process(flow())
    assert engine.health()["errors"] == 1
    assert engine.health()["processed"] == 0


def test_successful_inference_traces_model_and_measured_latency():
    class Stub:
        def predict(self, flow, context):
            return evidence()
    result = DetectionEngine(Stub()).process(flow())
    assert result["model"]["version"] == "test-1"
    assert result["inference_ms"] >= 0
    assert result["fusion"]["decision"] == "malicious"
    assert result["telemetry"]["source"] == "10.0.0.2"
    assert "context" in result["behavior"]


def test_drift_uses_separate_bounded_windows_and_never_retrains():
    monitor = DriftMonitor(window_size=10)
    result = evidence(fusion={"decision": "normal"})
    for i in range(10):
        monitor.observe(flow(), result)
    assert monitor.snapshot()["status"] == "warming_up"
    shifted = flow().model_dump()
    shifted["bytes"] = 100000000
    for i in range(20):
        monitor.observe(Flow.model_validate(shifted), result)
    snapshot = monitor.snapshot()
    assert snapshot["current_count"] == snapshot["reference_count"] == 10
    assert snapshot["status"] == "review_required"
    assert snapshot["automatic_retraining"] is False
