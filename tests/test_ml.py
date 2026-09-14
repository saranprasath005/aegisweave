"""Tests against a REAL trained bundle: contract, integrity, explanations, open-set attribution."""
from datetime import datetime, timedelta, timezone
import json

import numpy as np
import pytest

from aegisweave.demo import generate_demo, generate_episodes
from aegisweave.detection import DetectionEngine
from aegisweave.features import FLOW_FEATURES, flow_features
from aegisweave.ml import (ClassSupport, ModelBundle, _attack_log_odds, check_split_isolation,
                           choose_threshold, episodes_to_matrix, evaluate_decisions)
from aegisweave.behavior import BehaviorEngine
from aegisweave.schema import Flow


def measured_flow(**changes):
    values = dict(timestamp=datetime(2026, 3, 1, tzinfo=timezone.utc), source="10.9.0.4", destination="172.20.1.9",
                  source_port=50123, destination_port=443, protocol="TCP", duration=1.2, packets=14, bytes=3900,
                  reverse_packets=12, reverse_bytes=9800, failed=False, syn_ratio=.05, sensor_id="unit", simulated=True)
    values.update(changes)
    return Flow.model_validate(values)


def test_manifest_verification_detects_tampering(bundle_dir, tmp_path):
    assert ModelBundle.load(bundle_dir).metadata["version"] == "1.1.0"
    for mutate, message in [(lambda m: m["metadata"].update(id="forged"), "metadata"),
                            (lambda m: m.update(sklearn_version="0.0"), "sklearn"),
                            (lambda m: m.update(feature_schema="other"), "schema"),
                            (lambda m: m.update(sha256="0" * 64), "hash")]:
        copy = tmp_path / message
        copy.mkdir()
        (copy / "bundle.joblib").write_bytes((bundle_dir / "bundle.joblib").read_bytes())
        manifest = json.loads((bundle_dir / "manifest.json").read_text(encoding="utf-8"))
        mutate(manifest)
        (copy / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
        with pytest.raises(ValueError, match=message):
            ModelBundle.load(copy)


def test_engine_output_contract_is_complete_and_json_safe(bundle):
    engine = DetectionEngine(bundle)
    for flow in generate_demo(count=40, seed=3):
        event = engine.process(flow)
        json.dumps(event, allow_nan=False)
        assert event["fusion"]["decision"] in {"normal", "suspicious", "anomalous", "malicious", "unknown"}
        assert abs(sum(event["prediction"]["probabilities"].values()) - 1) < 1e-6
        assert 0 <= event["fusion"]["score"] <= 1 and 0 <= event["risk"]["score"] <= 100
        assert set(event["attribution"]["class_support"]) <= set(event["prediction"]["probabilities"])
        assert event["attribution"]["label"] in {*event["prediction"]["probabilities"], "unattributed", "uncertain"}
        assert event["explanation"] and all(isinstance(line, str) and line for line in event["explanation"])
        assert event["explanation"][-1] == event["attribution"]["statement"]
        assert event["model"]["simulated_training"] is True and event["inference_ms"] >= 0
    assert engine.health()["processed"] == 40


def test_identity_fields_never_change_model_evidence(bundle):
    context = {"available": False, "history_count": 0}
    base = measured_flow()
    other = measured_flow(source="192.0.2.77", destination="198.51.100.3", source_port=1111,
                          timestamp=datetime(2030, 1, 1, tzinfo=timezone.utc), sensor_id="elsewhere", simulated=False,
                          event_id="another-id")
    assert np.array_equal(flow_features(base), flow_features(other))
    a, b = bundle.predict(base, context), bundle.predict(other, context)
    assert a["prediction"] == b["prediction"] and a["fusion"]["score"] == b["fusion"]["score"]
    assert a["attribution"]["class_support"] == b["attribution"]["class_support"]


def test_sensitivity_explanation_is_recomputable_from_the_model(bundle):
    flow = measured_flow(duration=.05, packets=900, bytes=80000, reverse_packets=1, reverse_bytes=40, syn_ratio=.9)
    result = bundle.predict(flow, {"available": False, "history_count": 0})
    top = result["anomaly"]["contributions"][0]
    row = flow_features(flow)[None, :]
    index = FLOW_FEATURES.index(top["feature"])
    changed = row.copy()
    changed[0, index] = bundle.flow_center[index]
    before = _attack_log_odds(bundle._probabilities(row)[0, bundle.normal_index])
    after = _attack_log_odds(bundle._probabilities(changed)[0, bundle.normal_index])
    assert top["attack_log_odds_delta"] == pytest.approx(before - after, rel=1e-6, abs=1e-9)
    assert top["method"].endswith("(not causal)")


def test_unmeasured_fields_are_imputed_and_reduce_reliability(bundle):
    context = {"available": False, "history_count": 0}
    measured = bundle.predict(measured_flow(), context)
    data = measured_flow().model_dump()
    for field in ("syn_ratio", "reverse_bytes"):
        data.pop(field)
    partial = bundle.predict(Flow.model_validate(data), context)
    assert partial["fusion"]["reliability"] < measured["fusion"]["reliability"]
    assert any("Unmeasured fields" in line for line in partial["explanation"])


def test_split_isolation_rejects_shared_episodes(splits):
    leaked = dict(splits)
    leaked["test"] = splits["train"]
    with pytest.raises(ValueError, match="leakage"):
        check_split_isolation(leaked)


def test_class_support_percentiles_separate_in_and_out_of_distribution():
    rng = np.random.default_rng(1)
    train = np.vstack([rng.normal(0, 1, (300, 4)), rng.normal(8, 1, (300, 4))])
    labels = np.array(["a"] * 300 + ["b"] * 300)
    calibration = np.vstack([rng.normal(0, 1, (80, 4)), rng.normal(8, 1, (80, 4)), rng.normal(0, 1, (3, 4))])
    calibration_labels = np.array(["a"] * 80 + ["b"] * 80 + ["c"] * 3)
    support = ClassSupport().fit(train, labels, calibration, calibration_labels)
    assert "c" not in support.calibration  # too few held-out examples: no overconfident estimate
    inside = support.percentiles(rng.normal(0, 1, (200, 4)))
    assert (inside["a"] <= .99).mean() > .9 and (inside["b"] == 1).all()
    far = support.percentiles(np.full((1, 4), 40.))
    assert far["a"][0] == 1 and far["b"][0] == 1


def test_withheld_attack_family_is_never_given_a_known_attack_type(bundle):
    unknown = episodes_to_matrix(generate_episodes(8, 9151, unknown=True))
    report = evaluate_decisions(bundle, unknown)
    beacon = report["per_label"]["unknown_beacon"]
    assert beacon["flows"] > 50
    assert beacon["wrong_attack_attribution_rate"] == 0
    assert report["decision_counts"]["unknown_beacon"]["anomalous"] / beacon["flows"] >= .9


def test_held_out_decisions_are_useful_not_abstentions(bundle, splits):
    summary = evaluate_decisions(bundle, splits["test"])["summary"]
    # The inherited decision rule called only ~36% of benign flows normal. This half-size
    # fixture model measures ~0.78; the bound leaves margin for seed variance.
    assert summary["benign_normal_rate"] >= .65
    assert summary["benign_malicious_rate"] <= .01
    assert summary["attack_flagged_rate"] >= .9
    assert summary["attack_wrong_attribution_rate"] <= .05


def test_prediction_is_deterministic_and_late_events_get_no_history(bundle):
    engine = DetectionEngine(bundle)
    now = datetime(2026, 5, 1, tzinfo=timezone.utc)
    first = engine.process(measured_flow(timestamp=now, event_id="first"))
    reordered = engine.process(measured_flow(timestamp=now - timedelta(seconds=30), event_id="reordered"))
    assert reordered["behavior"]["context"]["reordered"] is True and reordered["behavior"]["context"]["late_event"] is False
    # Only earlier-starting flows count as prior context, so the later "first" flow is excluded.
    assert reordered["behavior"]["context"]["history_count"] == 0
    late = engine.process(measured_flow(timestamp=now - timedelta(seconds=301), event_id="late"))
    assert late["behavior"]["context"]["late_event"] is True and late["behavior"]["available"] is False
    again = bundle.predict(measured_flow(), {"available": False, "history_count": 0})
    assert again == bundle.predict(measured_flow(), {"available": False, "history_count": 0})
    assert first["model"]["version"] == "1.1.0"


def test_saturated_anomaly_scores_can_respect_zero_false_positive_budget():
    labels = np.array([0, 0, 1, 1])
    scores = np.array([1., 1., 1., 1.])
    threshold = choose_threshold(labels, scores, max_fpr=0)
    assert threshold > 1 and not (scores >= threshold).any()


def test_missing_window_counters_are_masked_until_they_age_out(bundle):
    engine = BehaviorEngine()
    base = measured_flow()
    data = base.model_dump()
    data.pop("reverse_bytes")
    data.pop("failed")
    partial = Flow.model_validate(data)
    context = engine.observe(partial)
    assert set(context["incomplete_features"]) == {"log_bytes_30s", "failed_ratio_30s"}
    for second in (1, 2, 3):
        context = engine.observe(measured_flow(timestamp=base.timestamp + timedelta(seconds=second)))
    prediction = bundle.predict(base, context)
    fully_measured_context = {**context, "incomplete_features": []}
    full = bundle.predict(base, fully_measured_context)
    assert prediction["behavior"]["history_reliability"] < full["behavior"]["history_reliability"]
    expired = engine.observe(measured_flow(timestamp=base.timestamp + timedelta(seconds=34)))
    assert expired["incomplete_features"] == []


def test_saved_prediction_is_traceable_to_verified_artifact(bundle_dir):
    restored = ModelBundle.load(bundle_dir)
    manifest = json.loads((bundle_dir / "manifest.json").read_text(encoding="utf-8"))
    prediction = restored.predict(measured_flow(), {"available": False, "history_count": 0})
    assert prediction["model"]["artifact_sha256"] == manifest["sha256"]
    fingerprint = prediction["model"]["training_fingerprint"]
    assert len(fingerprint) == 64 and fingerprint[:12] in prediction["model"]["id"]
    assert set(restored.metadata["implementation_sha256"]) == {"ml.py", "features.py", "behavior.py", "demo.py"}
