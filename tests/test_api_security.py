from datetime import datetime, timedelta, timezone
import threading
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from aegisweave.api import create_app
from aegisweave.storage import Store


TOKENS = {role: role + "-" + "x" * 32 for role in ("viewer", "analyst", "admin")}


def flow(event_id="e1", **changes):
    return {"event_id": event_id, "timestamp": datetime.now(timezone.utc).isoformat(),
            "source": "10.0.0.9", "destination": "10.0.0.2", "source_port": 50001,
            "destination_port": 443, "protocol": "TCP", "duration": 2.5,
            "packets": 10, "bytes": 2400, **changes}


class FakeEngine:
    def __init__(self, fail=False):
        self.fail = fail
        self.count = 0
        self.lock = threading.RLock()
        self.model = SimpleNamespace(metadata={"version": "test-v1", "dataset": "test fixture", "simulated_training": True})
        self.behavior = SimpleNamespace(snapshot=lambda: [], reset=lambda: None)

    def process(self, item):
        self.count += 1
        if self.fail:
            raise RuntimeError("private path /private/model")
        normalized = item.model_dump(mode="json")
        return {**normalized, "telemetry": normalized,
                "prediction": {"class": "scan", "confidence": 0.95},
                "anomaly": {"score": 0.98, "is_anomalous": True},
                "behavior": {"deviation": 0.9},
                "fusion": {"score": 0.9, "decision": "malicious"},
                "risk": {"score": 92, "severity": "critical"},
                "explanation": ["Test fixture only"], "model": self.model.metadata, "inference_ms": 2.0}

    def health(self):
        return {"status": "healthy", "model": "test-v1", "processed": self.count}

    def drift_snapshot(self):
        return {"status": "warming_up", "window_size": 0}


def headers(role="admin", **extra):
    return {"Authorization": "Bearer " + TOKENS[role], **extra}


@pytest.fixture
def client(tmp_path):
    app = create_app(engine=FakeEngine(), db_path=tmp_path / "events.db", tokens=TOKENS)
    with TestClient(app, base_url="http://localhost", client=("127.0.0.1", 12345)) as session:
        yield session


def test_auth_rbac_and_identity(client):
    assert client.get("/api/health").status_code == 200
    assert client.get("/api/events").status_code == 401
    assert client.get("/api/session").status_code == 404
    assert client.get("/api/identity", headers=headers("viewer")).json()["role"] == "viewer"
    assert client.get("/api/events", headers=headers("viewer")).status_code == 200
    assert client.post("/api/telemetry", json=flow(), headers=headers("viewer")).status_code == 403
    assert client.get("/api/audit", headers=headers("viewer")).status_code == 403
    assert client.put("/api/policies", json={}, headers=headers("analyst")).status_code == 403
    assert client.post("/api/models/reload", headers=headers("analyst")).status_code == 403


def test_loopback_session_random_and_perimeter(tmp_path):
    app = create_app(engine=FakeEngine(), db_path=tmp_path / "a.db", tokens={})
    with TestClient(app, base_url="http://localhost", client=("127.0.0.1", 12345)) as session:
        token = session.get("/api/session").json()["token"]
        assert len(token) >= 48
        assert session.get("/api/events", headers={"Authorization": "Bearer " + token}).status_code == 200
        assert session.get("/api/session", headers={"Origin": "http://evil.example"}).status_code == 403
        assert session.get("/api/session", headers={"Sec-Fetch-Site": "cross-site"}).status_code == 403
        assert session.get("/api/session", headers={"Host": "evil.example"}).status_code == 403
        assert session.get("/api/session", headers={"X-Forwarded-For": "127.0.0.1"}).status_code == 403
    other = create_app(engine=FakeEngine(), db_path=tmp_path / "b.db", tokens={})
    assert other.state.auth.session_token != token
    with TestClient(other, base_url="http://localhost", client=("192.0.2.2", 12345)) as remote:
        assert remote.get("/api/health").status_code == 403


@pytest.mark.parametrize("extra", [{"Origin": "https://evil.example"}, {"Origin": "null"}, {"Sec-Fetch-Site": "cross-site"}])
def test_cross_site_mutation_denied(client, extra):
    assert client.post("/api/telemetry", json=flow(), headers=headers(**extra)).status_code == 403


def test_same_origin_mutation_and_security_headers(client):
    response = client.post("/api/telemetry", json=flow(), headers=headers(Origin="http://localhost"))
    assert response.status_code == 201
    for key in ("Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options", "Cache-Control"):
        assert key in response.headers
    assert "frame-ancestors 'none'" in response.headers["Content-Security-Policy"]


@pytest.mark.parametrize("changes", [{"source": "$(whoami)"}, {"sensor_id": "bad\nlog"}, {"destination_port": 70000}, {"packets": -1}, {"label": "normal"}, {"asset_importance": 0.9}, {"timestamp": "2026-01-01T00:00:00"}, {"simulated": "false"}])
def test_malformed_telemetry_rejected(client, changes):
    assert client.post("/api/telemetry", json=flow(**changes), headers=headers()).status_code == 422
    assert client.get("/api/overview", headers=headers()).json()["total_events"] == 0


def test_request_and_batch_bounds(client):
    response = client.post("/api/telemetry", content=b"x" * (2 * 1024 * 1024 + 1), headers=headers())
    assert response.status_code == 413
    assert client.post("/api/telemetry/batch", json={"events": [flow(str(i)) for i in range(201)]}, headers=headers()).status_code == 422
    assert client.get("/api/events?limit=10000", headers=headers()).status_code == 422
    assert client.post("/api/demo", json={"count": 100000}, headers=headers()).status_code == 422


def test_persist_raw_normalized_correlate_and_duplicate_idempotency(client):
    raw = flow("one", source="2001:0db8:0000::1")
    result = client.post("/api/telemetry", json=raw, headers=headers()).json()
    assert result["source"] == "2001:db8::1"
    detail = client.get("/api/events/one", headers=headers()).json()
    assert detail["raw_telemetry"]["source"] == "2001:0db8:0000::1"
    assert detail["telemetry"]["source"] == "2001:db8::1"
    assert client.post("/api/telemetry", json=raw, headers=headers()).status_code == 409
    assert client.app.state.worker.engine.count == 1
    assert client.get("/api/overview", headers=headers()).json()["total_events"] == 1
    assert client.get("/api/incidents", headers=headers()).json()["items"][0]["event_count"] == 1


def test_api_endpoint_views_and_literal_injection_search(client):
    batch = {"events": [flow("a"), flow("b")]}
    result = client.post("/api/telemetry/batch", json=batch, headers=headers())
    assert result.status_code == 201 and result.json()["accepted"] == 2
    for path in ("events", "incidents", "models", "behavior", "metrics", "policies", "responses", "audit", "drift", "overview"):
        assert client.get("/api/" + path, headers=headers()).status_code == 200
    assert client.get("/api/events", params={"search": "%' OR 1=1 --"}, headers=headers()).json()["items"] == []
    assert client.get("/api/events/missing", headers=headers()).status_code == 404
    summary = client.get("/api/overview", headers=headers()).json()
    assert summary["detected_threats"] == 2 and summary["critical_incidents"] == 1


def test_worker_failure_visible_without_secret_leak_and_can_recover(tmp_path):
    fake = FakeEngine(fail=True)
    app = create_app(engine=fake, db_path=tmp_path / "f.db", tokens=TOKENS)
    with TestClient(app) as session:
        result = session.post("/api/telemetry", json=flow(), headers=headers())
        assert result.status_code == 503
        assert "private" not in result.text
        assert session.get("/api/metrics", headers=headers()).json()["errors"] == 1
        assert session.get("/api/audit", headers=headers()).json()["items"][0]["action"] == "inference.failed"
        fake.fail = False
        assert session.post("/api/telemetry", json=flow(), headers=headers()).status_code == 201


def test_queue_bound_rejects_whole_batch(tmp_path):
    app = create_app(engine=FakeEngine(), db_path=tmp_path / "q.db", tokens=TOKENS, queue_capacity=1)
    with TestClient(app) as session:
        result = session.post("/api/telemetry/batch", json={"events": [flow("a"), flow("b")]}, headers=headers())
        assert result.status_code == 429
        assert session.get("/api/overview", headers=headers()).json()["total_events"] == 0


def test_configured_short_or_duplicate_tokens_fail_closed(tmp_path):
    with pytest.raises(ValueError):
        create_app(engine=FakeEngine(), db_path=tmp_path / "x.db", tokens={"admin": "short"})
    with pytest.raises(ValueError):
        create_app(engine=FakeEngine(), db_path=tmp_path / "x.db", tokens={"admin": "x" * 32, "viewer": "x" * 32})


def test_missing_injected_model_fails_closed_and_openapi_requires_auth(tmp_path):
    fake = FakeEngine()
    fake.model = None
    app = create_app(engine=fake, db_path=tmp_path / "missing.db", tokens=TOKENS)
    with TestClient(app) as session:
        assert session.get("/api/models", headers=headers()).json()["available"] is False
        assert session.get("/api/health").json()["status"] == "degraded"
        assert session.post("/api/telemetry", json=flow(), headers=headers()).status_code == 503
        assert session.get("/api/openapi.json").status_code == 401
        spec = session.get("/api/openapi.json", headers=headers("viewer")).json()
        assert "/api/telemetry" in spec["paths"] and "Flow" in spec["components"]["schemas"]


def test_partial_batch_failures_report_committed_event_ids(client):
    client.post("/api/telemetry", json=flow("existing"), headers=headers())
    result = client.post("/api/telemetry/batch", json={"events": [flow("new"), flow("existing")]}, headers=headers())
    assert result.status_code == 409
    detail = result.json()["detail"]
    assert detail["accepted"] == 1 and detail["event_ids"] == ["new"]
    assert detail["errors"] == [{"event_id": "existing", "type": "DuplicateEvent"}]
    assert client.get("/api/health").json()["status"] == "healthy"


def test_metrics_resource_sampling_exposes_interval(client):
    resources = client.get("/api/metrics", headers=headers()).json()["resources"]
    if resources.get("status") != "unavailable":
        assert resources["rss_bytes"] > 0
        assert resources["cpu_sample_interval_seconds"] >= 0


def test_future_clock_poisoning_rejects_entire_batch_before_queue(client):
    future = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()
    result = client.post("/api/telemetry/batch", json={"events": [flow("valid"), flow("future", timestamp=future)]}, headers=headers())
    assert result.status_code == 422
    assert client.app.state.worker.engine.count == 0
    assert client.get("/api/overview", headers=headers()).json()["total_events"] == 0


def test_nonfinite_json_is_validation_error_without_input_reflection(client):
    import json
    body = json.dumps(flow(duration=float("nan")))
    result = client.post("/api/telemetry", content=body, headers=headers(**{"Content-Type": "application/json"}))
    assert result.status_code == 422
    assert "NaN" not in result.text
    assert client.app.state.worker.engine.count == 0


def test_api_response_workflow_and_policy_never_live(client):
    client.post("/api/telemetry", json=flow(), headers=headers())
    request = {"event_id": "e1", "action": "block_source", "reason": "Review suspicious evidence", "ttl_seconds": 60}
    assert client.post("/api/responses", json=request, headers=headers("viewer")).status_code == 403
    item = client.post("/api/responses", json=request, headers=headers("analyst")).json()
    assert item["status"] == "pending_approval" and item["simulated"] is True
    approved = client.post(f"/api/responses/{item['id']}/approve", json={"reason": "Evidence reviewed"}, headers=headers("analyst"))
    assert approved.json()["status"] == "simulated"
    rolled = client.post(f"/api/responses/{item['id']}/rollback", json={"reason": "Demo complete"}, headers=headers("analyst"))
    assert rolled.json()["status"] == "rolled_back"
    assert len(rolled.json()["audit"]) == 3
    for value in (False, 1, "true"):
        assert client.put("/api/policies", json={"simulation": value}, headers=headers()).status_code == 422


def test_database_reopen_and_retention(tmp_path):
    path = tmp_path / "persist.db"
    evidence = Store(path, max_events=2, max_audit=2)
    fake = FakeEngine()
    from aegisweave.schema import Flow
    for index in range(4):
        evidence.add_event(fake.process(Flow.model_validate(flow(str(index)))))
        evidence.audit("test", "test", str(index))
    assert len(evidence.events()) == 2
    assert len(evidence.audits()) == 2
    assert sum(i["event_count"] for i in evidence.incidents()) == 2
    evidence.close()
    reopened = Store(path)
    assert len(reopened.events()) == 2
    assert reopened.health()["schema_version"] == 2
    reopened.close()


def test_incident_event_time_boundaries_and_simulation_separation(tmp_path):
    evidence = Store(tmp_path / "time.db", correlation_seconds=30)
    fake = FakeEngine()
    from aegisweave.schema import Flow
    base = datetime.now(timezone.utc)
    for index, seconds, simulated in [("a", 0, False), ("b", 60, False), ("c", 30, False), ("d", 31, True), ("e", 300, False)]:
        evidence.add_event(fake.process(Flow.model_validate(flow(index, timestamp=(base + timedelta(seconds=seconds)).isoformat(), simulated=simulated))))
    groups = evidence.incidents()
    assert sorted(x["event_count"] for x in groups) == [1, 1, 3]
    assert len({x["id"] for x in groups}) == 3
    evidence.close()


def test_registry_preserves_distinct_fits_of_same_architecture(tmp_path):
    evidence = Store(tmp_path / "models.db")
    evidence.register_model({"version": "same-architecture", "id": "fit-one"}, "a" * 64)
    evidence.register_model({"version": "same-architecture", "id": "fit-two"}, "b" * 64)
    assert len(evidence.models()) == 2
    assert {x["artifact_sha256"] for x in evidence.models()} == {"a" * 64, "b" * 64}
    evidence.close()


def test_registry_v1_migration_preserves_old_metadata(tmp_path):
    import json
    import sqlite3
    path = tmp_path / "legacy.db"
    with sqlite3.connect(path) as legacy:
        legacy.execute("CREATE TABLE models (version TEXT PRIMARY KEY, registered_at TEXT NOT NULL, metadata_json TEXT NOT NULL)")
        legacy.execute("INSERT INTO models VALUES (?,?,?)", ("v1", datetime.now(timezone.utc).isoformat(), json.dumps({"id": "old-fit", "version": "v1"})))
        legacy.execute("PRAGMA user_version=1")
    evidence = Store(path)
    assert evidence.models() == [{"id": "old-fit", "version": "v1"}]
    evidence.register_model({"id": "new-fit", "version": "v1"})
    assert len(evidence.models()) == 2
    evidence.close()
