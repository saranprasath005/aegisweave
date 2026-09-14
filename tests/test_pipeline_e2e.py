"""Full pipeline with the real model: telemetry -> inference -> decision -> risk -> incident -> response -> audit -> dashboard."""
import json
import re
import shutil

import pytest
from fastapi.testclient import TestClient

from aegisweave.api import create_app
from aegisweave.collectors import zeek_to_flow
from aegisweave.detection import DetectionEngine
from test_api_security import TOKENS, headers


@pytest.fixture
def live(bundle, bundle_dir, tmp_path):
    model_path = tmp_path / "active"
    shutil.copytree(bundle_dir, model_path)
    app = create_app(engine=DetectionEngine(bundle), db_path=tmp_path / "e2e.db", model_path=model_path, tokens=TOKENS)
    with TestClient(app, base_url="http://localhost", client=("127.0.0.1", 40000)) as session:
        session.model_path = model_path
        yield session


def test_synthetic_replay_flows_through_every_stage(live):
    replay = live.post("/api/demo", json={"count": 180, "seed": 11}, headers=headers("analyst"))
    assert replay.status_code == 201 and replay.json() == {"accepted": 180, "simulated": True}

    overview = live.get("/api/overview", headers=headers("viewer")).json()
    assert overview["total_events"] == 180 and sum(overview["decisions"].values()) == 180
    assert overview["detected_threats"] == overview["decisions"]["malicious"] > 0
    assert overview["anomalous_unattributed"] == overview["decisions"]["anomalous"] > 0
    assert all("anomalous" in bucket for bucket in overview["trend"])

    events = live.get("/api/events", params={"limit": 500}, headers=headers("viewer")).json()["items"]
    assert len(events) == 180
    detail = live.get(f"/api/events/{events[0]['event_id']}", headers=headers("viewer")).json()
    for key in ("prediction", "anomaly", "attribution", "behavior", "fusion", "risk", "explanation", "model", "raw_telemetry"):
        assert key in detail
    assert detail["model"]["version"] == "1.1.0"

    anomalous = [e for e in events if e["fusion"]["decision"] == "anomalous"]
    assert all(e["attribution"]["label"] == "unattributed" for e in anomalous)
    filtered = live.get("/api/events", params={"decision": "anomalous", "limit": 500}, headers=headers("viewer")).json()["items"]
    assert len(filtered) == len(anomalous)
    assert live.get("/api/events", params={"search": "unattributed", "limit": 500}, headers=headers("viewer")).json()["items"]

    incidents = live.get("/api/incidents", headers=headers("viewer")).json()["items"]
    non_normal = {e["event_id"] for e in events if e["fusion"]["decision"] != "normal"}
    linked = {event_id for incident in incidents for event_id in incident["events"]}
    assert incidents and linked <= non_normal
    assert live.get(f"/api/incidents/{incidents[0]['id']}", headers=headers("viewer")).json()["timeline"]

    malicious = max((e for e in events if e["fusion"]["decision"] == "malicious"), key=lambda e: (e["risk"]["score"], e["prediction"]["confidence"]))
    request = {"event_id": malicious["event_id"], "action": "block_source", "reason": "End-to-end containment review", "ttl_seconds": 120}
    proposed = live.post("/api/responses", json=request, headers=headers("analyst")).json()
    if malicious["risk"]["score"] >= 70 and malicious["prediction"]["confidence"] >= .8:
        assert proposed["status"] == "pending_approval"
        approved = live.post(f"/api/responses/{proposed['id']}/approve", json={"reason": "Evidence reviewed"}, headers=headers("analyst")).json()
        assert approved["status"] == "simulated" and "no device" in approved["verification"]
        rolled = live.post(f"/api/responses/{proposed['id']}/rollback", json={"reason": "Exercise complete"}, headers=headers("analyst")).json()
        assert rolled["status"] == "rolled_back"
    else:
        assert proposed["status"] == "denied"

    if anomalous:
        blocked = live.post("/api/responses", json={**request, "event_id": anomalous[0]["event_id"]}, headers=headers("analyst")).json()
        assert blocked["status"] == "denied" and "anomalous" in blocked["audit"][-1]["reason"]
        notify = live.post("/api/responses", json={**request, "event_id": anomalous[0]["event_id"], "action": "notify"}, headers=headers("analyst")).json()
        assert notify["status"] == "simulated" and notify["approval_required"] is False

    actions = [x["action"] for x in live.get("/api/audit", params={"limit": 500}, headers=headers("analyst")).json()["items"]]
    assert "demo.replayed" in actions and "response.proposed" in actions
    assert all(r["simulated"] is True for r in live.get("/api/responses", headers=headers("viewer")).json()["items"])
    assert live.get("/api/behavior", headers=headers("viewer")).json()["items"]
    assert live.get("/api/metrics", headers=headers("viewer")).json()["health"]["status"] == "healthy"


def test_zeek_record_with_unmeasured_fields_is_scored_with_discount(live):
    row = {"ts": 1767225600.0, "uid": "CzeekE2E", "id.orig_h": "10.2.0.8", "id.resp_h": "172.20.4.4",
           "id.orig_p": 51000, "id.resp_p": 22, "proto": "tcp", "duration": .4, "orig_pkts": 6, "orig_bytes": 700,
           "resp_pkts": 4, "resp_bytes": 900, "conn_state": "SF"}
    flow = zeek_to_flow(row, "zeek-e2e")
    event = live.post("/api/telemetry", json=flow.model_dump(mode="json"), headers=headers("analyst")).json()
    assert event["missing_features"] == ["syn_ratio"] and event["simulated"] is False
    assert any("Unmeasured fields syn_ratio" in line for line in event["explanation"])
    assert live.post("/api/telemetry", json=flow.model_dump(mode="json"), headers=headers("analyst")).status_code == 409


def test_verified_model_reload_and_corruption_is_refused(live):
    reloaded = live.post("/api/models/reload", headers=headers("admin"))
    assert reloaded.status_code == 200 and reloaded.json()["version"] == "1.1.0"
    manifest = live.model_path / "manifest.json"
    data = json.loads(manifest.read_text(encoding="utf-8"))
    data["sha256"] = "f" * 64
    manifest.write_text(json.dumps(data), encoding="utf-8")
    assert live.post("/api/models/reload", headers=headers("admin")).status_code == 503
    assert live.get("/api/audit", headers=headers("admin")).json()["items"][0]["action"] == "model.reload_failed"
    # The previously verified model keeps serving.
    assert live.get("/api/models", headers=headers("viewer")).json()["available"] is True


def test_dashboard_page_and_its_assets_are_served(live):
    page = live.get("/")
    assert page.status_code == 200 and "text/html" in page.headers["content-type"]
    assets = re.findall(r'(?:src|href)="(/[^"]+\.(?:js|css))"', page.text)
    assert sorted(assets) == ["/static/app.js", "/static/styles.css"]
    for asset in assets:
        response = live.get(asset)
        assert response.status_code == 200 and len(response.content) > 1000
        assert "script-src 'self'" in response.headers["content-security-policy"]
