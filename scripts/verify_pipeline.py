"""Live end-to-end verification of the AegisWeave pipeline. Nothing is mocked.

Starts real server processes (own free ports, fresh databases under var/verify/<run>/),
drives them through real HTTP and the real CLI, and checks every stage:
telemetry -> validation -> features/ML -> anomaly/behaviour -> fusion -> attribution -> risk ->
explanation -> storage/incidents -> response policy -> simulated response -> audit -> dashboard,
plus persistence across restart, token RBAC and fail-closed model loading.

Run from the repository root:   python scripts/verify_pipeline.py
Exit code 0 only if every check passes. A JSON report is written next to the run's logs.
"""
from __future__ import annotations

import json
import os
import secrets
import shutil
import socket
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import httpx

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from aegisweave.collectors import zeek_to_flow  # noqa: E402
from aegisweave.features import FLOW_FEATURES  # noqa: E402
from aegisweave.ml import ModelBundle  # noqa: E402

MODEL = ROOT / "var" / "models" / "active"
RUN = ROOT / "var" / "verify" / datetime.now().strftime("%Y%m%d-%H%M%S")
RESULTS: list[dict] = []
CAPS = {"normal": 24, "unknown": 59, "suspicious": 69, "anomalous": 69, "malicious": 100}
LABEL_BY_DECISION = {"anomalous": "unattributed", "unknown": "uncertain", "normal": "normal"}


def check(stage: str, name: str, ok, detail="") -> bool:
    RESULTS.append({"stage": stage, "check": name, "passed": bool(ok), "detail": str(detail)})
    print(f"[{'PASS' if ok else 'FAIL'}] {stage:<24} {name}" + (f"  ({detail})" if detail != "" else ""), flush=True)
    return bool(ok)


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


class Server:
    def __init__(self, name, db, model=MODEL, tokens=None):
        self.name, self.port = name, free_port()
        self.url = f"http://127.0.0.1:{self.port}"
        env = {k: v for k, v in os.environ.items() if not k.startswith("AEGISWEAVE_")}
        env.update(tokens or {})
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        self.log_path = RUN / f"{name}.log"
        self.log = self.log_path.open("w", encoding="utf-8")
        self.proc = subprocess.Popen([sys.executable, "-m", "aegisweave", "serve", "--port", str(self.port),
                                      "--db", str(db), "--model", str(model)],
                                     cwd=ROOT, env=env, stdout=self.log, stderr=subprocess.STDOUT)

    def wait(self, timeout=120) -> dict:
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.proc.poll() is not None:
                raise RuntimeError(f"{self.name} exited with {self.proc.returncode}; see {self.log_path}")
            try:
                response = httpx.get(self.url + "/api/health", timeout=2, trust_env=False)
                if response.status_code == 200:
                    return response.json()
            except httpx.HTTPError:
                pass
            time.sleep(.3)
        raise TimeoutError(f"{self.name} did not become reachable")

    def client(self, token=None) -> httpx.Client:
        headers = {"Authorization": "Bearer " + token} if token else {}
        return httpx.Client(base_url=self.url, timeout=120, trust_env=False, headers=headers)

    def stop(self):
        self.proc.terminate()
        try:
            self.proc.wait(20)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()
        self.log.close()


class Clock:
    """Monotonic event time for the 'verify' sensor stream; late events would get no host history."""
    def __init__(self):
        self.at = datetime.now(timezone.utc) - timedelta(minutes=20)

    def next(self, seconds: float) -> str:
        self.at += timedelta(seconds=seconds)
        return self.at.isoformat()


def flow(clock: Clock, gap=1.0, **changes) -> dict:
    values = dict(event_id=f"verify-{uuid4()}", timestamp=clock.next(gap), source="10.200.0.10",
                  destination="172.20.1.9", source_port=50123, destination_port=443, protocol="TCP",
                  duration=1.2, packets=14, bytes=3900, reverse_packets=12, reverse_bytes=9800,
                  failed=False, syn_ratio=.05, sensor_id="verify")
    values.update(changes)
    return values


def cli(*args, token_env=None) -> subprocess.CompletedProcess:
    env = {k: v for k, v in os.environ.items() if not k.startswith("AEGISWEAVE_")}
    env.update(token_env or {})
    return subprocess.run([sys.executable, "-m", "aegisweave", *args], cwd=ROOT, env=env,
                          capture_output=True, text=True, timeout=300)


def last_json(text: str) -> dict:
    for line in reversed(text.strip().splitlines()):
        try:
            return json.loads(line)
        except json.JSONDecodeError:
            continue
    return {}


def main() -> int:
    RUN.mkdir(parents=True, exist_ok=True)
    started = time.time()
    print(f"Verification run directory: {RUN}\n", flush=True)

    # 1. Model artifact -----------------------------------------------------------------------
    stage = "1 model artifact"
    model = ModelBundle.load(MODEL)  # verifies manifest hash, sklearn version, feature schema, metadata
    check(stage, "manifest hash, schema and metadata verified on load", True, model.metadata["version"])
    check(stage, "artifact declares synthetic training", model.metadata["simulated_training"] is True)
    check(stage, "open-set class-support layer present", getattr(model, "class_support", None) is not None,
          model.metadata.get("attribution", {}).get("calibration_rows"))

    db = RUN / "pipeline.db"
    server = Server("server-demo", db)
    try:
        # 2. Startup ------------------------------------------------------------------------
        stage = "2 startup"
        check(stage, "server healthy", server.wait()["status"] == "healthy")
        anon = server.client()
        session = anon.get("/api/session").json()
        token = session["token"]
        api = server.client(token)
        log_text = server.log_path.read_text(encoding="utf-8")
        check(stage, "structured startup log names model and modes", "service_started model_version=1.1.0" in log_text)

        # 3. Perimeter and auth ---------------------------------------------------------------
        stage = "3 perimeter/auth"
        check(stage, "no token -> 401", anon.get("/api/events").status_code == 401)
        check(stage, "loopback demo session issued", session["role"] == "admin" and session["mode"] == "loopback_demo" and len(token) >= 48)
        check(stage, "cross-origin mutation -> 403", api.post("/api/demo", json={"count": 1}, headers={"Origin": "https://evil.example"}).status_code == 403)
        check(stage, "foreign Host header -> 403", api.get("/api/overview", headers={"Host": "evil.example"}).status_code == 403)
        check(stage, "2 MiB+ body -> 413", api.post("/api/telemetry", content=b"x" * (2 * 1024 * 1024 + 10), headers={"Content-Type": "application/json"}).status_code == 413)

        # 4. Telemetry validation -------------------------------------------------------------
        stage = "4 telemetry validation"
        clock = Clock()
        for bad in ({"label": "normal"}, {"source": "not-an-ip"}, {"bytes": -5}, {"timestamp": "2026-01-01T00:00:00"},
                    {"asset_importance": 1}, {"destination_port": 70000}, {"source": "$(whoami)"}):
            check(stage, f"rejects {list(bad)[0]}={list(bad.values())[0]!r}", api.post("/api/telemetry", json=flow(Clock(), **bad)).status_code == 422)
        check(stage, "nothing stored from rejected input", api.get("/api/overview").json()["total_events"] == 0)

        # 5. One flow through every layer -----------------------------------------------------
        stage = "5 single flow layers"
        benign = flow(clock)
        response = api.post("/api/telemetry", json=benign)
        event = response.json()
        check(stage, "accepted (201)", response.status_code == 201)
        missing = [k for k in ("prediction", "anomaly", "attribution", "behavior", "fusion", "risk", "explanation", "model", "inference_ms") if k not in event]
        check(stage, "event carries every pipeline layer", not missing, missing or "prediction/anomaly/attribution/behavior/fusion/risk/explanation/model")
        check(stage, "class probabilities sum to 1", abs(sum(event["prediction"]["probabilities"].values()) - 1) < 1e-6)
        check(stage, "benign-shaped flow not malicious", event["fusion"]["decision"] != "malicious", f"decision={event['fusion']['decision']} risk={event['risk']['score']}")
        check(stage, "inference latency measured", 0 < event["inference_ms"] < 1000, f"{event['inference_ms']} ms")
        check(stage, "model provenance on event", event["model"]["version"] == "1.1.0" and event["model"]["simulated_training"] is True)
        stored = api.get(f"/api/events/{benign['event_id']}").json()
        check(stage, "persisted with raw telemetry", stored.get("raw_telemetry", {}).get("source") == benign["source"])
        check(stage, "duplicate event_id -> 409", api.post("/api/telemetry", json=benign).status_code == 409)

        # 6. Behaviour / temporal context ------------------------------------------------------
        stage = "6 behaviour+detection"
        burst = []
        for i in range(20):
            item = flow(clock, gap=.3, source="10.200.0.66", destination=f"172.21.3.{i + 1}", destination_port=1000 + 37 * i,
                        duration=.05, packets=2, bytes=120, reverse_packets=0, reverse_bytes=0, failed=True, syn_ratio=.95)
            burst.append(api.post("/api/telemetry", json=item).json())
        context = burst[-1]["behavior"]["context"]
        check(stage, "causal window counts connections", context["connections_30s"] == 20 and context["unique_ports_30s"] == 20,
              f"connections_30s={context['connections_30s']} unique_ports_30s={context['unique_ports_30s']}")
        check(stage, "host history available after warm-up", burst[-1]["behavior"]["available"] and not burst[0]["behavior"]["available"])
        decisions = [e["fusion"]["decision"] for e in burst]
        flagged = sum(d != "normal" for d in decisions)
        check(stage, "scan-like burst flagged", flagged >= 15, {d: decisions.count(d) for d in set(decisions)})
        scans = [e for e in burst if e["fusion"]["decision"] == "malicious" and e["attribution"]["label"] == "scan"]
        check(stage, "known attack attributed as scan", len(scans) >= 1, f"{len(scans)} malicious scan events")

        # 7. Novel behaviour / open-set attribution -------------------------------------------
        stage = "7 novel behaviour"
        beacons = [api.post("/api/telemetry", json=flow(clock, gap=4, source="10.200.0.99", destination=f"203.0.113.{20 + i}",
                                                         destination_port=5353, protocol="UDP", duration=60, packets=2, bytes=30000,
                                                         reverse_packets=0, reverse_bytes=0, syn_ratio=0)).json() for i in range(5)]
        check(stage, "unseen beacon pattern -> anomalous", all(e["fusion"]["decision"] == "anomalous" for e in beacons),
              [e["fusion"]["decision"] for e in beacons])
        check(stage, "no attack type invented", all(e["attribution"]["label"] == "unattributed" for e in beacons),
              f"raw classifier said {beacons[0]['prediction']['class']} {beacons[0]['prediction']['confidence']:.3f}")
        check(stage, "analyst statement says type uncertain", all("attack type uncertain" in e["attribution"]["statement"] for e in beacons))
        check(stage, "unattributed risk capped below containment", all(e["risk"]["score"] <= 69 for e in beacons), [e["risk"]["score"] for e in beacons])

        # 8-10. Ingestion paths ------------------------------------------------------------------
        stage = "8 batch ingestion"
        batch_clock = Clock()
        batch = [flow(batch_clock, gap=.5, sensor_id="verify-batch", source=f"10.201.0.{i % 10 + 1}", destination=f"172.20.9.{i % 7 + 1}") for i in range(40)]
        result = api.post("/api/telemetry/batch", json={"events": batch})
        check(stage, "40 flows accepted in one batch", result.status_code == 201 and result.json()["accepted"] == 40)
        check(stage, "batch over 200 rejected", api.post("/api/telemetry/batch", json={"events": batch * 6}).status_code == 422)

        stage = "9 synthetic replay"
        result = api.post("/api/demo", json={"count": 200, "seed": 123})
        check(stage, "200 synthetic flows processed", result.status_code == 201 and result.json() == {"accepted": 200, "simulated": True})

        stage = "10 CLI collectors"
        jsonl = RUN / "generated.jsonl"
        generated = cli("generate-demo", str(jsonl), "--count", "50", "--seed", "77")
        check(stage, "generate-demo wrote JSONL", generated.returncode == 0 and len(jsonl.read_text(encoding="utf-8").splitlines()) == 50)
        replay = cli("replay", str(jsonl), "--url", server.url)
        check(stage, "replay CLI forwarded normalized JSONL", replay.returncode == 0 and last_json(replay.stdout).get("accepted") == 50,
              replay.stderr[-300:] if replay.returncode else "accepted=50")
        rows = [{"ts": 1767225600.0 + i, "uid": f"Cverify{i}", "id.orig_h": "10.202.0.9", "id.resp_h": "172.20.3.3",
                 "id.orig_p": 40000 + i, "id.resp_p": 22, "proto": "tcp", "duration": .3, "orig_pkts": 5, "orig_bytes": 420,
                 "resp_pkts": 3, "resp_bytes": 380, "conn_state": "REJ" if i % 2 else "SF"} for i in range(6)]
        zeek = RUN / "conn.json"
        zeek.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
        replay = cli("replay", str(zeek), "--format", "zeek", "--sensor", "zeek-verify", "--url", server.url)
        check(stage, "replay CLI forwarded Zeek conn.log", replay.returncode == 0 and last_json(replay.stdout).get("accepted") == 6,
              replay.stderr[-300:] if replay.returncode else "accepted=6")
        zeek_event = api.get(f"/api/events/{zeek_to_flow(rows[1], 'zeek-verify').event_id}").json()
        check(stage, "Zeek event is real (not simulated), SYN declared unmeasured",
              zeek_event.get("simulated") is False and zeek_event.get("missing_features") == ["syn_ratio"])
        check(stage, "unmeasured field disclosed in explanation", any("Unmeasured fields syn_ratio" in x for x in zeek_event.get("explanation", [])))

        # 11. Storage, overview and incidents ---------------------------------------------------
        stage = "11 storage+incidents"
        expected_total = 1 + 20 + 5 + 40 + 200 + 50 + 6
        overview = api.get("/api/overview").json()
        events = api.get("/api/events", params={"limit": 500}).json()["items"]
        check(stage, "every accepted flow stored once", overview["total_events"] == expected_total == len(events), f"{overview['total_events']} events")
        check(stage, "decision counters consistent", sum(overview["decisions"].values()) == expected_total and overview["detected_threats"] == overview["decisions"]["malicious"],
              overview["decisions"])
        check(stage, "decision filter works", len(api.get("/api/events", params={"decision": "anomalous", "limit": 500}).json()["items"]) == overview["decisions"]["anomalous"])
        incidents = api.get("/api/incidents", params={"limit": 500}).json()["items"]
        non_normal = {e["event_id"] for e in events if e["fusion"]["decision"] != "normal"}
        linked = {x for incident in incidents for x in incident["events"]}
        check(stage, "incidents link only non-normal events", incidents and linked <= non_normal, f"{len(incidents)} incidents")
        burst_incidents = [i for i in incidents if i["source"] == "10.200.0.66"]
        check(stage, "burst correlated into one incident", len(burst_incidents) == 1 and burst_incidents[0]["event_count"] == flagged,
              f"event_count={burst_incidents[0]['event_count'] if burst_incidents else None}, flagged={flagged}")
        detail = api.get(f"/api/incidents/{burst_incidents[0]['id']}").json() if burst_incidents else {}
        check(stage, "incident timeline available", len(detail.get("timeline", [])) == flagged)

        # 12. Risk, attribution and explanation invariants over ALL events ----------------------
        stage = "12 risk+explanations"
        violations = []
        for e in events:
            decision, risk, attribution = e["fusion"]["decision"], e["risk"], e["attribution"]
            severity = "critical" if risk["score"] >= 85 else "high" if risk["score"] >= 70 else "medium" if risk["score"] >= 40 else "low"
            if risk["score"] > CAPS[decision] or risk["severity"] != severity:
                violations.append(("risk", e["event_id"]))
            expected_label = LABEL_BY_DECISION.get(decision)
            if (decision == "malicious" and attribution["label"] != e["prediction"]["class"]) or (expected_label and attribution["label"] != expected_label):
                violations.append(("attribution", e["event_id"]))
            if not e["explanation"] or e["explanation"][-1] != attribution["statement"]:
                violations.append(("explanation", e["event_id"]))
            if any(c["feature"] not in FLOW_FEATURES for c in e["anomaly"]["contributions"]):
                violations.append(("contribution", e["event_id"]))
        check(stage, f"invariants hold on all {len(events)} events", not violations, violations[:5] or "risk caps, severity, labels, explanations, features")

        # 13. Response policy and simulated response ---------------------------------------------
        stage = "13 response policy"

        def propose(event_id, action="block_source", ttl=300):
            return api.post("/api/responses", json={"event_id": event_id, "action": action, "reason": "Pipeline verification request", "ttl_seconds": ttl}).json()

        def transition(response_id, kind):
            return api.post(f"/api/responses/{response_id}/{kind}", json={"reason": "Pipeline verification " + kind})

        normal_event = next(e for e in events if e["fusion"]["decision"] == "normal")
        notify = propose(normal_event["event_id"], "notify")
        check(stage, "notify needs no approval, recorded as simulation", notify["status"] == "simulated" and notify["approval_required"] is False)
        denied = propose(beacons[0]["event_id"])
        check(stage, "containment of anomalous event denied", denied["status"] == "denied" and "malicious decision" in denied["audit"][-1]["reason"])
        candidates = [e for e in events if e["fusion"]["decision"] == "malicious" and e["risk"]["score"] >= 70 and e["prediction"]["confidence"] >= .8]
        check(stage, "high-risk attributed malicious event exists", bool(candidates), f"{len(candidates)} candidates")
        target = max(candidates, key=lambda e: e["risk"]["score"])
        pending = propose(target["event_id"])
        check(stage, "containment requires human approval", pending["status"] == "pending_approval", target["attribution"]["label"])
        approved = transition(pending["id"], "approve").json()
        check(stage, "approval records simulation only", approved["status"] == "simulated" and approved["simulated"] is True and "no device" in approved["verification"])
        check(stage, "rollback ends simulated action", transition(pending["id"], "rollback").json()["status"] == "rolled_back")
        check(stage, "repeated rollback -> 409", transition(pending["id"], "rollback").status_code == 409)

        default_policy = api.get("/api/policies").json()
        api.put("/api/policies", json={**default_policy, "allowlist": default_policy["allowlist"] + [target["source"] + "/32"]})
        guarded = propose(target["event_id"])
        check(stage, "allowlisted target protected", guarded["status"] == "denied" and "allowlist" in guarded["audit"][-1]["reason"])
        api.put("/api/policies", json=default_policy)

        active = propose(target["event_id"])
        transition(active["id"], "approve")
        check(stage, "kill switch accepted", api.put("/api/policies", json={**default_policy, "kill_switch": True}).status_code == 200)
        check(stage, "kill switch rolled back active simulation", api.get("/api/responses").json()["items"] and
              next(r for r in api.get("/api/responses").json()["items"] if r["id"] == active["id"])["status"] == "rolled_back")
        blocked = propose(target["event_id"], "notify")
        check(stage, "kill switch blocks new actions", blocked["status"] == "denied" and "kill switch" in blocked["audit"][-1]["reason"])
        api.put("/api/policies", json=default_policy)
        check(stage, "simulation cannot be disabled", api.put("/api/policies", json={**default_policy, "simulation": False}).status_code == 422)

        leased = propose(target["event_id"], ttl=30)
        leased = transition(leased["id"], "approve").json()
        check(stage, "30 s lease recorded", leased["status"] == "simulated", leased["expires_at"])
        wait = (datetime.fromisoformat(leased["expires_at"]) - datetime.now(timezone.utc)).total_seconds() + 2.5
        print(f"      waiting {wait:.0f}s for automatic lease expiry...", flush=True)
        time.sleep(max(0, wait))
        expired = next(r for r in api.get("/api/responses").json()["items"] if r["id"] == leased["id"])
        check(stage, "lease expired automatically", expired["status"] == "expired")

        # 14. Audit ------------------------------------------------------------------------------
        stage = "14 audit trail"
        audit_actions = [x["action"] for x in api.get("/api/audit", params={"limit": 500}).json()["items"]]
        needed = ["demo.replayed", "response.proposed", "response.pending_approval", "response.simulated", "response.rolled_back",
                  "response.denied", "response.expired", "policy.updated", "telemetry.rejected"]
        check(stage, "every action type audited", all(a in audit_actions for a in needed), [a for a in needed if a not in audit_actions] or f"{len(audit_actions)} records")

        # 15. Monitoring and model lifecycle ------------------------------------------------------
        stage = "15 monitoring+models"
        drift = api.get("/api/drift").json()
        check(stage, "drift monitor out of warm-up", drift["status"] in {"stable", "review_required"} and drift["automatic_retraining"] is False, drift["status"])
        metrics = api.get("/api/metrics").json()
        check(stage, "no inference errors", metrics["errors"] == 0 and metrics["health"]["status"] == "healthy", f"error_rate={metrics['error_rate']}")
        check(stage, "behaviour snapshot populated", len(api.get("/api/behavior").json()["items"]) > 0)
        models = api.get("/api/models").json()
        check(stage, "active model registered", models["active_version"] == "1.1.0" and models["available"])
        reload = api.post("/api/models/reload")
        check(stage, "verified model reload", reload.status_code == 200 and reload.json()["status"] == "loaded")

        # 16. Dashboard ------------------------------------------------------------------------------
        stage = "16 dashboard"
        page = anon.get("/")
        check(stage, "dashboard page served", page.status_code == 200 and "/static/app.js" in page.text)
        check(stage, "script and stylesheet served", all(anon.get(p).status_code == 200 for p in ("/static/app.js", "/static/styles.css")))
        check(stage, "strict CSP header", "script-src 'self'" in page.headers.get("content-security-policy", ""))

        # 17. Persistence across restart ---------------------------------------------------------
        stage = "17 restart persistence"
        api.put("/api/policies", json={**default_policy, "min_risk": 71})
        before = {"events": overview["total_events"], "responses": len(api.get("/api/responses", params={"limit": 500}).json()["items"]),
                  "audit": len(api.get("/api/audit", params={"limit": 500}).json()["items"])}
        api.close()
        anon.close()
    finally:
        server.stop()

    server = Server("server-demo-restarted", db)
    try:
        check(stage, "restarted on same database", server.wait()["status"] == "healthy")
        anon = server.client()
        new_token = anon.get("/api/session").json()["token"]
        api = server.client(new_token)
        check(stage, "demo session token is ephemeral", new_token != token)
        after = {"events": api.get("/api/overview").json()["total_events"], "responses": len(api.get("/api/responses", params={"limit": 500}).json()["items"])}
        check(stage, "events and responses persisted", after["events"] == before["events"] and after["responses"] == before["responses"], after)
        check(stage, "policy persisted", api.get("/api/policies").json()["min_risk"] == 71)
        check(stage, "audit persisted", len(api.get("/api/audit", params={"limit": 500}).json()["items"]) >= before["audit"])
        api.put("/api/policies", json=default_policy)
        api.close()
        anon.close()
    finally:
        server.stop()

    # 18. Configured token RBAC ---------------------------------------------------------------------
    stage = "18 token RBAC"
    tokens = {f"AEGISWEAVE_{role.upper()}_TOKEN": secrets.token_urlsafe(32) for role in ("viewer", "analyst", "admin")}
    server = Server("server-tokens", RUN / "tokens.db", tokens=tokens)
    try:
        server.wait()
        viewer, analyst, admin = (server.client(tokens[f"AEGISWEAVE_{r}_TOKEN"]) for r in ("VIEWER", "ANALYST", "ADMIN"))
        anon = server.client()
        check(stage, "demo session disabled", anon.get("/api/session").status_code == 404)
        check(stage, "no or wrong token -> 401", anon.get("/api/overview").status_code == 401 and server.client("x" * 40).get("/api/overview").status_code == 401)
        check(stage, "viewer reads, cannot ingest or audit", viewer.get("/api/overview").status_code == 200 and
              viewer.post("/api/telemetry", json=flow(Clock())).status_code == 403 and viewer.get("/api/audit").status_code == 403)
        check(stage, "analyst ingests, cannot change policy", analyst.post("/api/telemetry", json=flow(Clock())).status_code == 201 and
              analyst.put("/api/policies", json=default_policy).status_code == 403)
        check(stage, "admin changes policy and reloads model", admin.put("/api/policies", json=default_policy).status_code == 200 and
              admin.post("/api/models/reload").status_code == 200)
        replay = cli("replay", str(zeek), "--format", "zeek", "--sensor", "zeek-rbac", "--url", server.url,
                     token_env={"AEGISWEAVE_TOKEN": tokens["AEGISWEAVE_ANALYST_TOKEN"]})
        check(stage, "CLI replay authenticates with analyst token", replay.returncode == 0 and last_json(replay.stdout).get("accepted") == 6)
        for c in (viewer, analyst, admin, anon):
            c.close()
    finally:
        server.stop()

    # 19. Fail closed --------------------------------------------------------------------------------
    stage = "19 fail closed"
    remote = cli("serve", "--host", "0.0.0.0", "--port", str(free_port()))
    check(stage, "remote bind without tokens refused", remote.returncode != 0 and "Remote binding requires" in remote.stderr + remote.stdout)
    corrupt = RUN / "corrupt-model"
    shutil.copytree(MODEL, corrupt)
    manifest = json.loads((corrupt / "manifest.json").read_text(encoding="utf-8"))
    manifest["sha256"] = "0" * 64
    (corrupt / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    tampered = cli("serve", "--port", str(free_port()), "--model", str(corrupt), "--db", str(RUN / "corrupt.db"))
    check(stage, "tampered model refused at startup", tampered.returncode != 0 and "hash mismatch" in tampered.stderr)

    # Report ---------------------------------------------------------------------------------------------
    failed = [r for r in RESULTS if not r["passed"]]
    report = {"run": str(RUN), "finished_at": datetime.now(timezone.utc).isoformat(), "seconds": round(time.time() - started, 1),
              "checks": len(RESULTS), "failed": len(failed), "results": RESULTS}
    (RUN / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"\n{len(RESULTS) - len(failed)}/{len(RESULTS)} checks passed in {report['seconds']} s. Report: {RUN / 'report.json'}")
    print(f"Inspect the populated database in the dashboard:  python -m aegisweave serve --port 8790 --db {db}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
