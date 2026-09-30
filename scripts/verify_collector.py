"""Real-process collector recovery checks using explicitly simulated Zeek records."""
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.verify_pipeline import RUN, Server, free_port
from aegisweave.ingest import collector_health


def run():
    RUN.mkdir(parents=True, exist_ok=True)
    source = RUN / "conn.json"
    pattern = str(RUN / "*.jsonl")
    source = source.with_suffix(".jsonl")
    spool_path = RUN / "collector.db"
    record = {"ts": 1700000000., "uid": "collector-fixture", "id.orig_h": "10.0.0.1",
              "id.resp_h": "10.0.0.2", "id.orig_p": 42000, "id.resp_p": 443, "proto": "tcp",
              "duration": .5, "orig_pkts": 5, "resp_pkts": 3, "orig_bytes": 300,
              "resp_bytes": 600, "conn_state": "SF"}
    source.write_text(json.dumps(record) + "\n", encoding="utf-8")
    results = []

    def check(name, condition):
        results.append({"check": name, "passed": bool(condition)})
        if not condition:
            raise AssertionError(name)

    def collect(url):
        env = {k: v for k, v in os.environ.items() if not k.startswith("AEGISWEAVE_")}
        process = subprocess.run([sys.executable, "-m", "aegisweave", "collect", "--source", pattern,
                                  "--spool", str(spool_path), "--sensor", "collector-verification",
                                  "--simulated", "--once", "--url", url], cwd=ROOT, env=env,
                                 capture_output=True, text=True, timeout=90)
        with (RUN / "collector-cli.log").open("a", encoding="utf-8") as log:
            log.write(process.stdout + process.stderr)
        return process.returncode, json.loads(process.stdout.strip().splitlines()[-1])

    server = None
    try:
        code, status = collect(f"http://127.0.0.1:{free_port()}")
        check("outage leaves one durable queued event", code == 1 and status["pending"] == 1)
        check("collector health exposes delivery outage", not collector_health(spool_path)["healthy"])
        server = Server("collector-api", RUN / "events.db")
        server.wait()
        code, status = collect(server.url)
        check("new collector process delivers retained event", code == 0 and status["delivered"] == 1 and status["pending"] == 0)
        check("collector health recovers after delivery", collector_health(spool_path)["healthy"])
        # A rotated duplicate models retry after an acknowledgment was lost.
        source.rename(RUN / "rotated.jsonl")
        source.write_text(json.dumps(record) + "\n" + json.dumps({**record, "uid": "second"}) + "\n", encoding="utf-8")
        code, status = collect(server.url)
        check("rotation and partial duplicate batch reconciled", code == 0 and status["delivered"] == 2 and status["duplicates"] == 1)
        with server.client() as client:
            token = client.get("/api/session").json()["token"]
            client.headers["Authorization"] = "Bearer " + token
            events = client.get("/api/events").json()["items"]
            check("API stores only two events", len(events) == 2)
            check("all test evidence remains simulated", all(e["simulated"] for e in events))
        code, status = collect(server.url)
        check("restart does not reread committed source offsets", code == 0 and status["queued"] == 3)
    finally:
        if server is not None:
            server.stop()
        report = {"simulated_fixtures": True, "checks": results, "passed": len(results) == 8 and all(r["passed"] for r in results)}
        (RUN / "collector-report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(json.dumps({"report": str(RUN / "collector-report.json"), **report}, indent=2))


if __name__ == "__main__":
    run()
