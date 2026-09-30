"""Start an isolated, explicitly synthetic Windows presentation workspace."""
from __future__ import annotations

import argparse
from datetime import datetime
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
from urllib.request import urlopen
import webbrowser

ROOT = Path(__file__).resolve().parents[1]
PORT = 8775
URL = f"http://127.0.0.1:{PORT}"
STATE = ROOT / "var" / "prototype" / "server.json"


def ready():
    try:
        with urlopen(URL + "/api/health", timeout=2) as response:
            health = json.load(response)
        with urlopen(URL + "/api/session", timeout=2) as response:
            session = json.load(response)
        return health.get("status") == "healthy" and health.get("response_mode") == "simulation" and session.get("mode") == "loopback_demo"
    except (OSError, ValueError):
        return False


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--no-browser", action="store_true")
    args = parser.parse_args()
    if STATE.exists() and ready():
        print(f"Prototype is already running: {URL}")
        if not args.no_browser:
            webbrowser.open(URL)
        return
    with socket.socket() as probe:
        try:
            probe.bind(("127.0.0.1", PORT))
        except OSError:
            raise SystemExit(f"Port {PORT} is occupied by another or unhealthy service. No service was stopped.")
    model = ROOT / "var" / "models" / "active"
    if not (model / "bundle.joblib").is_file():
        raise SystemExit("Existing demo model is missing; restore it before the presentation.")
    run = STATE.parent / datetime.now().strftime("%Y%m%d-%H%M%S-%f")
    run.mkdir(parents=True)
    # Only this loopback demo child gets a clean auth environment.
    env = {k: v for k, v in os.environ.items() if not k.startswith("AEGISWEAVE_")}
    command = [sys.executable, "-m", "aegisweave", "demo", "--host", "127.0.0.1",
               "--port", str(PORT), "--count", "200", "--seed", "42",
               "--model", str(model), "--db", str(run / "demo.db")]
    with (run / "server.log").open("w", encoding="utf-8") as log:
        process = subprocess.Popen(command, cwd=ROOT, env=env, stdin=subprocess.DEVNULL,
                                   stdout=log, stderr=subprocess.STDOUT,
                                   creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
    print("Preparing 200 simulated flows. Please wait...", flush=True)
    for _ in range(120):
        if process.poll() is not None:
            raise SystemExit(f"Startup failed. Details: {run / 'server.log'}")
        if ready():
            STATE.write_text(json.dumps({"url": URL, "pid": process.pid, "run": str(run)}, indent=2), encoding="utf-8")
            print(f"Prototype ready: {URL}\nSynthetic demonstration only; response actions are simulated.\nLogs and database: {run}")
            if not args.no_browser:
                webbrowser.open(URL)
            return
        time.sleep(1)
    process.terminate()
    process.wait(timeout=15)
    raise SystemExit(f"Startup timed out. Details: {run / 'server.log'}")


if __name__ == "__main__":
    main()
