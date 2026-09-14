"""Local operation commands; all response execution remains simulated."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

os.environ.setdefault("OMP_NUM_THREADS", "1")
os.environ.setdefault("OPENBLAS_NUM_THREADS", "1")

# Matches the layout written by `train-demo` and `experiments.run --model`.
DEFAULT_MODEL = Path(os.environ.get("AEGISWEAVE_MODEL", "var/models/active"))


def parser():
    result = argparse.ArgumentParser(prog="aegisweave", description="AegisWeave network behavior intelligence")
    sub = result.add_subparsers(dest="command", required=True)
    for name in ("serve", "demo"):
        p = sub.add_parser(name, help="Start the API and SOC dashboard" if name == "serve" else "Train if absent, replay synthetic evidence, and start dashboard")
        p.add_argument("--host", default="127.0.0.1")
        p.add_argument("--port", default=8765, type=int)
        p.add_argument("--model", type=Path, default=DEFAULT_MODEL)
        p.add_argument("--db", type=Path, default=Path("var/aegisweave.db"))
        p.add_argument("--config", type=Path, help="Trusted local detection thresholds and asset priorities JSON")
        if name == "demo":
            p.add_argument("--count", default=160, type=int)
            p.add_argument("--seed", default=42, type=int)
    train = sub.add_parser("train-demo", help="Fit and save a synthetic research model")
    train.add_argument("--model", type=Path, default=DEFAULT_MODEL)
    train.add_argument("--seed", default=42, type=int)
    replay = sub.add_parser("replay", help="Forward normalized JSONL or Zeek conn.log JSON to the authenticated telemetry API")
    replay.add_argument("file", type=Path)
    replay.add_argument("--format", choices=["normalized", "zeek"], default="normalized")
    replay.add_argument("--sensor", default="zeek-local")
    replay.add_argument("--url", default="http://127.0.0.1:8765")
    replay.add_argument("--follow", action="store_true", help="Follow appended lines until interrupted")
    replay.add_argument("--interval", type=float, default=0, help="Seconds between submitted flows")
    export = sub.add_parser("generate-demo", help="Write explicitly simulated normalized JSONL")
    export.add_argument("output", type=Path)
    export.add_argument("--count", default=120, type=int)
    export.add_argument("--seed", default=42, type=int)
    return result


def main():
    args = parser().parse_args()
    import logging
    logging.basicConfig(level=os.environ.get("AEGISWEAVE_LOG_LEVEL", "INFO").upper(),
                        format="%(asctime)s %(levelname)s %(name)s %(message)s")
    if args.command == "train-demo":
        from aegisweave.ml import train_demo
        model = train_demo(args.model, seed=args.seed)
        print(json.dumps(model.metadata, indent=2, default=str))
    elif args.command in ("serve", "demo"):
        import uvicorn
        from aegisweave.api import create_app
        from aegisweave.detection import DetectionConfig, DetectionEngine, RiskConfig
        from aegisweave.ml import ModelBundle, train_demo
        if args.host not in ("127.0.0.1", "localhost", "::1") and not any(os.environ.get(f"AEGISWEAVE_{role}_TOKEN") for role in ("ADMIN", "ANALYST", "VIEWER")):
            raise SystemExit("Remote binding requires configured role tokens. The default demo is loopback-only.")
        # Fail before training or replaying evidence, not after, when the port is taken.
        import socket
        try:
            with socket.socket(socket.AF_INET6 if ":" in args.host else socket.AF_INET) as probe:
                probe.bind((args.host, args.port))
        except OSError:
            raise SystemExit(f"Port {args.port} on {args.host} is already in use - another AegisWeave server is probably running. "
                             f"Stop it (Ctrl+C in its terminal) or choose another port, e.g. --port {args.port + 1}.")
        if args.command == "demo":
            if not 0 <= args.count <= 2000:
                raise SystemExit("Demo count must be between 0 and 2000")
            if not args.model.exists():
                print("Training an explicitly synthetic model; no real-world performance is implied.", flush=True)
                train_demo(args.model, seed=args.seed)
        model = ModelBundle.load(args.model) if args.model.exists() else None
        if model is None:
            print(f"WARNING: no model at {args.model}; inference is unavailable until "
                  "`python -m aegisweave train-demo` (or a verified artifact) is placed there and reloaded.", flush=True)
        settings = json.loads(args.config.read_text(encoding="utf-8")) if args.config else {}
        if set(settings) - {"detection", "assets", "risk"}:
            raise SystemExit("Unknown configuration section")
        import ipaddress
        assets = {str(ipaddress.ip_address(k)): float(v) for k, v in settings.get("assets", {}).items()}
        if any(not 0 <= v <= 1 for v in assets.values()):
            raise SystemExit("Asset importance must be within [0, 1]")
        engine = DetectionEngine(model, config=DetectionConfig(**settings.get("detection", {})), asset_importance=assets,
                                 risk_config=RiskConfig(**settings.get("risk", {})))
        app = create_app(engine=engine, db_path=str(args.db), model_path=args.model)
        if args.command == "demo" and args.count:
            from aegisweave.demo import generate_demo
            from aegisweave.storage import Store
            seed_store = Store(args.db)
            try:
                for flow in generate_demo(count=args.count, seed=args.seed):
                    seed_store.add_event(engine.process(flow))
            finally:
                seed_store.close()
            print(f"Replayed {args.count} synthetic flows. Response mode: simulation.", flush=True)
        print(f"AegisWeave dashboard: http://{args.host}:{args.port}", flush=True)
        uvicorn.run(app, host=args.host, port=args.port, access_log=False, proxy_headers=False)
    elif args.command == "generate-demo":
        from aegisweave.demo import generate_demo
        if not 1 <= args.count <= 100000:
            raise SystemExit("count must be between 1 and 100000")
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("w", encoding="utf-8") as handle:
            for flow in generate_demo(count=args.count, seed=args.seed):
                handle.write(flow.model_dump_json() + "\n")
        print(f"Wrote {args.count} simulated flows to {args.output}")
    elif args.command == "replay":
        from aegisweave.collectors import forward
        forward(args.file, args.url, args.format, args.sensor, args.follow, args.interval)


if __name__ == "__main__":
    main()
