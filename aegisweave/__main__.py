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
        if name == "serve":
            p.add_argument("--require-real-model", action="store_true", help="Refuse missing or synthetic-trained model artifacts")
        if name == "demo":
            p.add_argument("--count", default=160, type=int)
            p.add_argument("--seed", default=42, type=int)
    train = sub.add_parser("train-demo", help="Fit and save a synthetic research model")
    train.add_argument("--model", type=Path, default=DEFAULT_MODEL)
    train.add_argument("--seed", default=42, type=int)
    replay = sub.add_parser("replay", help="Forward normalized JSONL or Zeek conn.log (JSON or default TSV) to the authenticated telemetry API")
    replay.add_argument("file", type=Path)
    replay.add_argument("--format", choices=["normalized", "zeek", "zeek-tsv"], default="normalized",
                        help="zeek = conn.log JSON lines; zeek-tsv = Zeek's default tab-separated conn.log")
    replay.add_argument("--sensor", default="zeek-local")
    replay.add_argument("--url", default="http://127.0.0.1:8765")
    replay.add_argument("--follow", action="store_true", help="Follow appended lines until interrupted")
    replay.add_argument("--interval", type=float, default=0, help="Seconds between submitted flows")
    replay.add_argument("--simulated", action="store_true", help="Label every input as simulated, for constructed sensor fixtures or exercises")
    replay.add_argument("--batch-size", type=int, default=1, help="Flows per request (1-200); batches use /api/telemetry/batch")
    collect = sub.add_parser("collect", help="Durably spool and forward Zeek JSON logs")
    collect.add_argument("--source", required=True, help="Quoted glob including active and retained rotated JSON logs")
    collect.add_argument("--spool", type=Path, default=Path("var/collector.db"))
    collect.add_argument("--sensor", default="zeek-local")
    collect.add_argument("--url", default="http://127.0.0.1:8765")
    collect.add_argument("--once", action="store_true", help="One bounded intake/delivery cycle; nonzero if backlog or errors remain")
    collect.add_argument("--poll-seconds", type=float, default=1.)
    collect.add_argument("--max-pending", type=int, default=100000)
    collect.add_argument("--simulated", action="store_true", help="Mark constructed fixtures as simulated")
    collector_health = sub.add_parser("collector-health", help="Check collector status freshness, errors and backlog age")
    collector_health.add_argument("--spool", type=Path, default=Path("var/collector.db"))
    collector_health.add_argument("--max-age", type=float, default=120.)
    collector_health.add_argument("--max-backlog-age", type=float, default=300.)
    backup = sub.add_parser("backup", help="Create a consistent SQLite snapshot in a new directory")
    backup.add_argument("--db", type=Path, default=Path("var/aegisweave.db"))
    backup.add_argument("--output", type=Path, required=True)
    restore = sub.add_parser("restore", help="Verify a snapshot and restore to a new, unused database path")
    restore.add_argument("--backup", type=Path, required=True)
    restore.add_argument("--output", type=Path, required=True)
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
        if getattr(args, "require_real_model", False) and (model is None or model.metadata.get("simulated_training") is not False):
            raise SystemExit("This deployment requires a verified, non-synthetic-trained model; no suitable artifact was supplied")
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
        if not 1 <= args.count <= 5000:
            raise SystemExit("count must be between 1 and 5000")
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("w", encoding="utf-8") as handle:
            for flow in generate_demo(count=args.count, seed=args.seed):
                handle.write(flow.model_dump_json() + "\n")
        print(f"Wrote {args.count} simulated flows to {args.output}")
    elif args.command == "backup":
        from aegisweave.backup import snapshot
        print(json.dumps(snapshot(args.db, args.output), indent=2))
    elif args.command == "restore":
        from aegisweave.backup import restore
        print(json.dumps(restore(args.backup, args.output), indent=2))
    elif args.command == "collect":
        from aegisweave.ingest import run
        raise SystemExit(run(args.source, args.spool, args.sensor, args.url, args.once, args.poll_seconds, args.max_pending, args.simulated))
    elif args.command == "collector-health":
        from aegisweave.ingest import collector_health
        result = collector_health(args.spool, args.max_age, args.max_backlog_age)
        print(json.dumps(result))
        raise SystemExit(0 if result["healthy"] else 1)
    elif args.command == "replay":
        from aegisweave.collectors import forward
        forward(args.file, args.url, args.format, args.sensor, args.follow, args.interval, force_simulated=args.simulated,
                batch_size=args.batch_size)


if __name__ == "__main__":
    main()
