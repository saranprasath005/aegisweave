"""Durable read-only Zeek JSON ingestion; no packet capture or probing.

Offsets and payloads commit together. Delivery is at least once, with stable
event IDs for server deduplication. Retain renamed logs matching the source glob.
Copy/truncate rotation is rejected because missing bytes cannot be recovered.
"""
from __future__ import annotations

import glob
from collections import Counter
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import time
from urllib.parse import urlsplit

from pydantic import TypeAdapter

from .collectors import _unique_json, zeek_to_flow
from .schema import Flow


class CollectorError(RuntimeError):
    pass


class Spool:
    def __init__(self, path: Path, sensor: str, source: str, max_pending=100000, simulated=False):
        if max_pending < 1:
            raise ValueError("max_pending must be positive")
        # Invalid local configuration must fail before consuming any source records.
        sensor = TypeAdapter(Flow.model_fields["sensor_id"].rebuild_annotation()).validate_python(sensor)
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.lock = self.path.with_suffix(self.path.suffix + ".lock").open("a+b")
        try:
            if os.name == "nt":
                import msvcrt
                if self.lock.seek(0, 2) == 0:
                    self.lock.write(b"0")
                    self.lock.flush()
                self.lock.seek(0)
                msvcrt.locking(self.lock.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            self.lock.close()
            raise CollectorError("Another collector owns this spool") from exc
        self.db = sqlite3.connect(self.path)
        self.db.row_factory = sqlite3.Row
        self.sensor, self.source, self.max_pending = sensor, source, max_pending
        self.simulated = simulated
        try:
            self.db.executescript("""
                PRAGMA journal_mode=WAL;
                PRAGMA synchronous=FULL;
                CREATE TABLE IF NOT EXISTS config (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS sources (
                    identity TEXT PRIMARY KEY, path TEXT NOT NULL, offset INTEGER NOT NULL,
                    anchor TEXT NOT NULL, anchor_length INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS pending (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT, payload TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS counters (key TEXT PRIMARY KEY, value INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS errors (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, path TEXT, offset INTEGER, reason TEXT);
            """)
            if "queued_at" not in {r[1] for r in self.db.execute("PRAGMA table_info(pending)")}:
                self.db.execute("ALTER TABLE pending ADD COLUMN queued_at REAL NOT NULL DEFAULT 0")
            for key, value in {"sensor": sensor, "source": source, "schema": "zeek-json-v1", "simulated": str(simulated)}.items():
                existing = self.db.execute("SELECT value FROM config WHERE key=?", (key,)).fetchone()
                if existing and existing[0] != value:
                    raise CollectorError(f"Spool {key} differs; use its original configuration or a new spool")
                self.db.execute("INSERT OR IGNORE INTO config VALUES (?,?)", (key, value))
            self.db.commit()
        except Exception:
            self.close()
            raise

    def close(self):
        try:
            self.db.close()
        finally:
            self.lock.close()

    def count(self, key, amount=1):
        self.db.execute("INSERT INTO counters VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=value+excluded.value", (key, amount))

    def status(self):
        result = dict(self.db.execute("SELECT key,value FROM counters"))
        result["pending"] = self.db.execute("SELECT count(*) FROM pending").fetchone()[0]
        result["sources"] = self.db.execute("SELECT count(*) FROM sources").fetchone()[0]
        oldest = self.db.execute("SELECT min(queued_at) FROM pending").fetchone()[0]
        result["oldest_pending_age_seconds"] = max(0., time.time() - oldest) if oldest is not None else 0.
        result["recent_errors"] = [dict(r) for r in self.db.execute("SELECT path,offset,reason FROM errors ORDER BY id DESC LIMIT 5")]
        return result

    def poll(self, max_records=1000, max_line=16384):
        remaining = min(max_records, self.max_pending - self.status()["pending"])
        if remaining <= 0:
            return 0
        paths = sorted((Path(p) for p in glob.glob(self.source) if Path(p).is_file()),
                       key=lambda p: (p.stat().st_mtime_ns, str(p)))
        if not paths:
            raise CollectorError("No source logs match; retain rotated logs and check the source glob")
        reserved = {self.path.resolve(), self.path.with_suffix(self.path.suffix + ".lock").resolve(),
                    Path(str(self.path) + ".status.json").resolve(),
                    Path(str(self.path) + "-wal").resolve(), Path(str(self.path) + "-shm").resolve()}
        if any(p.resolve() in reserved for p in paths):
            raise CollectorError("Source glob includes collector state; use a dedicated log directory")
        processed = 0
        for path in paths:
            with path.open("rb") as handle:
                st = os.fstat(handle.fileno())
                identity = f"{st.st_dev}:{st.st_ino}"
                saved = self.db.execute("SELECT * FROM sources WHERE identity=?", (identity,)).fetchone()
                offset = saved["offset"] if saved else 0
                if saved:
                    anchor = hashlib.sha256(handle.read(saved["anchor_length"])).hexdigest()
                    if st.st_size < offset or anchor != saved["anchor"]:
                        raise CollectorError(f"Source was truncated or rewritten: {path}; retain original files for recovery")
                handle.seek(offset)
                while processed < remaining:
                    start = handle.tell()
                    line = handle.readline(max_line + 1)
                    if len(line) > max_line:
                        raise CollectorError(f"Source line exceeds {max_line} bytes at {path}:{start}")
                    if not line or not line.endswith(b"\n"):
                        break
                    end = handle.tell()
                    payload, reason = None, None
                    try:
                        def nonfinite(value):
                            raise ValueError("Nonfinite JSON value")
                        row = json.loads(line.decode("utf-8-sig"), object_pairs_hook=_unique_json, parse_constant=nonfinite)
                        if not isinstance(row, dict):
                            raise ValueError("Expected a JSON object")
                        flow = zeek_to_flow(row, self.sensor)
                        if self.simulated:
                            flow = flow.model_copy(update={"simulated": True})
                        payload = flow.model_dump_json()
                    except (ValueError, KeyError, TypeError, OverflowError, OSError) as exc:
                        reason = type(exc).__name__ + ": invalid or unrepresentable Zeek JSON record"
                    length = min(end, 4096)
                    handle.seek(0)
                    anchor = hashlib.sha256(handle.read(length)).hexdigest()
                    handle.seek(end)
                    with self.db:
                        if payload is not None:
                            self.db.execute("INSERT INTO pending(payload,queued_at) VALUES (?,?)", (payload, time.time()))
                            self.count("queued")
                        else:
                            self.db.execute("INSERT INTO errors(path,offset,reason) VALUES (?,?,?)", (str(path), start, reason))
                            self.count("rejected")
                            self.db.execute("DELETE FROM errors WHERE id NOT IN (SELECT id FROM errors ORDER BY id DESC LIMIT 1000)")
                        self.db.execute("INSERT INTO sources VALUES (?,?,?,?,?) ON CONFLICT(identity) DO UPDATE SET path=excluded.path,offset=excluded.offset,anchor=excluded.anchor,anchor_length=excluded.anchor_length",
                                        (identity, str(path), end, anchor, length))
                    processed += 1
            if processed >= remaining:
                break
        return processed

    def deliver(self, client, batch_size=200):
        if not 1 <= batch_size <= 200:
            raise ValueError("batch_size must be between 1 and 200")
        rows = self.db.execute("SELECT seq,payload FROM pending ORDER BY seq LIMIT ?", (batch_size,)).fetchall()
        if not rows:
            return 0
        flows = [json.loads(r["payload"]) for r in rows]
        response = client.post("/api/telemetry/batch", json={"events": flows})
        ids = Counter(f["event_id"] for f in flows)
        if response.status_code == 201:
            body = response.json()
            returned = [e["event_id"] for e in body.get("events", [])]
            if body.get("accepted") != len(rows) or Counter(returned) != ids:
                raise CollectorError("API acknowledgment does not match queued events")
            acknowledged, duplicates = len(rows), 0
        elif response.status_code == 409:
            detail = response.json().get("detail", {})
            errors = detail.get("errors", [])
            succeeded = detail.get("event_ids", [])
            returned = succeeded + [e.get("event_id") for e in errors]
            if (not errors or any(e.get("type") != "DuplicateEvent" for e in errors)
                    or detail.get("accepted") != len(succeeded) or Counter(returned) != ids):
                raise CollectorError("API duplicate acknowledgment does not match queued events")
            acknowledged, duplicates = len(succeeded), len(errors)
        else:
            response.raise_for_status()
            raise CollectorError("Unexpected API acknowledgment")
        with self.db:
            self.db.executemany("DELETE FROM pending WHERE seq=?", [(r["seq"],) for r in rows])
            self.count("delivered", acknowledged)
            self.count("duplicates", duplicates)
        return len(rows)


def publish_status(spool_path, status):
    path = Path(str(spool_path) + ".status.json")
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent, delete=False) as handle:
            temporary = Path(handle.name)
            json.dump({**status, "updated_at_epoch": time.time()}, handle, allow_nan=False)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()


def collector_health(spool_path, max_age=120., max_backlog_age=300.):
    if not 0 < max_age or not 0 < max_backlog_age:
        raise ValueError("Health age bounds must be positive")
    try:
        status = json.loads(Path(str(spool_path) + ".status.json").read_text(encoding="utf-8"))
        if not {"pending", "oldest_pending_age_seconds", "source_error", "delivery_error", "backpressure", "rejected_this_cycle"}.issubset(status):
            raise ValueError("Incomplete collector status")
        age = time.time() - status["updated_at_epoch"]
        reasons = []
        if not 0 <= age <= max_age:
            reasons.append("collector status is stale or future-dated")
        for field in ("source_error", "delivery_error", "backpressure", "rejected_this_cycle"):
            if status.get(field):
                reasons.append(field)
        if status.get("oldest_pending_age_seconds", 0) + age > max_backlog_age and status.get("pending", 0):
            reasons.append("pending telemetry is older than the backlog age limit")
        return {"healthy": not reasons, "reasons": reasons, "status": status}
    except (OSError, ValueError, KeyError, TypeError):
        return {"healthy": False, "reasons": ["collector status is missing or invalid"]}


def run(source, spool_path, sensor, url, once=False, poll_seconds=1., max_pending=100000, simulated=False):
    import httpx
    if not .1 <= poll_seconds <= 60:
        raise ValueError("poll_seconds must be between 0.1 and 60")
    parts = urlsplit(url)
    try:
        local = parts.hostname == "localhost" or ipaddress.ip_address(parts.hostname).is_loopback
    except ValueError:
        local = False
    if (parts.username or parts.password or parts.query or parts.fragment or parts.path not in {"", "/"}
            or not (parts.scheme == "https" or (parts.scheme == "http" and local))):
        raise ValueError("Use an HTTPS origin, or loopback HTTP, without credentials or a path")
    token = os.environ.get("AEGISWEAVE_TOKEN")
    if not token and not local:
        raise ValueError("Set AEGISWEAVE_TOKEN for the remote API")
    source = str(Path(source).absolute())
    spool = Spool(spool_path, sensor, source, max_pending, simulated)
    failures = 0
    try:
        with httpx.Client(base_url=url.rstrip("/"), timeout=60, follow_redirects=False, trust_env=False) as client:
            while True:
                source_error = delivery_error = None
                retry_after = 0.
                rejected_before = spool.status().get("rejected", 0)
                try:
                    spool.poll()
                except (CollectorError, OSError) as exc:
                    source_error = str(exc)
                try:
                    if spool.status()["pending"]:
                        if token:
                            client.headers["Authorization"] = "Bearer " + token
                        else:
                            session = client.get("/api/session")
                            session.raise_for_status()
                            client.headers["Authorization"] = "Bearer " + session.json()["token"]
                        spool.deliver(client)
                    failures = 0
                except (httpx.HTTPError, CollectorError, ValueError, KeyError) as exc:
                    failures += 1
                    delivery_error = type(exc).__name__
                    if isinstance(exc, httpx.HTTPStatusError):
                        delay = exc.response.headers.get("Retry-After", "")
                        if delay.isdigit():
                            retry_after = min(300., float(delay))
                status = spool.status()
                status.update(source_error=source_error, delivery_error=delivery_error,
                              backpressure=status["pending"] >= max_pending,
                              rejected_this_cycle=status.get("rejected", 0) - rejected_before)
                publish_status(spool.path, status)
                print(json.dumps(status), flush=True)
                if once:
                    return 1 if source_error or delivery_error or status["pending"] else 0
                time.sleep(max(retry_after, min(60., max(poll_seconds, 2 ** min(failures, 6)))) if failures else poll_seconds)
    finally:
        spool.close()
