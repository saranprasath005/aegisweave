"""Read-only telemetry forwarding. Never captures packets or sends probes."""
from __future__ import annotations

from datetime import datetime, timezone
import ipaddress
import json
import os
from pathlib import Path
import time
from urllib.parse import urlsplit
from uuid import NAMESPACE_URL, uuid5

from aegisweave.schema import Flow


def _counter(row: dict, name: str, required: bool = True):
    if name not in row:
        if required:
            raise ValueError(f"Required measured counter is missing: {name}")
        return 0
    value = row[name]
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"Counter {name} must be a nonnegative integer")
    return value


def zeek_to_flow(row: dict, sensor_id: str = "zeek-local") -> Flow:
    """Normalize Zeek conn JSON with explicit missing measurements.

    Bytes are transport payload counters (orig_bytes/resp_bytes), never mixed
    with IP-length counters. orig_pkts and resp_pkts are direction-separated.
    Zeek's compact history string cannot provide a measured SYN packet ratio.
    """
    missing = ["syn_ratio"]
    if "resp_pkts" not in row:
        missing.append("reverse_packets")
    if "resp_bytes" not in row:
        missing.append("reverse_bytes")
    state = row.get("conn_state")
    if state not in {"S0", "REJ", "RSTOS0", "SF", "S1", "S2", "S3"}:
        missing.append("failed")
    protocol = str(row["proto"]).upper()
    ts = row["ts"]
    if isinstance(ts, bool) or not isinstance(ts, (int, float)):
        raise ValueError("Zeek ts must be epoch seconds")
    return Flow(
        event_id=str(uuid5(NAMESPACE_URL, f"{sensor_id}/{row['uid']}/{ts}")),
        timestamp=datetime.fromtimestamp(ts, timezone.utc),
        source=row["id.orig_h"], destination=row["id.resp_h"],
        source_port=_counter(row, "id.orig_p", required=False),
        destination_port=_counter(row, "id.resp_p", required=False),
        protocol=protocol if protocol in {"TCP", "UDP", "ICMP"} else "OTHER",
        duration=row["duration"], packets=_counter(row, "orig_pkts"), bytes=_counter(row, "orig_bytes"),
        reverse_packets=_counter(row, "resp_pkts", required=False),
        reverse_bytes=_counter(row, "resp_bytes", required=False),
        failed=state in {"S0", "REJ", "RSTOS0"}, syn_ratio=0,
        sensor_id=sensor_id, simulated=False, missing_features=missing,
    )


def _unique_json(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate JSON key: {key}")
        result[key] = value
    return result


def read_jsonl(path: Path, follow=False, max_line=16384):
    with Path(path).open(encoding="utf-8-sig") as handle:
        line_number = 0
        while True:
            offset = handle.tell()
            line = handle.readline(max_line + 1)
            if len(line) > max_line:
                raise ValueError(f"Line {line_number + 1} exceeds {max_line} characters")
            if not line or (follow and not line.endswith("\n")):
                if not follow:
                    return
                handle.seek(offset)
                time.sleep(.25)
                continue
            line_number += 1
            if not line.strip():
                continue
            try:
                def nonfinite(value):
                    raise ValueError("Nonfinite JSON value")
                row = json.loads(line, object_pairs_hook=_unique_json, parse_constant=nonfinite)
                if not isinstance(row, dict):
                    raise ValueError("Expected a JSON object")
                yield row
            except (ValueError, TypeError) as exc:
                raise ValueError(f"Invalid JSONL evidence at line {line_number}: {exc}") from exc


def forward(path: Path, url: str, format: str, sensor_id: str, follow=False, interval=0):
    import httpx
    if interval < 0 or interval > 60:
        raise ValueError("Replay interval must be between 0 and 60 seconds")
    parts = urlsplit(url)
    if parts.username or parts.password or parts.query or parts.fragment or parts.path not in {"", "/"}:
        raise ValueError("Provide an API origin without credentials, query, fragment or path")
    try:
        local = parts.hostname == "localhost" or ipaddress.ip_address(parts.hostname).is_loopback
    except ValueError:
        local = False
    if parts.scheme != "https" and not (parts.scheme == "http" and local):
        raise ValueError("Remote telemetry forwarding requires HTTPS")
    token = os.environ.get("AEGISWEAVE_TOKEN")
    with httpx.Client(base_url=url.rstrip("/"), timeout=60, follow_redirects=False, trust_env=False) as client:
        if not token:
            if not local:
                raise ValueError("Set AEGISWEAVE_TOKEN to an analyst/admin credential")
            session = client.get("/api/session")
            session.raise_for_status()
            token = session.json()["token"]
        client.headers["Authorization"] = "Bearer " + token
        accepted = 0
        for row in read_jsonl(path, follow):
            flow = zeek_to_flow(row, sensor_id) if format == "zeek" else Flow.model_validate(row)
            response = client.post("/api/telemetry", json=flow.model_dump(mode="json"))
            if response.status_code == 409:
                print(json.dumps({"event_id": flow.event_id, "status": "already_ingested"}), flush=True)
                continue
            response.raise_for_status()
            event = response.json()
            accepted += 1
            print(json.dumps({"event_id": flow.event_id, "decision": event["fusion"]["decision"],
                              "risk": event["risk"]["score"], "simulated": flow.simulated}), flush=True)
            if interval:
                time.sleep(interval)
        print(json.dumps({"accepted": accepted, "source": str(path)}))
