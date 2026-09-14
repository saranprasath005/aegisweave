"""Read-only telemetry forwarding. Never captures packets or sends probes."""
from __future__ import annotations

from datetime import datetime, timezone
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import time
from urllib.parse import urlsplit
from uuid import NAMESPACE_URL, uuid5

from aegisweave.schema import Flow

# Fixed header sizes used only to derive UDP/ICMP payload from IP-length counters.
IP_HEADER_BYTES = {4: 20, 6: 40}
FIXED_TRANSPORT_HEADER_BYTES = {"udp": 8, "icmp": 8}


def _counter(row: dict, name: str, required: bool = True):
    if name not in row:
        if required:
            raise ValueError(f"Required measured counter is missing: {name}")
        return 0
    value = row[name]
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"Counter {name} must be a nonnegative integer")
    return value


def _payload_bytes(row: dict, direction: str, packets: int, protocol: str, address: str):
    """Zeek leaves payload bytes unset for single-packet connections.

    Values are never guessed: zero packets carry zero payload, a single TCP packet
    without a handshake (SYN/RST probe) carries no sequence-tracked payload, and
    UDP/ICMP payload is derived exactly from the measured IP length minus fixed
    IPv4/IPv6 and UDP/ICMP headers (IP options, which are rare, would be counted).
    Anything else is refused rather than invented.
    """
    key = f"{direction}_bytes"
    if key in row:
        return _counter(row, key)
    if packets == 0:
        return 0
    if protocol == "tcp" and packets == 1:
        return 0
    ip_bytes = row.get(f"{direction}_ip_bytes")
    if protocol in FIXED_TRANSPORT_HEADER_BYTES and isinstance(ip_bytes, int) and not isinstance(ip_bytes, bool) and ip_bytes >= 0:
        overhead = IP_HEADER_BYTES[ipaddress.ip_address(address).version] + FIXED_TRANSPORT_HEADER_BYTES[protocol]
        return max(0, ip_bytes - packets * overhead)
    raise ValueError(f"Zeek {key} is missing (unset) and cannot be derived from measured counters")


def zeek_to_flow(row: dict, sensor_id: str = "zeek-local") -> Flow:
    """Normalize a Zeek conn record (JSON or TSV-parsed) with explicit missing measurements.

    Bytes are transport payload counters (orig_bytes/resp_bytes), never mixed
    with IP-length counters except for the exact fixed-header derivation above.
    orig_pkts and resp_pkts are direction-separated. Zeek's compact history
    string cannot provide a measured SYN packet ratio. Label columns present in
    research logs are ignored: telemetry never carries ground truth.
    """
    missing = ["syn_ratio"]
    state = row.get("conn_state")
    if state not in {"S0", "REJ", "RSTOS0", "SF", "S1", "S2", "S3"}:
        missing.append("failed")
    raw_protocol = str(row["proto"]).lower()
    protocol = raw_protocol.upper()
    ts = row["ts"]
    if isinstance(ts, bool) or not isinstance(ts, (int, float)) or not math.isfinite(ts):
        raise ValueError("Zeek ts must be finite epoch seconds")
    orig_packets = _counter(row, "orig_pkts")
    reverse_packets = _counter(row, "resp_pkts", required=False)
    if "resp_pkts" not in row:
        missing.append("reverse_packets")
    if "duration" in row:
        duration = row["duration"]
    elif orig_packets + reverse_packets <= 1 and "resp_pkts" in row:
        duration = 0.0  # Zeek leaves duration unset when first and last packet coincide.
    else:
        raise ValueError("Zeek duration is unset for a multi-packet connection")
    reverse_bytes = 0
    if "resp_pkts" in row:
        reverse_bytes = _payload_bytes(row, "resp", reverse_packets, raw_protocol, row["id.resp_h"])
    elif "resp_bytes" in row:
        reverse_bytes = _counter(row, "resp_bytes")
    if "resp_bytes" not in row and "resp_pkts" not in row:
        missing.append("reverse_bytes")
    return Flow(
        event_id=str(uuid5(NAMESPACE_URL, f"{sensor_id}/{row['uid']}/{ts}")),
        timestamp=datetime.fromtimestamp(ts, timezone.utc),
        source=row["id.orig_h"], destination=row["id.resp_h"],
        source_port=_counter(row, "id.orig_p", required=False),
        destination_port=_counter(row, "id.resp_p", required=False),
        protocol=protocol if protocol in {"TCP", "UDP", "ICMP"} else "OTHER",
        duration=duration, packets=orig_packets,
        bytes=_payload_bytes(row, "orig", orig_packets, raw_protocol, row["id.orig_h"]),
        reverse_packets=reverse_packets, reverse_bytes=reverse_bytes,
        failed=state in {"S0", "REJ", "RSTOS0"}, syn_ratio=0,
        sensor_id=sensor_id, simulated=False, missing_features=missing,
    )


_ZEEK_FLOAT_TYPES = {"time", "interval", "double"}
_ZEEK_INT_TYPES = {"count", "int", "port"}


def _split_tsv(line: str, width: int) -> list[str]:
    values = line.split("\t")
    # IoT-23 research logs join their final label columns with runs of spaces.
    if len(values) < width and re.search(r" {2,}", values[-1]):
        values = values[:-1] + re.split(r" {2,}", values[-1])
    return values


def _zeek_value(value: str, zeek_type: str, field: str, line_number: int):
    try:
        if zeek_type in _ZEEK_FLOAT_TYPES:
            number = float(value)
            if not math.isfinite(number):
                raise ValueError("non-finite")
            return number
        if zeek_type in _ZEEK_INT_TYPES:
            if not re.fullmatch(r"-?\d+", value):
                raise ValueError("not an integer")
            return int(value)
        if zeek_type == "bool":
            if value not in {"T", "F"}:
                raise ValueError("not T/F")
            return value == "T"
    except ValueError as exc:
        raise ValueError(f"Invalid Zeek {zeek_type} for {field} at line {line_number}: {exc}") from exc
    return value


def read_zeek_tsv(path: Path, follow=False, max_line=16384):
    """Read Zeek ASCII (tab-separated) logs into typed records.

    Unset fields are omitted, exactly like Zeek JSON output, so the same
    normalizer applies to both formats. Header blocks may repeat (log rotation).
    """
    fields = types = None
    unset, empty = "-", "(empty)"
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
            line = line.rstrip("\r\n")
            if not line:
                continue
            if line.startswith("#"):
                key, _, value = line[1:].replace("\t", " ", 1).partition(" ")
                if key == "separator" and value not in {"\\x09", "\t"}:
                    raise ValueError("Only tab-separated Zeek ASCII logs are supported")
                if key in {"fields", "types"}:
                    names = re.split(r"\t| {2,}", line)[1:]
                    fields, types = (names, types) if key == "fields" else (fields, names)
                elif key == "unset_field":
                    unset = value
                elif key == "empty_field":
                    empty = value
                continue
            if not fields or not types or len(fields) != len(types):
                raise ValueError(f"Zeek TSV record at line {line_number} has no valid #fields/#types header")
            values = _split_tsv(line, len(fields))
            if len(values) != len(fields):
                raise ValueError(f"Zeek TSV line {line_number} has {len(values)} values for {len(fields)} fields")
            record = {}
            for field, zeek_type, value in zip(fields, types, values):
                if value == unset:
                    continue
                record[field] = "" if value == empty else _zeek_value(value, zeek_type, field, line_number)
            yield record


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


def _post_with_backoff(client, path: str, payload: dict, attempts: int = 10):
    """Honor the server's rate limits (429 Retry-After) instead of failing or hammering it."""
    for _ in range(attempts):
        response = client.post(path, json=payload)
        if response.status_code != 429:
            return response
        delay = response.headers.get("retry-after", "2")
        time.sleep(min(60, max(1, int(delay) if delay.isdigit() else 2)))
    return response


def forward(path: Path, url: str, format: str, sensor_id: str, follow=False, interval=0, force_simulated=False, batch_size=1):
    import httpx
    if interval < 0 or interval > 60:
        raise ValueError("Replay interval must be between 0 and 60 seconds")
    if not 1 <= batch_size <= 200:
        raise ValueError("Batch size must be between 1 and 200")
    if follow and batch_size > 1:
        raise ValueError("Follow mode forwards each record as it arrives; use a batch size of 1")
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
        accepted = rejected = duplicates = 0
        pending = []

        def report(event, simulated):
            print(json.dumps({"event_id": event["event_id"], "decision": event["fusion"]["decision"],
                              "risk": event["risk"]["score"], "simulated": simulated}), flush=True)

        def send(flows):
            nonlocal accepted, duplicates
            if len(flows) == 1 and batch_size == 1:
                response = _post_with_backoff(client, "/api/telemetry", flows[0].model_dump(mode="json"))
                if response.status_code == 409:
                    duplicates += 1
                    print(json.dumps({"event_id": flows[0].event_id, "status": "already_ingested"}), flush=True)
                    return
                response.raise_for_status()
                accepted += 1
                report(response.json(), flows[0].simulated)
                return
            response = _post_with_backoff(client, "/api/telemetry/batch", {"events": [f.model_dump(mode="json") for f in flows]})
            if response.status_code == 409:
                # Only duplicates failed; the rest of the batch was committed by the server.
                detail = response.json()["detail"]
                accepted += detail["accepted"]
                duplicates += len(detail["errors"])
                print(json.dumps({"status": "batch_partially_already_ingested", "accepted": detail["accepted"],
                                  "already_ingested": len(detail["errors"])}), flush=True)
                return
            response.raise_for_status()
            for event in response.json()["events"]:
                accepted += 1
                report(event, event.get("simulated"))

        rows = read_zeek_tsv(path, follow) if format == "zeek-tsv" else read_jsonl(path, follow)
        for number, row in enumerate(rows, 1):
            # A single unrepresentable sensor record (e.g. Zeek bad-checksum entries with no
            # counted packets) is reported and skipped; it must not stop the collector.
            try:
                flow = zeek_to_flow(row, sensor_id) if format in {"zeek", "zeek-tsv"} else Flow.model_validate(row)
            except ValueError as exc:
                rejected += 1
                print(json.dumps({"record": number, "status": "rejected", "reason": str(exc).splitlines()[-1][:300]}), flush=True)
                continue
            if force_simulated:
                flow = flow.model_copy(update={"simulated": True})
            pending.append(flow)
            if len(pending) >= batch_size:
                send(pending)
                pending = []
                if interval:
                    time.sleep(interval)
        if pending:
            send(pending)
        print(json.dumps({"accepted": accepted, "rejected": rejected, "already_ingested": duplicates, "source": str(path)}))
