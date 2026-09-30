import json

import httpx
import pytest

from aegisweave.ingest import CollectorError, Spool, collector_health, publish_status


def row(uid="one"):
    return {"ts": 1700000000., "uid": uid, "id.orig_h": "10.0.0.1", "id.resp_h": "10.0.0.2",
            "id.orig_p": 42000, "id.resp_p": 443, "proto": "tcp", "duration": .5,
            "orig_pkts": 5, "resp_pkts": 3, "orig_bytes": 300, "resp_bytes": 600, "conn_state": "SF"}


def write(path, *rows):
    with path.open("ab") as out:
        for record in rows:
            out.write((json.dumps(record) + "\n").encode())


def test_offsets_and_pending_survive_restart_and_partial_line(tmp_path):
    path = tmp_path / "conn.log"
    write(path, row())
    partial = json.dumps(row("two")).encode()
    with path.open("ab") as out:
        out.write(partial)
    for expected in (1, 0):
        spool = Spool(tmp_path / "spool.db", "sensor", str(path))
        try:
            assert spool.poll() == expected
            assert spool.status()["pending"] == 1
        finally:
            spool.close()
    with path.open("ab") as out:
        out.write(b"\n")
    spool = Spool(tmp_path / "spool.db", "sensor", str(path))
    try:
        assert spool.poll() == 1
        assert spool.status()["pending"] == 2
    finally:
        spool.close()


def test_rename_rotation_and_backpressure(tmp_path):
    path = tmp_path / "conn.log"
    write(path, row("one"), row("two"))
    spool = Spool(tmp_path / "spool.db", "sensor", str(tmp_path / "*.log"), max_pending=1)
    try:
        assert spool.poll() == 1
        path.rename(tmp_path / "old.log")
        write(path, row("three"))
        assert spool.poll() == 0
        def ack(request):
            events = json.loads(request.content)["events"]
            return httpx.Response(201, json={"accepted": len(events), "events": events})
        with httpx.Client(transport=httpx.MockTransport(ack), base_url="http://test") as client:
            for _ in range(3):
                spool.deliver(client)
                spool.poll()
        assert spool.status()["queued"] == 3
        assert spool.status()["delivered"] == 3
        assert spool.status()["pending"] == 0
    finally:
        spool.close()


def test_failed_delivery_then_duplicate_ack_retains_evidence(tmp_path):
    path = tmp_path / "conn.log"
    write(path, row())
    spool = Spool(tmp_path / "spool.db", "sensor", str(path))
    try:
        spool.poll()
        def failure(request):
            return httpx.Response(503)
        with httpx.Client(transport=httpx.MockTransport(failure), base_url="http://test") as client:
            with pytest.raises(httpx.HTTPStatusError):
                spool.deliver(client)
        assert spool.status()["pending"] == 1
        def duplicate(request):
            events = json.loads(request.content)["events"]
            return httpx.Response(409, json={"detail": {"accepted": 0, "event_ids": [],
                "errors": [{"event_id": e["event_id"], "type": "DuplicateEvent"} for e in events]}})
        with httpx.Client(transport=httpx.MockTransport(duplicate), base_url="http://test") as client:
            assert spool.deliver(client) == 1
        assert spool.status()["pending"] == 0
        assert spool.status()["duplicates"] == 1
    finally:
        spool.close()


def test_rejection_accounting_and_transaction_rollback(tmp_path, monkeypatch):
    path = tmp_path / "conn.log"
    path.write_bytes(b'{"bad":true}\n')
    write(path, row())
    spool = Spool(tmp_path / "spool.db", "sensor", str(path))
    try:
        original = spool.count
        def fail(key, amount=1):
            if key == "queued":
                raise RuntimeError("simulated crash before cursor commit")
            original(key, amount)
        monkeypatch.setattr(spool, "count", fail)
        with pytest.raises(RuntimeError):
            spool.poll()
        assert spool.status()["rejected"] == 1
        assert spool.status()["pending"] == 0
        monkeypatch.setattr(spool, "count", original)
        assert spool.poll() == 1
        assert spool.status()["pending"] == 1
    finally:
        spool.close()


def test_truncation_and_competing_owner_are_visible(tmp_path):
    path = tmp_path / "conn.log"
    write(path, row())
    db = tmp_path / "spool.db"
    spool = Spool(db, "sensor", str(path))
    try:
        spool.poll()
        with pytest.raises(CollectorError, match="owns"):
            Spool(db, "sensor", str(path))
        path.write_bytes(b"")
        with pytest.raises(CollectorError, match="truncated"):
            spool.poll()
    finally:
        spool.close()
    with pytest.raises(CollectorError, match="sensor differs"):
        Spool(db, "different-sensor", str(path))


def test_unmatched_ack_does_not_discard_queue(tmp_path):
    path = tmp_path / "conn.log"
    write(path, row())
    spool = Spool(tmp_path / "spool.db", "sensor", str(path))
    try:
        spool.poll()
        with httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(201,
                         json={"accepted": 1, "events": [{"event_id": "wrong"}]})), base_url="http://test") as client:
            with pytest.raises(CollectorError, match="acknowledgment"):
                spool.deliver(client)
        assert spool.status()["pending"] == 1
    finally:
        spool.close()


def test_bad_sensor_and_self_matching_source_fail_before_consumption(tmp_path):
    with pytest.raises(ValueError):
        Spool(tmp_path / "bad.db", "invalid sensor", str(tmp_path / "*.log"))
    assert not (tmp_path / "bad.db").exists()
    spool = Spool(tmp_path / "spool.db", "sensor", str(tmp_path / "*"))
    try:
        with pytest.raises(CollectorError, match="collector state"):
            spool.poll()
        assert spool.status()["pending"] == 0
    finally:
        spool.close()


def test_health_reports_missing_stale_delivery_and_backlog(tmp_path, monkeypatch):
    import time
    spool = tmp_path / "spool.db"
    assert not collector_health(spool)["healthy"]
    status = {"pending": 0, "oldest_pending_age_seconds": 0, "source_error": None,
              "delivery_error": None, "backpressure": False, "rejected_this_cycle": 0}
    publish_status(spool, status)
    assert collector_health(spool)["healthy"]
    for change in ({"source_error": "missing log"}, {"delivery_error": "HTTPStatusError"},
                   {"backpressure": True}, {"rejected_this_cycle": 1},
                   {"pending": 1, "oldest_pending_age_seconds": 500}):
        publish_status(spool, {**status, **change})
        assert not collector_health(spool)["healthy"]
    publish_status(spool, status)
    future = time.time() + 150
    monkeypatch.setattr("aegisweave.ingest.time.time", lambda: future)
    assert not collector_health(spool)["healthy"]
