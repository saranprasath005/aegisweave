from datetime import timezone
import json

import pytest

from aegisweave.collectors import read_jsonl, zeek_to_flow
from aegisweave.schema import Flow


def zeek():
    return {"ts": 1700000000., "uid": "test-connection", "id.orig_h": "10.0.0.1", "id.resp_h": "10.0.0.2",
            "id.orig_p": 42000, "id.resp_p": 443, "proto": "tcp", "duration": .5,
            "orig_pkts": 5, "resp_pkts": 3, "orig_bytes": 300, "resp_bytes": 600, "conn_state": "SF"}


def test_zeek_uses_directional_counts_and_declares_missing_syn_measurement():
    result = zeek_to_flow(zeek())
    assert result.packets == 5 and result.reverse_packets == 3
    assert result.bytes == 300 and result.reverse_bytes == 600
    assert result.missing_features == ["syn_ratio"]
    assert result.simulated is False and result.timestamp.tzinfo == timezone.utc
    assert zeek_to_flow(zeek()).event_id == result.event_id


def test_zeek_does_not_invent_unavailable_measurements():
    row = zeek()
    del row["resp_pkts"]
    row["conn_state"] = "OTH"
    result = zeek_to_flow(row)
    assert set(result.missing_features) == {"syn_ratio", "failed", "reverse_packets"}
    del row["orig_bytes"]
    with pytest.raises(ValueError, match="missing"):
        zeek_to_flow(row)


@pytest.mark.parametrize("value", [-1, True, "5", 3.5])
def test_invalid_zeek_counter(value):
    row = zeek()
    row["orig_pkts"] = value
    with pytest.raises(ValueError):
        zeek_to_flow(row)


@pytest.mark.parametrize("content", ['{"a":1,"a":2}\n', '{"a":NaN}\n', '[]\n', '{bad}\n'])
def test_jsonl_rejects_ambiguous_or_malformed_rows(tmp_path, content):
    path = tmp_path / "events.jsonl"
    path.write_text(content)
    with pytest.raises(ValueError):
        list(read_jsonl(path))


def test_bounded_jsonl_and_final_line_without_newline(tmp_path):
    path = tmp_path / "events.jsonl"
    path.write_text('{"a":1}\n{"a":2}')
    assert list(read_jsonl(path)) == [{"a": 1}, {"a": 2}]
    with pytest.raises(ValueError, match="exceeds"):
        list(read_jsonl(path, max_line=5))


def test_omitted_optional_telemetry_fields_are_explicit():
    row = zeek_to_flow(zeek()).model_dump()
    del row["failed"]
    del row["reverse_bytes"]
    row["missing_features"] = []
    assert set(Flow.model_validate(row).missing_features) == {"failed", "reverse_bytes"}
