from datetime import timezone
import json

import pytest

from aegisweave.collectors import read_jsonl, read_zeek_tsv, zeek_to_flow
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


TSV_HEADER = ("#separator \\x09\n#set_separator\t,\n#empty_field\t(empty)\n#unset_field\t-\n#path\tconn\n"
              "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\t"
              "conn_state\tlocal_orig\tlocal_resp\tmissed_bytes\thistory\torig_pkts\torig_ip_bytes\tresp_pkts\tresp_ip_bytes\t"
              "tunnel_parents   label   detailed-label\n"
              "#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tstring\tinterval\tcount\tcount\tstring\tbool\tbool\tcount\t"
              "string\tcount\tcount\tcount\tcount\tset[string]   string   string\n")


def tsv_row(*values, labels="-   Malicious   PartOfAHorizontalPortScan"):
    return "\t".join(map(str, values)) + "\t" + labels + "\n"


def test_zeek_tsv_reader_types_unset_and_iot23_label_quirk(tmp_path):
    path = tmp_path / "conn.log.labeled"
    path.write_text(TSV_HEADER
                    + tsv_row(1526756261.8665, "C1", "192.168.2.5", 38792, "200.168.87.203", 23, "tcp", "-", "-", "-", "-",
                              "S0", "-", "-", 0, "S", 1, 60, 0, 0)
                    + tsv_row(1526756262.1, "C2", "192.168.2.5", 5353, "224.0.0.251", 5353, "udp", "dns", "-", "-", "-",
                              "S0", "T", "F", 0, "D", 1, 76, 0, 0, labels="(empty)   Benign   -")
                    + "#close\t2018-05-19-15-15-52\n")
    scan, dns = list(read_zeek_tsv(path))
    assert scan["ts"] == 1526756261.8665 and scan["id.resp_p"] == 23 and scan["orig_pkts"] == 1
    assert "duration" not in scan and "orig_bytes" not in scan  # unset fields are omitted like Zeek JSON
    assert scan["detailed-label"] == "PartOfAHorizontalPortScan" and dns["tunnel_parents"] == "" and dns["local_orig"] is True
    probe = zeek_to_flow(scan, "iot23")
    assert probe.duration == 0 and probe.bytes == 0 and probe.packets == 1 and probe.failed is True
    datagram = zeek_to_flow(dns, "iot23")
    assert datagram.bytes == 76 - 20 - 8 and datagram.reverse_bytes == 0  # exact UDP payload from IP length


@pytest.mark.parametrize("line,match", [
    ("1\tC1\t10.0.0.1\n", "values for"),
    (tsv_row("nan", "C1", "10.0.0.1", 1, "10.0.0.2", 2, "tcp", "-", "-", "-", "-", "S0", "-", "-", 0, "S", 1, 40, 0, 0), "Invalid Zeek time"),
    (tsv_row(1.0, "C1", "10.0.0.1", "x", "10.0.0.2", 2, "tcp", "-", "-", "-", "-", "S0", "-", "-", 0, "S", 1, 40, 0, 0), "Invalid Zeek port"),
])
def test_zeek_tsv_rejects_malformed_records(tmp_path, line, match):
    path = tmp_path / "conn.log"
    path.write_text(TSV_HEADER + line)
    with pytest.raises(ValueError, match=match):
        list(read_zeek_tsv(path))


def test_zeek_tsv_requires_header(tmp_path):
    path = tmp_path / "conn.log"
    path.write_text(tsv_row(1.0, "C1", "10.0.0.1", 1, "10.0.0.2", 2, "tcp", "-", "-", "-", "-", "S0", "-", "-", 0, "S", 1, 40, 0, 0))
    with pytest.raises(ValueError, match="header"):
        list(read_zeek_tsv(path))


def test_zeek_unset_measurements_are_derived_exactly_or_refused():
    single = {**zeek(), "orig_pkts": 1, "resp_pkts": 0, "conn_state": "S0"}
    for key in ("duration", "orig_bytes", "resp_bytes"):
        single.pop(key)
    assert zeek_to_flow(single).duration == 0.0
    multi = {**single, "orig_pkts": 3}
    with pytest.raises(ValueError, match="duration"):
        zeek_to_flow(multi)
    ipv6_udp = {**single, "proto": "udp", "id.orig_h": "2001:db8::1", "id.resp_h": "2001:db8::2", "orig_ip_bytes": 100}
    assert zeek_to_flow(ipv6_udp).bytes == 100 - 40 - 8
    with pytest.raises(ValueError, match="missing"):
        zeek_to_flow({**single, "proto": "udp"})  # no IP length to derive payload from


def test_responder_only_records_are_valid_but_packetless_records_are_not():
    responder_only = {**zeek(), "orig_pkts": 0, "orig_bytes": 0, "conn_state": "RSTRH"}
    assert zeek_to_flow(responder_only).packets == 0
    with pytest.raises(ValueError, match="at least one measured packet"):
        zeek_to_flow({**zeek(), "orig_pkts": 0, "resp_pkts": 0, "orig_bytes": 0, "resp_bytes": 0, "conn_state": "OTH"})


def test_omitted_optional_telemetry_fields_are_explicit():
    row = zeek_to_flow(zeek()).model_dump()
    del row["failed"]
    del row["reverse_bytes"]
    row["missing_features"] = []
    assert set(Flow.model_validate(row).missing_features) == {"failed", "reverse_bytes"}
