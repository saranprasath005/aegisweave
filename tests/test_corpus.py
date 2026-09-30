"""Real-corpus pipeline on an IoT-23-format fixture: labels, accounting, splits, provenance."""
import json

import numpy as np
import pytest

from aegisweave.behavior import BehaviorEngine
from aegisweave.collectors import read_zeek_tsv, zeek_to_flow
from aegisweave.corpus import BLOCK_PATTERN, build_split, iot23_label, load_capture
from aegisweave.features import behavior_features, flow_features
from aegisweave.ml import ModelBundle, fit_bundle

HEADER = ("#separator \\x09\n#set_separator\t,\n#empty_field\t(empty)\n#unset_field\t-\n#path\tconn\n"
          "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\t"
          "conn_state\tlocal_orig\tlocal_resp\tmissed_bytes\thistory\torig_pkts\torig_ip_bytes\tresp_pkts\tresp_ip_bytes\t"
          "tunnel_parents\tlabel\tdet_label\n"
          "#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tstring\tinterval\tcount\tcount\tstring\tbool\tbool\tcount\t"
          "string\tcount\tcount\tcount\tcount\tset[string]\tstring\tstring\n")


def fixture(path, records=1200, name="CTU-Fixture-Capture-1-1"):
    rng = np.random.default_rng(3)
    lines, t = [HEADER], 1_600_000_000.
    for i in range(records):
        t += float(rng.uniform(.5, 3))
        kind = ("benign", "scan", "benign", "attack", "benign", "scan")[i % 6]
        if i % 97 == 5:
            kind = "packetless"
        if kind == "benign":
            row = [t, f"B{i}", "192.168.1.10", 40000 + i % 900, f"8.8.{i % 4}.8", 53, "udp", "dns", round(rng.uniform(.01, .2), 4),
                   int(rng.integers(30, 60)), int(rng.integers(60, 200)), "SF", "-", "-", 0, "Dd", 1, 80, 1, 150, "-", "Benign", "-"]
        elif kind == "scan":
            row = [t, f"S{i}", "192.168.1.50", 50000 + i % 900, f"45.{i % 200}.{i % 7}.1", 23, "tcp", "-", "-", "-", "-",
                   "S0", "-", "-", 0, "S", 1, 60, 0, 0, "-", "Malicious", "PartOfAHorizontalPortScan"]
        elif kind == "attack":
            row = [t, f"A{i}", "192.168.1.50", 51000 + i % 900, "192.168.1.1", 2323, "tcp", "-", round(rng.uniform(1, 4), 3),
                   int(rng.integers(20, 90)), int(rng.integers(20, 90)), "SF", "-", "-", 0, "ShAdDaFf", 8, 500, 7, 480, "-", "Malicious", "Attack"]
        else:
            row = [t, f"P{i}", "192.168.1.50", 65279, "123.59.209.185", 80, "tcp", "-", "-", "-", "-",
                   "OTH", "-", "-", 0, "C", 0, 0, 0, 0, "-", "Malicious", "DDoS"]
        lines.append("\t".join(map(str, row)) + "\n")
    file = path / f"{name}.conn.log.labeled"
    file.write_text("".join(lines))
    return file


@pytest.mark.parametrize("record,expected", [
    ({"label": "Benign", "detailed-label": "-"}, "normal"), ({"label": "benign", "det_label": "-"}, "normal"),
    ({"label": "Malicious", "detailed-label": "PartOfAHorizontalPortScan"}, "scan"),
    ({"label": "Malicious", "det_label": "C&C-HeartBeat"}, "command_and_control"), ({"label": "Malicious", "detailed-label": "Attack"}, "attack_attempt")])
def test_documented_iot23_labels(record, expected):
    assert iot23_label(record) == expected


@pytest.mark.parametrize("record", [{"label": "Malicious", "detailed-label": "-"}, {"label": "Malicious", "detailed-label": "Exfiltration"}])
def test_unmapped_labels_are_refused(record):
    with pytest.raises(ValueError):
        iot23_label(record)


def test_capture_uses_serving_code_path_and_accounts_for_exclusions(tmp_path):
    path = fixture(tmp_path)
    capture = load_capture(path, held_out=False, seed=1, reservoir=25)
    packetless = sum(1 for i in range(1200) if i % 97 == 5)
    assert capture.excluded == {"dos: no measured packets": packetless}
    assert capture.kept.sum() == 1200 - packetless and not capture.kept[5]
    # Features equal an independent pass through the serving collector and behaviour engine.
    engine, index = BehaviorEngine(), 0
    for record in read_zeek_tsv(path):
        try:
            flow = zeek_to_flow(record, sensor_id="iot23-CTU-Fixture-Capture-1-1")
        except ValueError:
            index += 1
            continue
        context = engine.observe(flow)
        assert np.array_equal(capture.flow[index], flow_features(flow))
        assert np.array_equal(capture.behavior[index], behavior_features(context))
        index += 1
    samples = capture.samples[("temporal_blocks", "scan")]
    assert len(samples) == 25 and all(BLOCK_PATTERN[capture.block[i]] == "test" for i, _, _ in samples)
    assert ("leave_capture_out", "scan") not in capture.samples


def test_split_guarantees_and_real_data_provenance(tmp_path):
    captures = [load_capture(fixture(tmp_path), held_out=False, seed=1, reservoir=40)]
    split = build_split(captures, "temporal_blocks", withheld_classes=("attack_attempt",), seed=1, gap_seconds=5,
                        decision_rows_per_label=30, min_train_rows=50)
    for name in ("train", "calibration", "fusion", "tuning"):
        assert "attack_attempt" not in split.parts[name].labels
    assert "attack_attempt" in split.parts["test"].labels
    # Packetless DDoS records never reach a partition; they are reported as unrepresentable, not as rare.
    assert split.report["excluded_rare_classes"] == {}
    assert split.report["captures"]["CTU-Fixture-Capture-1-1"]["excluded_unrepresentable"] == {"dos: no measured packets": 13}
    assert len(split.unseen_test) == len(split.parts["test"].labels)
    assert split.report["context_isolation"]["test_captures_disjoint_from_fitting"] is False
    assert split.report["context_isolation"]["all_fitting_partitions_have_independent_context"] is True
    assert split.report["test_rows_unseen"] == int(split.unseen_test.sum())
    assert set(split.decision_sample.labels) == {"normal", "scan", "attack_attempt"}
    assert len(split.decision_sample.flows) == len(split.decision_sample.labels) <= 90
    # Reservoir rows inside a boundary purge never reach serving-path evaluation.
    from aegisweave.corpus import assign, purge_mask
    capture = captures[0]
    purged = purge_mask(capture, assign(capture, "temporal_blocks", set()), 5)
    sampled = {flow.event_id for flow in split.decision_sample.flows}
    indices = [i for (_, label), rows in capture.samples.items() for i, flow, _ in rows if flow.event_id in sampled]
    assert indices and not purged[indices].any()
    dataset = {"id_prefix": "fixture-real", "name": "fixture corpus", "simulated": False, "status": "research-real-data",
               "implementation_files": ("corpus.py", "collectors.py"), "provenance": {"source": "unit fixture"}}
    bundle = fit_bundle(split.parts, 1, dataset=dataset, isolation=split.report)
    assert bundle.metadata["simulated_training"] is False and bundle.metadata["provenance"]["source"] == "unit fixture"
    assert {"corpus.py", "collectors.py"} <= set(bundle.metadata["implementation_sha256"])
    assert "attack_attempt" not in bundle.supervised.classes_
    bundle.save(tmp_path / "model")
    restored = ModelBundle.load(tmp_path / "model")
    result = restored.predict(split.decision_sample.flows[0], split.decision_sample.contexts[0])
    assert result["model"]["simulated_training"] is False
    json.dumps(restored.metadata, allow_nan=False, default=str)


def test_split_refuses_partitions_without_both_benign_and_attack_rows(tmp_path):
    path = fixture(tmp_path, records=400)
    text = "".join(line for line in path.read_text().splitlines(True) if line.startswith("#") or "\tBenign\t" in line)
    path.write_text(text)
    with pytest.raises(ValueError, match="lacks benign or attack rows"):
        build_split([load_capture(path, held_out=False, seed=1)], "temporal_blocks", seed=1, gap_seconds=0)


def test_held_out_captures_must_exist(tmp_path):
    captures = [load_capture(fixture(tmp_path), held_out=False, seed=1)]
    with pytest.raises(ValueError, match="not loaded"):
        build_split(captures, "leave_capture_out", held_out=("CTU-Missing",), seed=1)


@pytest.mark.parametrize("perturb", ["test", "withheld"])
def test_other_partitions_cannot_influence_fitting_context(tmp_path, perturb):
    from aegisweave.corpus import BLOCKS
    path = fixture(tmp_path, records=600)
    original = load_capture(path, held_out=False, seed=7)
    kwargs = dict(withheld_classes=("attack_attempt",), seed=7, gap_seconds=0, min_train_rows=10)
    before = build_split([original], "temporal_blocks", **kwargs)
    lines, index = [], 0
    for line in path.read_text().splitlines(True):
        if line.startswith("#"):
            lines.append(line)
            continue
        fields = line.rstrip("\n").split("\t")
        partition = BLOCK_PATTERN[min(BLOCKS - 1, index * BLOCKS // 600)]
        target = partition == "test" if perturb == "test" else fields[-1] == "Attack"
        if target:
            # Extreme future timestamps used to poison the shared watermark, too.
            fields[0] = str(float(fields[0]) + 100000)
            fields[9] = "900000"
            fields[4] = "203.0.113.99"
        lines.append("\t".join(fields) + "\n")
        index += 1
    path.write_text("".join(lines))
    after = build_split([load_capture(path, held_out=False, seed=7)], "temporal_blocks", **kwargs)
    for partition in ("train", "calibration", "fusion", "tuning"):
        for field in ("flow", "behavior", "history", "labels"):
            np.testing.assert_array_equal(getattr(before.parts[partition], field), getattr(after.parts[partition], field))


@pytest.mark.parametrize("protocol", ["temporal_blocks", "leave_capture_out"])
def test_split_context_matches_independent_partition_replay(tmp_path, protocol):
    from aegisweave.corpus import assign, purge_mask
    paths = [fixture(tmp_path, records=600, name=f"capture-{i}") for i in range(2)]
    # held_out at loading is deliberately false: build_split owns the actual protocol.
    captures = [load_capture(p, held_out=False, seed=2) for p in paths]
    held = {"capture-1"} if protocol == "leave_capture_out" else set()
    split = build_split(captures, protocol, held_out=held, withheld_classes=("attack_attempt",),
                        gap_seconds=5, min_train_rows=10, decision_rows_per_label=1000)
    expected = {}
    expected_rows = {}
    for capture, path in zip(captures, paths):
        assignment = assign(capture, protocol, held)
        purged = purge_mask(capture, assignment, 5)
        engine, previous = BehaviorEngine(), None
        for i, record in enumerate(read_zeek_tsv(path)):
            partition = assignment[i]
            if previous != partition:
                engine = BehaviorEngine()
                previous = partition
            if not capture.kept[i] or purged[i]:
                continue
            if partition != "test" and capture.labels[i] == "attack_attempt":
                continue
            flow = zeek_to_flow(record, sensor_id=f"iot23-{capture.name}")
            context = engine.observe(flow)
            expected[flow.event_id] = (partition, context)
            expected_rows.setdefault((partition, capture.name, capture.labels[i]), []).append(context)
    for partition, part in split.parts.items():
        for capture in captures:
            for label in set(part.labels):
                mask = (part.episode_ids == capture.name) & (part.labels == label)
                if not mask.any():
                    continue
                contexts = expected_rows[(partition, capture.name, label)]
                np.testing.assert_array_equal(part.behavior[mask], [behavior_features(c) for c in contexts])
                np.testing.assert_array_equal(part.history[mask],
                    [float(c["available"]) * min(1., c["history_count"] / 8) for c in contexts])
    sample = split.decision_sample
    assert sample.flows
    for i, (flow, context) in enumerate(zip(sample.flows, sample.contexts)):
        partition, reference = expected[flow.event_id]
        assert partition == "test"
        assert context == reference
        np.testing.assert_array_equal(sample.behavior[i], behavior_features(reference))
        assert sample.history[i] == float(reference["available"]) * min(1., reference["history_count"] / 8)
    if held:
        assert set(sample.episode_ids) == held


def test_split_refuses_changed_source(tmp_path):
    path = fixture(tmp_path, records=600)
    capture = load_capture(path, held_out=False, seed=1)
    path.write_text(path.read_text() + "# changed\n")
    with pytest.raises(ValueError, match="source missing or changed"):
        build_split([capture], "temporal_blocks", gap_seconds=0, min_train_rows=10)
