"""Labeled real-traffic corpora for training and evaluating the LIVE pipeline (IoT-23).

Records pass through the same Zeek collector and behaviour engine used in serving, in the
order a live sensor delivers them (Zeek writes a connection when it ends). Ground-truth
labels are read only from the research columns and never enter telemetry or features.

Partition assignments (fixed before the original experiments; context isolation revised in v2):
- temporal_blocks: each capture's records are cut into 20 contiguous arrival-order blocks
  mapped to partitions by a fixed interleaved pattern, so bursty attack phases remain
  testable without shuffling rows. Records within `gap_seconds` of a boundary between
  different partitions are purged.
- leave_capture_out: whole captures are held out for testing; the other captures supply
  train/calibration/fusion/tuning blocks.

For fitting and evaluation, build_split rebuilds behavior after assignment and exclusions,
resetting all history and watermarks at each partition transition. load_capture retains
whole-capture features only for replay diagnostics.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field, replace
import hashlib
from pathlib import Path
import uuid

import numpy as np

from .behavior import BehaviorEngine
from .collectors import read_zeek_tsv, zeek_to_flow
from .features import BEHAVIOR_FEATURES, FLOW_FEATURES, behavior_features, flow_features

IOT23 = {"name": "IoT-23", "source": "https://www.stratosphereips.org/datasets-iot23",
         "files": "https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios/",
         "citation": "S. Garcia, A. Parmisano and M. J. Erquiaga, IoT-23: A labeled dataset with malicious and benign IoT network traffic, Stratosphere Laboratory, 2020"}

# Documented IoT-23 labels -> project classes. Unmapped labels are refused, never guessed.
IOT23_CLASSES = {
    "benign": "normal",
    "partofahorizontalportscan": "scan",
    "ddos": "dos",
    "c&c": "command_and_control",
    "c&c-filedownload": "command_and_control",
    "c&c-heartbeat": "command_and_control",
    "c&c-heartbeat-filedownload": "command_and_control",
    "c&c-mirai": "command_and_control",
    "c&c-torii": "command_and_control",
    "attack": "attack_attempt",
    "filedownload": "file_download",
}
PARTITIONS = ("train", "calibration", "fusion", "tuning", "test")
BLOCKS = 20
BLOCK_PATTERN = ("train", "train", "calibration", "train", "fusion", "train", "tuning", "train", "test", "train",
                 "train", "calibration", "train", "fusion", "train", "tuning", "train", "test", "train", "train")


def iot23_label(record: dict) -> str:
    detailed = str(record.get("detailed-label", record.get("det_label", ""))).strip()
    raw = detailed if detailed not in {"", "-"} else str(record.get("label", "")).strip()
    key = raw.lower()
    if key == "malicious":
        raise ValueError("Malicious IoT-23 record without a detailed label")
    if key not in IOT23_CLASSES:
        raise ValueError(f"Unmapped IoT-23 label: {raw!r}")
    return IOT23_CLASSES[key]


def capture_name(path: Path) -> str:
    return Path(path).name.split(".")[0]


def count_records(path: Path) -> int:
    with Path(path).open(encoding="utf-8-sig") as handle:
        return sum(1 for line in handle if line.strip() and not line.startswith("#"))


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


@dataclass
class Capture:
    """Model inputs for every record of one capture, in sensor arrival order."""
    name: str
    sha256: str
    flow: np.ndarray
    behavior: np.ndarray
    history: np.ndarray
    timestamp: np.ndarray
    labels: np.ndarray
    event_key: np.ndarray
    kept: np.ndarray
    block: np.ndarray
    excluded: dict
    reordered: int
    isolated: int
    source_path: str = ""
    max_lateness: float = 300.
    samples: dict = field(default_factory=dict)  # (protocol, label) -> list[(index, Flow, context)]


def _history_reliability(context: dict) -> float:
    return float(context["available"]) * min(1., context["history_count"] / 8)


def load_capture(path: Path, *, held_out: bool, seed: int, reservoir: int = 2000, max_lateness: float = 300.) -> Capture:
    """One streaming pass: collector -> behaviour engine -> features, plus seeded test reservoirs.

    Reservoirs keep full Flow objects and contexts (needed for serving-path decision
    evaluation) only for a bounded sample of test-partition records per label.
    """
    path = Path(path)
    name = capture_name(path)
    total = count_records(path)
    flow_x = np.zeros((total, len(FLOW_FEATURES)))
    behavior_x = np.zeros((total, len(BEHAVIOR_FEATURES)))
    history, timestamp = np.zeros(total), np.zeros(total)
    labels = np.empty(total, dtype=object)
    event_key = np.zeros(total, dtype=np.uint64)
    kept = np.zeros(total, dtype=bool)
    block = np.minimum(BLOCKS - 1, np.arange(total) * BLOCKS // max(total, 1))
    excluded = Counter()
    engine = BehaviorEngine(max_lateness=max_lateness)
    rng = np.random.default_rng([seed, int(hashlib.sha256(name.encode()).hexdigest()[:8], 16)])
    samples, seen = defaultdict(list), Counter()
    reordered = isolated = 0
    index = -1
    for index, record in enumerate(read_zeek_tsv(path)):
        label = iot23_label(record)
        labels[index] = label
        timestamp[index] = record["ts"]
        try:
            flow = zeek_to_flow(record, sensor_id=f"iot23-{name}")
        except ValueError as exc:
            reason = "no measured packets" if "measured packet" in str(exc) else str(exc).splitlines()[-1][:120]
            excluded[f"{label}: {reason}"] += 1
            continue
        context = engine.observe(flow)
        reordered += context["reordered"]
        isolated += context["late_event"]
        flow_x[index] = flow_features(flow)
        behavior_x[index] = behavior_features(context)
        history[index] = _history_reliability(context)
        event_key[index] = uuid.UUID(flow.event_id).int & 0xFFFFFFFFFFFFFFFF
        kept[index] = True
        protocols = ["leave_capture_out"] if held_out else []
        if BLOCK_PATTERN[block[index]] == "test":
            protocols.append("temporal_blocks")
        for protocol in protocols:
            key = (protocol, label)
            seen[key] += 1
            if len(samples[key]) < reservoir:
                samples[key].append((index, flow, context))
            else:
                slot = int(rng.integers(0, seen[key]))
                if slot < reservoir:
                    samples[key][slot] = (index, flow, context)
    if index + 1 != total:
        raise ValueError(f"{name}: counted {total} records but read {index + 1}")
    return Capture(name, file_sha256(path), flow_x, behavior_x, history, timestamp, labels, event_key, kept, block,
                   dict(excluded), reordered, isolated, str(path.resolve()), max_lateness, dict(samples))


def purge_mask(capture: Capture, assignment: np.ndarray, gap_seconds: float) -> np.ndarray:
    """True for records within gap_seconds (event time) of a block whose partition differs."""
    purged = np.zeros(len(assignment), dtype=bool)
    if gap_seconds <= 0:
        return purged
    for b in range(BLOCKS):
        members = np.flatnonzero(capture.block == b)
        if not len(members):
            continue
        for neighbour in (b - 1, b + 1):
            others = np.flatnonzero(capture.block == neighbour)
            if not len(others) or assignment[members[0]] == assignment[others[0]]:
                continue
            times = capture.timestamp[members]
            if neighbour < b:
                purged[members] |= times < capture.timestamp[others].max() + gap_seconds
            else:
                purged[members] |= times > capture.timestamp[others].min() - gap_seconds
    return purged


def assign(capture: Capture, protocol: str, held_out: set[str]) -> np.ndarray:
    pattern = np.asarray(BLOCK_PATTERN, dtype=object)[capture.block]
    if protocol == "temporal_blocks":
        return pattern
    if protocol == "leave_capture_out":
        if capture.name in held_out:
            return np.full(len(capture.block), "test", dtype=object)
        return np.where(pattern == "test", "train", pattern)
    raise ValueError(f"Unknown split protocol {protocol}")


def _isolated_capture(capture, assignment, usable, protocol, seed, reservoir):
    """Rebuild from verified source, with state confined to a contiguous partition run.

    Unselected rows may supply context only within their own eligible partition.
    Purged, rare, and withheld fitting rows never update state or its watermark.
    Original whole-capture arrays remain available for historical replay comparisons.
    """
    path = Path(capture.source_path)
    if not capture.source_path or not path.is_file() or file_sha256(path) != capture.sha256:
        raise ValueError(f"{capture.name}: source missing or changed; reload the capture before splitting")
    behavior = np.zeros_like(capture.behavior)
    history = np.zeros_like(capture.history)
    engine = BehaviorEngine(max_lateness=capture.max_lateness)
    rng = np.random.default_rng([seed, int(hashlib.sha256(capture.name.encode()).hexdigest()[:8], 16)])
    samples, seen = defaultdict(list), Counter()
    previous = None
    index = -1
    for index, record in enumerate(read_zeek_tsv(path)):
        partition = assignment[index]
        if partition != previous:
            engine.reset()
            previous = partition
        if not usable[index]:
            continue
        flow = zeek_to_flow(record, sensor_id=f"iot23-{capture.name}")
        context = engine.observe(flow)
        behavior[index] = behavior_features(context)
        history[index] = _history_reliability(context)
        if partition == "test":
            key = (protocol, capture.labels[index])
            seen[key] += 1
            item = (index, flow, context)
            if len(samples[key]) < reservoir:
                samples[key].append(item)
            else:
                slot = int(rng.integers(0, seen[key]))
                if slot < reservoir:
                    samples[key][slot] = item
    if index + 1 != len(assignment) or file_sha256(path) != capture.sha256:
        raise ValueError(f"{capture.name}: source changed while rebuilding context")
    return replace(capture, behavior=behavior, history=history, samples=dict(samples))


def _rows_view(matrix: np.ndarray) -> np.ndarray:
    matrix = np.ascontiguousarray(matrix, dtype="<f8")
    return matrix.view(np.dtype((np.void, matrix.dtype.itemsize * matrix.shape[1]))).ravel()


DEFAULT_CAPS = {"train": 15000, "calibration": 3000, "fusion": 3000, "tuning": 3000, "test": None}


@dataclass
class CorpusSplit:
    parts: dict          # train/calibration/fusion/tuning/test MatrixSets (test: every usable row)
    unseen_test: np.ndarray  # test rows whose flow vector never occurs in any fitting-partition row
    decision_sample: object  # MatrixSet with Flow objects and contexts for serving-path evaluation
    report: dict


def build_split(captures: list[Capture], protocol: str, *, held_out=(), withheld_classes=(), caps=None,
                seed=42, gap_seconds=60., min_train_rows=50, decision_rows_per_label=2000) -> CorpusSplit:
    from .ml import MatrixSet
    if not np.isfinite(gap_seconds) or gap_seconds < 0:
        raise ValueError("gap_seconds must be finite and nonnegative")
    if decision_rows_per_label < 1:
        raise ValueError("decision_rows_per_label must be positive")
    if len({c.name for c in captures}) != len(captures):
        raise ValueError("Capture names must be unique")
    caps = {**DEFAULT_CAPS, **(caps or {})}
    held_out, withheld_classes = set(held_out), set(withheld_classes)
    unknown = held_out - {c.name for c in captures}
    if unknown:
        raise ValueError(f"Held-out captures not loaded: {sorted(unknown)}")
    rng = np.random.default_rng(seed)
    selected = {p: [] for p in PARTITIONS}
    fitting_vectors, available_train = [], Counter()
    report = {"protocol": protocol, "held_out_captures": sorted(held_out), "withheld_classes": sorted(withheld_classes),
              "gap_seconds": gap_seconds, "caps_per_capture_label": caps, "captures": {}}
    purged_masks = {}
    for ci, capture in enumerate(captures):
        assignment = assign(capture, protocol, held_out)
        purged = purge_mask(capture, assignment, gap_seconds) & capture.kept
        purged_masks[capture.name] = purged
        usable = capture.kept & ~purged
        report["captures"][capture.name] = {
            "sha256": capture.sha256, "records": int(len(capture.kept)), "represented": int(capture.kept.sum()),
            "excluded_unrepresentable": capture.excluded, "purged_near_partition_boundary": int(purged.sum()),
            "reordered_within_tolerance": int(capture.reordered), "isolated_beyond_tolerance": int(capture.isolated),
            "block_partitions": sorted(set(assignment.tolist())),
            "rows_by_partition": {p: {str(k): int(v) for k, v in Counter(capture.labels[usable & (assignment == p)]).items()}
                                  for p in PARTITIONS}}
        for p in PARTITIONS:
            mask = usable & (assignment == p)
            if p != "test":
                fitting_vectors.append(capture.flow[mask])
            for label in sorted(set(capture.labels[mask])):
                if p == "train":
                    available_train[label] += int((mask & (capture.labels == label)).sum())
                if p != "test" and label in withheld_classes:
                    continue
                indices = np.flatnonzero(mask & (capture.labels == label))
                if caps[p] and len(indices) > caps[p]:
                    indices = np.sort(rng.choice(indices, caps[p], replace=False))
                selected[p].append((ci, label, indices))
    trained = Counter()
    for ci, label, indices in selected["train"]:
        trained[label] += len(indices)
    rare = sorted(label for label in set(available_train) | {l for _, l, _ in selected["test"]}
                  if trained[label] < min_train_rows and label not in withheld_classes)
    report["excluded_rare_classes"] = {label: int(available_train[label]) for label in rare}
    if "normal" in rare or trained["normal"] == 0:
        raise ValueError("The corpus needs benign training traffic")

    # Feature construction happens only after eligibility and partition ownership are known.
    isolated = []
    for capture in captures:
        assignment = assign(capture, protocol, held_out)
        usable = capture.kept & ~purged_masks[capture.name] & ~np.isin(capture.labels, rare)
        usable &= (assignment == "test") | ~np.isin(capture.labels, list(withheld_classes))
        isolated.append(_isolated_capture(capture, assignment, usable, protocol, seed, decision_rows_per_label))
    captures = isolated

    def matrix(p):
        chosen = [(captures[ci], label, idx) for ci, label, idx in selected[p] if label not in rare]
        if not chosen:
            raise ValueError(f"Partition {p} is empty")
        return MatrixSet(np.vstack([c.flow[i] for c, _, i in chosen]), np.vstack([c.behavior[i] for c, _, i in chosen]),
                         np.concatenate([np.full(len(i), l, dtype=object) for _, l, i in chosen]).astype(str),
                         np.concatenate([c.history[i] for c, _, i in chosen]),
                         np.concatenate([np.full(len(i), c.name, dtype=object) for c, _, i in chosen]).astype(str), [], [])

    parts = {p: matrix(p) for p in PARTITIONS}
    for p in ("train", "calibration", "fusion", "tuning"):
        if len(np.unique(parts[p].binary)) < 2:
            raise ValueError(f"{protocol}: the {p} partition lacks benign or attack rows, so calibration/fusion cannot be fitted honestly")
    seen = set(_rows_view(np.vstack(fitting_vectors)).tolist())
    unseen = np.fromiter((row not in seen for row in _rows_view(parts["test"].flow).tolist()), dtype=bool, count=len(parts["test"].labels))

    # Event identity must be unique across every represented row of every capture.
    keys = np.concatenate([c.event_key[c.kept] for c in captures])
    duplicates = int(len(keys) - len(np.unique(keys)))
    if duplicates:
        raise ValueError(f"{duplicates} duplicate event identities across the corpus")
    flows, contexts, labels, rows = [], [], [], []
    for label in sorted({l for c in captures for (proto, l) in c.samples if proto == protocol} - set(rare)):
        pool = [(capture, index, flow, context) for capture in captures
                for index, flow, context in capture.samples.get((protocol, label), [])
                if not purged_masks[capture.name][index]]
        if len(pool) > decision_rows_per_label:
            pool = [pool[i] for i in np.sort(rng.choice(len(pool), decision_rows_per_label, replace=False))]
        for capture, index, flow, context in pool:
            flows.append(flow)
            contexts.append(context)
            labels.append(label)
            rows.append((capture, index))
    sample = MatrixSet(np.vstack([c.flow[i] for c, i in rows]), np.vstack([c.behavior[i] for c, i in rows]),
                       np.asarray(labels, dtype=str), np.asarray([c.history[i] for c, i in rows]),
                       np.asarray([c.name for c, _ in rows], dtype=str), flows, contexts)
    report.update({
        "partitions": {p: {"rows": int(len(parts[p].labels)),
                           "class_counts": {str(k): int(v) for k, v in Counter(parts[p].labels.tolist()).items()},
                           "captures": sorted(set(parts[p].episode_ids.tolist()))} for p in PARTITIONS},
        "test_rows_with_flow_vector_seen_in_fitting_partitions": int((~unseen).sum()),
        "test_rows_unseen": int(unseen.sum()),
        "event_identity_unique": True,
        "decision_sample": {"rows": len(labels), "class_counts": dict(Counter(labels)), "max_rows_per_label": decision_rows_per_label},
        "checks": ["documented label mapping only", "unrepresentable records excluded and counted",
                   "arrival-order blocks per capture" if protocol == "temporal_blocks" else "whole captures held out",
                   "boundary purge in event time", "partition-local behavior rebuilt after exclusions", "unique event identity", "withheld classes absent from all fitting partitions",
                   "duplicate flow vectors reported; test also scored on unseen vectors"],
        "passed": True})
    for p in ("train", "calibration", "fusion", "tuning"):
        if withheld_classes & set(parts[p].labels.tolist()):
            raise AssertionError(f"Withheld class leaked into {p}")
    # Temporally concentrated classes can miss a validation partition entirely; report, never hide.
    trained_classes = set(parts["train"].labels.tolist())
    report["coverage_gaps"] = {p: sorted(trained_classes - set(parts[p].labels.tolist()) - {"normal"})
                               for p in ("calibration", "fusion", "tuning")}
    report["context_isolation"] = {
        "version": 2,
        "method": "rebuild eligible records with fresh state per contiguous partition run",
        "test_captures_disjoint_from_fitting": protocol == "leave_capture_out",
        "all_fitting_partitions_have_independent_context": True,
        "test_context_independent_from_fitting": True,
        "purged_records_excluded_from_context": True,
        "withheld_classes_excluded_from_fitting_context": True,
        "behavior_window_seconds": 300,
        "purge_seconds": gap_seconds,
        "limitation": "Temporal blocks still share capture environments and hosts, and are interleaved rather than forward-only. State resets introduce cold starts. Context isolation does not prove cross-network generalization or eliminate repeated flow vectors.",
    }
    return CorpusSplit(parts, unseen, sample, report)
