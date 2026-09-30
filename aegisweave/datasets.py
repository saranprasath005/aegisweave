"""Strict public-dataset adapters to the shared, reduced numeric flow schema.

No fabricated addresses, time order, failures, SYN ratios, or temporal context.
These adapters are for offline benchmark research, not live Flow construction.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import hashlib
import numpy as np
import pandas as pd

from .features import COMMON_FEATURES

UNSW_SOURCE = "https://research.unsw.edu.au/projects/unsw-nb15-dataset"
CIC_SOURCE = "https://www.unb.ca/cic/datasets/ids-2017.html"
UNSW_MIRROR = "https://github.com/Nir-J/ML-Projects/tree/master/UNSW-Network_Packet_Classification"


@dataclass
class BenchmarkData:
    x: np.ndarray
    labels: np.ndarray
    hashes: np.ndarray
    provenance: dict

    @property
    def binary(self):
        return (self.labels != "normal").astype(int)


def _numeric(frame: pd.DataFrame, columns: list[str]) -> np.ndarray:
    missing = set(columns) - set(frame.columns)
    if missing:
        raise ValueError(f"Missing required dataset columns: {sorted(missing)}")
    values = frame[columns].apply(pd.to_numeric, errors="raise").to_numpy(dtype=float, copy=True)
    if not np.isfinite(values).all() or (values < 0).any():
        raise ValueError("Dataset contains missing, non-finite, or negative required counters; clean explicitly and record exclusions")
    if not np.equal(values[:, 1:], np.floor(values[:, 1:])).all():
        raise ValueError("Packet/byte counters must be integer-valued")
    return values


def _matrix(values: np.ndarray):
    duration, packets, nbytes, reverse_packets, reverse_bytes = values.T
    total_p, total_b = packets + reverse_packets, nbytes + reverse_bytes
    floor = np.maximum(duration, .001)
    return np.column_stack([np.log1p(values), np.log1p(total_p / floor), np.log1p(total_b / floor),
                            np.log1p(total_b / np.maximum(total_p, 1)),
                            reverse_packets / np.maximum(total_p, 1), reverse_bytes / np.maximum(total_b, 1)])


def feature_hashes(x):
    # Hex SHA256 stable for exact model-input equality, excluding all labels/IDs.
    return np.asarray([hashlib.sha256(np.asarray(row, dtype="<f8").tobytes()).hexdigest() for row in x])


def _result(path, x, labels, name, source, rows, extras=None):
    hashes = feature_hashes(x)
    provenance = {"name": name, "source": source, "file": str(Path(path).name),
                  "sha256": hashlib.sha256(Path(path).read_bytes()).hexdigest(), "rows": rows,
                  "feature_schema": "aegisweave.common.v1", "features": list(COMMON_FEATURES),
                  "within_file_duplicate_feature_rows": int(rows - len(np.unique(hashes))),
                  "temporal_available": False,
                  "unavailable": ["validated host identity and ordered event chronology", "SYN packet ratio", "connection failure semantics"],
                  "notes": "Reduced common counters only; no dataset-specific ct_* features, labels, IDs, ports, IPs or timestamps are classifier inputs."}
    if extras:
        provenance.update(extras)
    return BenchmarkData(x, labels, hashes, provenance)


def load_unsw(path: str | Path) -> BenchmarkData:
    frame = pd.read_csv(path)
    frame.columns = frame.columns.str.strip()
    if not {"attack_cat", "label"}.issubset(frame.columns):
        raise ValueError("UNSW designated train/test CSV must include attack_cat and label")
    values = _numeric(frame, ["dur", "spkts", "sbytes", "dpkts", "dbytes"])
    labels = frame.attack_cat.astype(str).str.strip().str.lower().to_numpy()
    binary = pd.to_numeric(frame.label, errors="raise").to_numpy()
    if not np.isin(binary, [0, 1]).all() or not np.array_equal((labels != "normal").astype(int), binary):
        raise ValueError("UNSW category and binary labels disagree")
    return _result(path, _matrix(values), labels, "UNSW-NB15", UNSW_SOURCE, len(frame),
                   {"duration_unit": "seconds", "split_policy": "Preserve supplied designated training and testing files"})


def normalize_cic_columns(frame):
    """Normalize known header variants without changing measurement semantics."""
    frame = frame.copy()
    frame.columns = frame.columns.str.strip()
    aliases = {"Total Fwd Packets": "Total Fwd Packets", "Tot Fwd Pkts": "Total Fwd Packets",
               "Total Fwd Packet": "Total Fwd Packets", "Total Bwd packets": "Total Backward Packets",
               "Total Length of Fwd Packet": "Total Length of Fwd Packets", "Total Length of Bwd Packet": "Total Length of Bwd Packets",
               "Total Backward Packets": "Total Backward Packets", "Tot Bwd Pkts": "Total Backward Packets",
               "Total Length of Fwd Packets": "Total Length of Fwd Packets", "TotLen Fwd Pkts": "Total Length of Fwd Packets",
               "Total Length of Bwd Packets": "Total Length of Bwd Packets", "TotLen Bwd Pkts": "Total Length of Bwd Packets",
               "Flow Duration": "Flow Duration", "Flow Duration (us)": "Flow Duration"}
    frame = frame.rename(columns=aliases)
    if frame.columns.duplicated().any():
        raise ValueError("Ambiguous duplicate normalized CIC columns")
    if "Label" not in frame:
        raise ValueError("CIC CSV must include Label")
    return frame


def load_cic(path: str | Path) -> BenchmarkData:
    frame = normalize_cic_columns(pd.read_csv(path, encoding="utf-8-sig"))
    values = _numeric(frame, ["Flow Duration", "Total Fwd Packets", "Total Length of Fwd Packets",
                              "Total Backward Packets", "Total Length of Bwd Packets"])
    values[:, 0] /= 1_000_000  # CICFlowMeter microseconds -> canonical seconds.
    labels = frame.Label.astype(str).str.strip().str.lower().replace({"benign": "normal"}).to_numpy()
    if np.isin(labels, ["", "nan"]).any():
        raise ValueError("Empty CIC label")
    return _result(path, _matrix(values), labels, "CIC-IDS2017/2018 counters", CIC_SOURCE, len(frame),
                   {"duration_unit": "microseconds converted to seconds", "split_policy": "Caller must keep capture days separate; this adapter never shuffles or invents chronology"})
