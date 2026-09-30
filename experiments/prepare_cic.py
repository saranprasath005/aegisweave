"""Stage one CIC capture CSV with explicit counter exclusions and provenance.

No training, split shuffling, label inference, or synthetic temporal context.
One output directory per input capture keeps acquisition and partition decisions separate.
"""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import json
from pathlib import Path

import numpy as np
import pandas as pd

from aegisweave.corpus import file_sha256
from aegisweave.datasets import CIC_SOURCE, normalize_cic_columns

COLUMNS = ["Flow Duration", "Total Fwd Packets", "Total Length of Fwd Packets",
           "Total Backward Packets", "Total Length of Bwd Packets"]


def prepare(source, output, *, capture_id, download_url, encoding="utf-8-sig", chunksize=50000, attempted_policy="refuse"):
    source, output = Path(source).resolve(), Path(output).resolve()
    if not capture_id.strip() or not download_url.startswith(("https://", "http://")):
        raise ValueError("Provide an explicit capture ID and acquisition URL")
    if chunksize < 1:
        raise ValueError("chunksize must be positive")
    if attempted_policy not in {"refuse", "benign", "exclude"}:
        raise ValueError("Unknown attempted-flow policy")
    source_hash = file_sha256(source)
    output.mkdir(parents=True, exist_ok=False)
    partial = output / "capture.csv.partial"
    reasons, all_labels, retained_labels = Counter(), Counter(), Counter()
    rows = retained = attempted_rows = mapped_benign = 0
    with partial.open("w", encoding="utf-8", newline="") as destination, (output / "excluded.jsonl").open("w", encoding="utf-8") as rejected:
        wrote_header = False
        for chunk in pd.read_csv(source, encoding=encoding, chunksize=chunksize, dtype=str, keep_default_na=False):
            chunk = normalize_cic_columns(chunk)
            missing = set(COLUMNS) - set(chunk.columns)
            if missing:
                raise ValueError(f"Missing required columns: {sorted(missing)}")
            numeric = chunk[COLUMNS].apply(pd.to_numeric, errors="coerce").to_numpy(dtype=float)
            labels = chunk.Label.str.strip()
            all_labels.update(labels.tolist())
            attempted = np.zeros(len(chunk), dtype=bool)
            if "Attempted Category" in chunk:
                categories = pd.to_numeric(chunk["Attempted Category"], errors="raise").to_numpy(dtype=float)
                if not np.isfinite(categories).all() or (categories < -1).any() or (categories != np.floor(categories)).any():
                    raise ValueError("Invalid Attempted Category values")
                attempted = categories != -1
            elif labels.str.contains("Attempted", case=False, regex=False).any():
                raise ValueError("Attempted labels require the documented Attempted Category column")
            attempted_rows += int(attempted.sum())
            if attempted.any() and attempted_policy == "refuse":
                raise ValueError("Choose an explicit attempted-flow policy for the corrected dataset")
            if attempted_policy == "benign":
                labels = labels.mask(attempted, "BENIGN")
            finite = np.isfinite(numeric).all(axis=1)
            with np.errstate(invalid="ignore"):
                reason_masks = {
                    "missing_or_nonfinite_counter": ~finite,
                    "negative_counter": (numeric < 0).any(axis=1),
                    "fractional_packet_or_byte_counter": finite & (numeric[:, 1:] != np.floor(numeric[:, 1:])).any(axis=1),
                    "zero_total_packets": finite & ((numeric[:, 1] + numeric[:, 3]) == 0),
                    "missing_label": labels.str.lower().isin(["", "nan", "null", "none"]).to_numpy(),
                    "attempted_flow_excluded_by_policy": attempted & (attempted_policy == "exclude"),
                }
            invalid = np.logical_or.reduce(list(reason_masks.values()))
            for i in np.flatnonzero(invalid):
                why = [reason for reason, mask in reason_masks.items() if mask[i]]
                reasons.update(why)
                rejected.write(json.dumps({"record_index": rows + int(i), "label": labels.iloc[i], "reasons": why}) + "\n")
            good = pd.DataFrame(numeric[~invalid], columns=COLUMNS)
            good["Label"] = labels.to_numpy()[~invalid]
            good.to_csv(destination, index=False, header=not wrote_header)
            wrote_header = True
            retained_labels.update(good.Label.tolist())
            if attempted_policy == "benign":
                mapped_benign += int((attempted & ~invalid).sum())
            retained += len(good)
            rows += len(chunk)
    if not retained:
        raise ValueError("No valid rows remain; incomplete staging directory retained for inspection")
    if file_sha256(source) != source_hash:
        raise ValueError("Input changed during staging; no completed manifest published")
    prepared = output / "capture.csv"
    partial.rename(prepared)
    report = {"schema": "aegisweave.cic-staging.v1", "created_at": datetime.now(timezone.utc).isoformat(),
              "capture_id": capture_id, "source_file": source.name, "source_sha256": source_hash,
              "source_encoding": encoding, "dataset_description": CIC_SOURCE, "download_url": download_url,
              "source_authenticity": "Acquisition URL and local hashes recorded; not independently authenticated by dataset authors",
              "rows_read": rows, "rows_retained": retained, "rows_excluded": rows - retained,
              "exclusion_reason_counts": dict(reasons), "reason_counts_may_overlap": True,
              "all_label_counts": dict(all_labels), "retained_label_counts": dict(retained_labels),
              "attempted_flow_policy": attempted_policy, "attempted_rows": attempted_rows,
              "attempted_retained_as_benign": mapped_benign,
              "attempted_policy_source": "https://intrusion-detection.distrinet-research.be/CNS2022/Dataset_Download.html",
              "output_file": "capture.csv", "output_sha256": file_sha256(prepared),
              "duration_unit": "microseconds (unchanged)", "features": COLUMNS,
              "labels_reviewed": False, "split_assigned": False, "temporal_context_available": False,
              "ready_for_live_model": False,
              "limitations": ["Only required numeric counters are validated; unused CIC features are omitted",
                              "No packet-length equivalence with Zeek payload counters is asserted",
                              "Capture identity is caller-supplied and requires provenance review",
                              "Labels are preserved except for the explicitly selected attempted-flow policy",
                              "Exact feature overlap must be audited after partition assignment",
                              "Malformed CSV structure fails staging instead of silently dropping rows"]}
    (output / "manifest.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--capture-id", required=True)
    parser.add_argument("--download-url", required=True)
    parser.add_argument("--encoding", default="utf-8-sig")
    parser.add_argument("--attempted-policy", choices=["refuse", "benign", "exclude"], default="refuse")
    args = parser.parse_args()
    print(json.dumps(prepare(args.source, args.output, capture_id=args.capture_id,
                             download_url=args.download_url, encoding=args.encoding, attempted_policy=args.attempted_policy), indent=2))


if __name__ == "__main__":
    main()
