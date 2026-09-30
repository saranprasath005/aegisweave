import json

import numpy as np
import pandas as pd
import pytest

from aegisweave.datasets import load_cic
from experiments.prepare_cic import COLUMNS, prepare


def test_staging_accounts_for_exclusions_and_preserves_units(tmp_path):
    source = tmp_path / "capture.csv"
    data = [[1000000, 5, 300, 3, 600, "BENIGN"],
            [2000000, 6, 400, 4, 800, "PortScan"],
            [-1, 1, 1, 1, 1, "BENIGN"],
            [1, 1.5, 1, 1, 1, "BENIGN"],
            [1, 0, 0, 0, 0, "BENIGN"],
            [1, 1, 1, 1, "Infinity", "BENIGN"],
            [1, 1, 1, 1, 1, ""]]
    pd.DataFrame(data, columns=COLUMNS + ["Label"]).to_csv(source, index=False)
    original = source.read_bytes()
    report = prepare(source, tmp_path / "staged", capture_id="fixture-day", download_url="https://example.org/fixture", chunksize=2)
    assert report["rows_read"] == 7 and report["rows_retained"] == 2 and report["rows_excluded"] == 5
    assert report["ready_for_live_model"] is False and report["labels_reviewed"] is False
    exclusions = [json.loads(line) for line in (tmp_path / "staged/excluded.jsonl").read_text().splitlines()]
    assert [r["record_index"] for r in exclusions] == [2, 3, 4, 5, 6]
    prepared = load_cic(tmp_path / "staged/capture.csv")
    np.testing.assert_allclose(prepared.x[:, 0], np.log1p([1, 2]))
    assert prepared.labels.tolist() == ["normal", "portscan"]
    assert source.read_bytes() == original
    with pytest.raises(FileExistsError):
        prepare(source, tmp_path / "staged", capture_id="fixture-day", download_url="https://example.org/fixture")


def test_ambiguous_headers_fail_without_complete_manifest(tmp_path):
    source = tmp_path / "bad.csv"
    pd.DataFrame([[1, 1, 1, 1, 1, "BENIGN", 2]], columns=COLUMNS + ["Label", "Tot Fwd Pkts"]).to_csv(source, index=False)
    with pytest.raises(ValueError, match="Ambiguous"):
        prepare(source, tmp_path / "staged", capture_id="fixture", download_url="https://example.org/fixture")
    assert not (tmp_path / "staged/manifest.json").exists()


def test_corrected_attempted_flows_need_explicit_policy(tmp_path):
    source = tmp_path / "corrected.csv"
    pd.DataFrame([[1, 1, 1, 1, 1, "BENIGN", -1], [1, 2, 2, 1, 1, "DoS - Attempted", 2]],
                 columns=COLUMNS + ["Label", "Attempted Category"]).to_csv(source, index=False)
    kwargs = {"capture_id": "fixture", "download_url": "https://example.org/fixture"}
    with pytest.raises(ValueError, match="explicit"):
        prepare(source, tmp_path / "refused", **kwargs)
    report = prepare(source, tmp_path / "benign", attempted_policy="benign", **kwargs)
    assert report["attempted_retained_as_benign"] == 1
    assert load_cic(tmp_path / "benign/capture.csv").labels.tolist() == ["normal", "normal"]
    report = prepare(source, tmp_path / "excluded", attempted_policy="exclude", **kwargs)
    assert report["rows_retained"] == 1
    assert report["exclusion_reason_counts"]["attempted_flow_excluded_by_policy"] == 1
