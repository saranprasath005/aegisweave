import numpy as np
import pytest

from aegisweave.datasets import BenchmarkData, feature_hashes
from experiments import cic_baseline


def test_threshold_handles_ties_and_saturated_scores():
    values = np.r_[np.zeros(900), np.ones(100)]
    threshold = cic_baseline.benign_threshold(values)
    assert threshold > 1
    assert (values >= threshold).mean() <= .01
    with pytest.raises(ValueError):
        cic_baseline.benign_threshold([np.nan])


def test_test_capture_changes_cannot_change_fitted_thresholds(tmp_path, monkeypatch):
    rng = np.random.default_rng(5)
    data = {}
    for day in (*cic_baseline.FIT_DAYS, cic_baseline.CALIBRATION_DAY, *cic_baseline.TEST_DAYS):
        x = rng.uniform(0, 2, (300, 10))
        labels = np.array(["normal"] * 200 + ["attack"] * 100)
        x[200:] += 2
        data[day] = BenchmarkData(x, labels, feature_hashes(x), {})
    monkeypatch.setattr(cic_baseline, "load_staged", lambda root, day: (data[day], {"fixture": True}))
    first = cic_baseline.run(tmp_path, tmp_path / "first.json", cap_per_class=200)
    for day in cic_baseline.TEST_DAYS:
        part = data[day]
        part.x[:] = 100
        part.labels[:] = "normal"
        part.hashes = feature_hashes(part.x)
    second = cic_baseline.run(tmp_path, tmp_path / "second.json", cap_per_class=200)
    assert first["thresholds"] == second["thresholds"]
    assert first["protocol"]["calibration_benign_unseen_rows"] == second["protocol"]["calibration_benign_unseen_rows"]
    assert first["deployable_artifact"] is False
