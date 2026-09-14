from datetime import datetime, timezone

from aegisweave.detection import DriftRegistry
from aegisweave.schema import Flow


def flow(sensor="sensor-a", simulated=False, nbytes=400):
    return Flow(timestamp=datetime.now(timezone.utc), source="10.0.0.1", destination="10.0.0.2",
                protocol="TCP", duration=1, packets=5, bytes=nbytes, sensor_id=sensor, simulated=simulated)


EVIDENCE = {"prediction": {"confidence": .8, "class": "normal"}, "anomaly": {"score": .1}, "fusion": {"decision": "normal"}}


def test_demo_cannot_contaminate_real_drift_reference_or_monitor():
    monitor = DriftRegistry(window_size=5)
    for _ in range(5):
        monitor.observe(flow(), EVIDENCE)
    for _ in range(15):
        monitor.observe(flow(simulated=True, nbytes=10000000), EVIDENCE)
    view = monitor.snapshot()
    assert view["scope"] == {"sensor_id": "sensor-a", "simulated": False}
    assert view["reference_count"] == 5 and view["current_count"] == 0
    assert view["status"] == "warming_up" and view["monitored_streams"] == 2
    for _ in range(5):
        monitor.observe(flow(), EVIDENCE)
    assert monitor.snapshot()["status"] == "stable"


def test_sensors_have_separate_windows_and_eviction_is_bounded():
    monitor = DriftRegistry(window_size=3, max_streams=2)
    for _ in range(6):
        monitor.observe(flow("one"), EVIDENCE)
    monitor.observe(flow("two", nbytes=1000000), EVIDENCE)
    assert monitor.snapshot()["current_count"] == 0
    assert monitor.snapshot()["reference_count"] == 1
    monitor.observe(flow("three"), EVIDENCE)
    assert monitor.snapshot()["monitored_streams"] == 2
    assert {s["sensor_id"] for s in monitor.snapshot()["streams"]} == {"two", "three"}


def test_unobserved_and_demo_only_status_is_explicit():
    monitor = DriftRegistry(window_size=3)
    assert monitor.snapshot()["scope"] is None
    monitor.observe(flow(simulated=True), EVIDENCE)
    assert monitor.snapshot()["scope"]["simulated"] is True
    assert "simulated" in monitor.snapshot()["message"]
