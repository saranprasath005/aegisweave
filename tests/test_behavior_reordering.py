"""Event-time host context under sensor reordering (Zeek emits connections when they end)."""
from datetime import datetime, timedelta, timezone

import numpy as np
import pytest

from aegisweave.behavior import BehaviorEngine
from aegisweave.demo import generate_demo
from aegisweave.features import behavior_features
from aegisweave.schema import Flow

START = datetime(2026, 2, 1, tzinfo=timezone.utc)


def flow(seconds, destination="10.9.0.2", port=443, source="10.9.0.1"):
    return Flow(timestamp=START + timedelta(seconds=seconds), source=source, destination=destination,
                destination_port=port, protocol="TCP", duration=.2, packets=3, bytes=200, sensor_id="zeek-a")


def test_in_order_streams_are_identical_for_any_tolerance():
    strict, tolerant = BehaviorEngine(max_lateness=0), BehaviorEngine(max_lateness=300)
    for item in generate_demo(count=400, seed=9):
        a, b = strict.observe(item), tolerant.observe(item)
        assert np.array_equal(behavior_features(a), behavior_features(b))
        assert (a["history_count"], a["available"]) == (b["history_count"], b["available"])


def test_reordered_flow_sees_only_earlier_starting_flows_and_joins_history():
    engine = BehaviorEngine()
    for second in (0, 5, 20):
        engine.observe(flow(second, destination=f"10.9.1.{second}"))
    reordered = engine.observe(flow(10, destination="10.9.2.1"))
    assert reordered["reordered"] and not reordered["late_event"]
    assert reordered["history_count"] == 2 and reordered["available"]  # flows at 0 s and 5 s, not 20 s
    after = engine.observe(flow(25, destination="10.9.3.1"))
    assert after["history_count"] == 4 and after["connections_30s"] == 5
    host = engine.snapshot()[0]
    assert host["timestamp"] == after["timestamp"]  # a reordered flow never replaces the newest snapshot


def test_flows_beyond_tolerance_are_isolated_and_do_not_alter_history():
    engine = BehaviorEngine(max_lateness=60)
    engine.observe(flow(1000))
    engine.observe(flow(1001))
    isolated = engine.observe(flow(900))
    assert isolated["late_event"] and not isolated["available"] and isolated["history_count"] == 0
    assert engine.observe(flow(1002))["history_count"] == 2


def test_capacity_is_respected_when_inserting_reordered_flows():
    engine = BehaviorEngine(max_events_per_host=4)
    for second in range(10):
        engine.observe(flow(second * 2))
    history = lambda: [o.at - START.timestamp() for o in engine._hosts[("zeek-a", False, "10.9.0.1")]]
    assert history() == [12, 14, 16, 18]
    assert engine.observe(flow(5))["reordered"]
    assert history() == [12, 14, 16, 18]  # older than all retained events: displaces nothing
    engine.observe(flow(15))
    assert history() == [14, 15, 16, 18]  # oldest evicted, order preserved


def test_tolerance_is_bounded():
    with pytest.raises(ValueError):
        BehaviorEngine(max_lateness=-1)
    with pytest.raises(ValueError):
        BehaviorEngine(max_lateness=86400)
