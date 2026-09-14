"""Synthetic telemetry only: no packets, commands, remote probes, or live attacks."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from uuid import NAMESPACE_URL, uuid4, uuid5
import numpy as np

from .schema import Flow

CLASSES = ("normal", "scan", "brute_force", "dos", "exfiltration")


@dataclass
class Episode:
    episode_id: str
    flows: list[Flow]
    labels: list[str]


def generate_episodes(count=80, seed=42, start=None, unknown=False, shift=False) -> list[Episode]:
    rng = np.random.default_rng(seed)
    start = start or datetime(2026, 1, 1, tzinfo=timezone.utc)
    episodes = []
    for e in range(count):
        # Episode labels are held outside telemetry. The entire independent host
        # episode belongs to one split, including its benign warm-up.
        kind = "unknown_beacon" if unknown and e % 2 else str(rng.choice(CLASSES, p=[.38, .17, .15, .16, .14]))
        length = int(rng.integers(22, 44))
        source = f"10.{1 + seed % 220}.{e // 250}.{1 + e % 250}"
        target = f"172.20.{int(rng.integers(1, 20))}.{int(rng.integers(1, 240))}"
        service = int(rng.choice([22, 53, 80, 443, 445, 3389, 8080]))
        at = start + timedelta(seconds=e * 900)
        rows, labels = [], []
        for i in range(length):
            label = "normal" if i < 4 else kind
            duration = float(rng.lognormal(-.4, 1.15))
            packets = int(rng.integers(3, 32))
            mean_size = float(rng.lognormal(5.6, .55))
            nbytes = int(packets * mean_size)
            rp = int(packets * rng.uniform(.4, 1.4))
            rb = int(nbytes * rng.uniform(.6, 3.5))
            failed = bool(rng.random() < .07)
            syn = float(rng.beta(1, 10))
            interval = float(rng.uniform(1.8, 8.5))
            destination = target if rng.random() < .8 else f"172.20.25.{int(rng.integers(1, 50))}"
            port = service if rng.random() < .9 else int(rng.choice([53, 80, 443]))
            protocol = str(rng.choice(["TCP", "UDP"], p=[.85, .15]))
            # Some episodes deliberately overlap in per-flow observations;
            # their causal rate/destination context provides extra evidence.
            subtle = (e % 3 == 0)
            if label == "scan":
                destination = f"172.21.{int(rng.integers(1, 8))}.{int(rng.integers(1, 240))}"
                port = int(rng.integers(1, 60000))
                interval = float(rng.uniform(.1, .9))
                failed = bool(rng.random() < .55)
                if not subtle:
                    duration, packets, nbytes, rp, rb = float(rng.uniform(.01, .4)), int(rng.integers(1, 5)), int(rng.integers(40, 350)), 0, 0
                    syn = float(rng.uniform(.5, 1.))
            elif label == "brute_force":
                port, interval = int(rng.choice([22, 3389, 443])), float(rng.uniform(.25, 1.3))
                failed = bool(rng.random() < .8)
                if not subtle:
                    duration, packets, nbytes, rp, rb = float(rng.uniform(.1, 1.5)), int(rng.integers(3, 18)), int(rng.integers(100, 2500)), int(rng.integers(1, 5)), int(rng.integers(50, 800))
            elif label == "dos":
                interval = float(rng.uniform(.015, .15))
                if not subtle:
                    duration, packets = float(rng.uniform(.01, .18)), int(rng.integers(300, 4000))
                    nbytes, rp, rb = packets * int(rng.integers(40, 200)), int(rng.integers(0, 5)), int(rng.integers(0, 500))
                    syn = float(rng.uniform(.5, 1.))
            elif label == "exfiltration":
                destination, port = "198.51.100.42", int(rng.choice([443, 8080, 8443]))
                interval = float(rng.uniform(.5, 3.))
                if not subtle:
                    duration, packets = float(rng.uniform(2, 25)), int(rng.integers(800, 6500))
                    nbytes, rp, rb = packets * int(rng.integers(700, 1400)), int(rng.integers(5, 30)), int(rng.integers(500, 5000))
            elif label == "unknown_beacon":
                protocol, port = "UDP", 5353
                duration, packets, nbytes, rp, rb = float(rng.uniform(35, 120)), int(rng.integers(1, 4)), int(rng.integers(15000, 50000)), 0, 0
                interval, failed = 4., False
                destination = f"203.0.113.{20 + i % 9}"
            # Benign bursts/backups avoid a wholly trivial normal distribution.
            if label == "normal" and e % 7 == 0:
                packets *= 25
                nbytes *= 40
                rp *= 25
                rb *= 40
                interval = float(rng.uniform(.1, 1.))
            if shift:
                duration *= 2.5
                nbytes = int(nbytes * 1.8)
                rb = int(rb * 1.8)
            at += timedelta(seconds=interval)
            rows.append(Flow(event_id=str(uuid5(NAMESPACE_URL, f"aegisweave/{seed}/{e}/{i}/{unknown}/{shift}")),
                             timestamp=at, source=source, destination=destination, source_port=int(rng.integers(1024, 65535)),
                             destination_port=port, protocol=protocol, duration=duration, packets=packets, bytes=nbytes,
                             reverse_packets=rp, reverse_bytes=rb, failed=failed, syn_ratio=syn,
                             sensor_id="synthetic", simulated=True))
            labels.append(label)
        episodes.append(Episode(f"synthetic-{seed}-{e}", rows, labels))
    return episodes


def generate_demo(count=120, seed=42, start=None) -> list[Flow]:
    if not 1 <= count <= 5000:
        raise ValueError("Demo count must be between 1 and 5000")
    end = start or datetime.now(timezone.utc)
    episodes = generate_episodes(count // 22 + 2, seed, unknown=True)
    rows = []
    # Align independent episode ends, then replay chronologically. A replay is a
    # new observation set even when its scenario seed is repeated.
    replay_sensor = f"demo-{uuid4().hex[:12]}"
    for episode in episodes:
        offset = end - episode.flows[-1].timestamp
        for flow in episode.flows:
            rows.append(flow.model_copy(update={"timestamp": flow.timestamp + offset,
                                                "event_id": str(uuid4()), "sensor_id": replay_sensor}))
            if len(rows) == count:
                return sorted(rows, key=lambda f: f.timestamp)
    return sorted(rows, key=lambda f: f.timestamp)
