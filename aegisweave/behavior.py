"""Bounded, causal host context; inference never updates a learned baseline."""
from __future__ import annotations

from bisect import bisect_right
from collections import Counter, OrderedDict, deque
from dataclasses import dataclass
import math
import numpy as np


@dataclass(frozen=True)
class Observation:
    at: float
    destination: str
    port: int
    protocol: str
    failed: bool
    nbytes: int
    packet_rate: float
    missing: tuple[str, ...] = ()


def _entropy(values) -> float:
    counts = Counter(values)
    total = sum(counts.values())
    return -sum((n / total) * math.log2(n / total) for n in counts.values()) if total else 0.


class BehaviorEngine:
    """Per-host event-time windows over (sensor, simulation) streams.

    Flow sensors such as Zeek emit a connection when it ENDS but stamp it with its
    START, so arrival order is not event order (6-55% of IoT-23 flows). Flows up to
    `max_lateness` seconds behind the stream watermark are placed in event-time order
    and see only earlier-starting flows; older flows are isolated and cannot alter
    history. The 300 s default is Zeek's TCP inactivity timeout. Streams that arrive
    in order produce the same context for any tolerance unless a host reaches the
    per-host event cap, where retained older history can displace window events.
    Training corpora and live serving use the same engine and settings.
    """

    def __init__(self, windows=(5, 30, 60, 300), max_hosts=2048, max_events_per_host=256, max_lateness=300.0):
        if tuple(sorted(windows)) != tuple(windows) or any(w <= 0 for w in windows):
            raise ValueError("Windows must be positive and increasing")
        if not {5, 30, 60, 300}.issubset(windows):
            raise ValueError("The v1 model requires 5, 30, 60 and 300 second windows")
        if max_hosts < 1 or max_events_per_host < 2:
            raise ValueError("History limits must be positive")
        if not 0 <= max_lateness <= 3600:
            raise ValueError("Reordering tolerance must be between 0 and 3600 seconds")
        self.windows = tuple(windows)
        self.max_hosts = max_hosts
        self.max_events_per_host = max_events_per_host
        self.max_lateness = float(max_lateness)
        self._hosts: OrderedDict[tuple, deque] = OrderedDict()
        self._snapshots: dict[tuple, dict] = {}
        self._watermarks: OrderedDict[tuple, float] = OrderedDict()

    def reset(self):
        self._hosts.clear()
        self._snapshots.clear()
        self._watermarks.clear()

    def observe(self, flow) -> dict:
        now = flow.timestamp.timestamp()
        stream = (flow.sensor_id, flow.simulated)
        key = (flow.sensor_id, flow.simulated, str(flow.source))
        span = self.windows[-1]
        watermark = self._watermarks.get(stream, float("-inf"))
        # Input beyond the reordering tolerance is not compared with later observations
        # and cannot alter trusted history. It still receives an isolated flow prediction.
        late = now < watermark - self.max_lateness
        reordered = not late and now < watermark
        if now >= watermark:
            watermark = now
            self._watermarks[stream] = now
            self._watermarks.move_to_end(stream)
            while len(self._watermarks) > self.max_hosts:
                self._watermarks.popitem(last=False)
            stale = [k for k, h in self._hosts.items() if k[:2] == stream and (not h or h[-1].at < now - span - self.max_lateness)]
            for k in stale:
                self._hosts.pop(k, None)
                self._snapshots.pop(k, None)
        history = self._hosts.get(key, deque(maxlen=self.max_events_per_host)) if not late else deque()
        while history and history[0].at < watermark - span - self.max_lateness:
            history.popleft()
        # Event-time prior context: flows that started no later than this one.
        prior = [o for o in history if now - span <= o.at <= now]
        prior_count = len(prior)
        # The cap has cut into this flow's own window when the oldest retained event is inside it.
        truncated = len(history) >= self.max_events_per_host and history[0].at > now - span
        previous_edges = Counter((o.destination, o.port, o.protocol) for o in prior)
        edge = (str(flow.destination), flow.destination_port, flow.protocol)
        current = Observation(now, str(flow.destination), flow.destination_port, flow.protocol,
                              flow.failed, flow.bytes + flow.reverse_bytes,
                              (flow.packets + flow.reverse_packets) / max(flow.duration, .001),
                              tuple(getattr(flow, "missing_features", ())))
        newest_for_host = not history or history[-1].at <= now
        if not late:
            if newest_for_host:
                history.append(current)
            else:
                index = bisect_right([o.at for o in history], now)
                # In a full history a flow older than every retained event would be evicted
                # first, so it is not stored and displaces nothing.
                if len(history) < history.maxlen:
                    history.insert(index, current)
                elif index > 0:
                    history.popleft()
                    history.insert(index - 1, current)
        window = prior + [current]
        recent = [o for o in window if o.at >= now - 30]
        first = window[0].at
        rates = [o.packet_rate for o in recent]
        counts = {w: sum(o.at >= now - w for o in window) for w in self.windows}
        missing = {field for observation in recent for field in observation.missing}
        incomplete = []
        if "failed" in missing:
            incomplete.append("failed_ratio_30s")
        if "reverse_bytes" in missing:
            incomplete.append("log_bytes_30s")
        if "reverse_packets" in missing:
            incomplete.extend(("log_mean_packet_rate", "log_packet_rate_std"))
        # Occupancy describes repeated activity, not repeated model anomalies.
        occupied_bins = len({min(5, int((now - o.at) // 5)) for o in recent})
        available_bins = min(6, max(1, int((now - first) // 5) + 1))
        context = {f"connections_{w}s": n for w, n in counts.items()}
        context.update({
            "source": str(flow.source), "sensor_id": flow.sensor_id, "simulated": flow.simulated,
            "timestamp": flow.timestamp.isoformat(), "history_count": prior_count,
            "unique_destinations_30s": len({o.destination for o in recent}),
            "unique_ports_30s": len({o.port for o in recent}),
            "failed_ratio_30s": sum(o.failed for o in recent) / len(recent),
            "bytes_30s": sum(o.nbytes for o in recent),
            "destination_entropy": _entropy(o.destination for o in recent),
            "protocol_entropy": _entropy(o.protocol for o in recent),
            "new_edge": float(edge not in previous_edges),
            "edge_frequency": previous_edges[edge] / max(prior_count, 1),
            "rate_change": min(20., (counts[5] / 5) / max((counts[30] - counts[5]) / 25, .04)),
            "temporal_consistency": occupied_bins / available_bins,
            "mean_packet_rate": float(np.mean(rates)), "packet_rate_std": float(np.std(rates)),
            "history_seconds": now - first, "history_truncated": truncated,
            "incomplete_features": incomplete,
            "available": not late and prior_count >= 2, "late_event": late, "reordered": reordered,
            "evidence": [f"{counts[30]} observed connections to {len({o.destination for o in recent})} destinations in 30s",
                         f"{occupied_bins}/{available_bins} observed 5s bins contain activity; this is activity persistence, not proof of attack"],
        })
        if incomplete:
            context["evidence"].append("Some window counters are incomplete because sensor measurements are missing; affected model coordinates use the frozen benign baseline.")
        if not late:
            self._hosts[key] = history
            self._hosts.move_to_end(key)
            if newest_for_host:
                self._snapshots[key] = context
            while len(self._hosts) > self.max_hosts:
                evicted, _ = self._hosts.popitem(last=False)
                self._snapshots.pop(evicted, None)
        return context

    def snapshot(self) -> list[dict]:
        return [dict(self._snapshots[k]) for k in reversed(self._hosts)]
