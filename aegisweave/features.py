"""Versioned numeric telemetry features. Addresses, identifiers and labels are excluded."""
from __future__ import annotations

from typing import Any
import numpy as np

FEATURE_SCHEMA = "aegisweave.flow.v1"
COMMON_FEATURES = (
    "log_duration", "log_packets", "log_bytes", "log_reverse_packets", "log_reverse_bytes",
    "log_packet_rate", "log_byte_rate", "log_mean_packet_size", "reverse_packet_share", "reverse_byte_share",
)
FLOW_FEATURES = COMMON_FEATURES + (
    "tcp", "udp", "icmp", "other_protocol", "log_destination_port", "failed", "syn_ratio",
)
BEHAVIOR_FEATURES = (
    "log_connections_5s", "log_connections_30s", "log_connections_60s", "log_connections_300s",
    "log_unique_destinations_30s", "log_unique_ports_30s", "failed_ratio_30s", "log_bytes_30s",
    "destination_entropy", "protocol_entropy", "new_edge", "rate_change", "temporal_consistency",
    "log_mean_packet_rate", "log_packet_rate_std", "edge_frequency",
)


def _get(obj: Any, key: str, default: Any = 0) -> Any:
    return obj.get(key, default) if isinstance(obj, dict) else getattr(obj, key, default)


def flow_features(flow: Any, common_only: bool = False) -> np.ndarray:
    """Forward counters have the same meaning in live telemetry and CSV adapters.

    Derived rates use a documented 1ms denominator floor; capped inputs prevent
    tiny durations from creating infinities. No fitted transformation occurs here.
    """
    duration = float(_get(flow, "duration"))
    packets, nbytes = float(_get(flow, "packets")), float(_get(flow, "bytes"))
    rp, rb = float(_get(flow, "reverse_packets")), float(_get(flow, "reverse_bytes"))
    vals = np.asarray([duration, packets, nbytes, rp, rb], dtype=float)
    if not np.isfinite(vals).all() or (vals < 0).any():
        raise ValueError("Feature inputs must be finite and nonnegative")
    total_p, total_b = packets + rp, nbytes + rb
    base = [*np.log1p(vals), np.log1p(total_p / max(duration, .001)),
            np.log1p(total_b / max(duration, .001)), np.log1p(total_b / max(total_p, 1)),
            rp / max(total_p, 1), rb / max(total_b, 1)]
    if not common_only:
        protocol = str(_get(flow, "protocol", "OTHER")).upper()
        base.extend([float(protocol == p) for p in ("TCP", "UDP", "ICMP", "OTHER")])
        base.extend([np.log1p(float(_get(flow, "destination_port"))),
                     float(_get(flow, "failed", False)), float(_get(flow, "syn_ratio"))])
    out = np.asarray(base, dtype=np.float64)
    if not np.isfinite(out).all():
        raise ValueError("Non-finite derived feature")
    return out


def behavior_features(context: dict) -> np.ndarray:
    out = []
    for name in BEHAVIOR_FEATURES:
        if name.startswith("log_"):
            out.append(np.log1p(max(0., float(context.get(name[4:], 0)))))
        else:
            out.append(float(context.get(name, 0)))
    result = np.asarray(out, dtype=np.float64)
    if not np.isfinite(result).all():
        raise ValueError("Non-finite behavior feature")
    return result
