"""Validated network evidence. Labels and asset criticality are never telemetry inputs."""
from __future__ import annotations

import ipaddress
from datetime import datetime, timezone
from typing import Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class Flow(BaseModel):
    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)

    event_id: str = Field(default_factory=lambda: str(uuid4()), min_length=1, max_length=96, pattern=r"^[A-Za-z0-9_.:-]+$")
    timestamp: datetime
    source: str = Field(max_length=45)
    destination: str = Field(max_length=45)
    source_port: int = Field(default=0, ge=0, le=65535, strict=True)
    destination_port: int = Field(default=0, ge=0, le=65535, strict=True)
    protocol: Literal["TCP", "UDP", "ICMP", "OTHER"]
    duration: float = Field(ge=0, le=604800)
    packets: int = Field(ge=1, le=10**10, strict=True)
    bytes: int = Field(ge=0, le=10**15, strict=True)
    reverse_packets: int = Field(default=0, ge=0, le=10**10, strict=True)
    reverse_bytes: int = Field(default=0, ge=0, le=10**15, strict=True)
    failed: bool = Field(default=False, strict=True)
    syn_ratio: float = Field(default=0, ge=0, le=1)
    sensor_id: str = Field(default="local", min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_.:-]+$")
    simulated: bool = Field(default=False, strict=True)
    missing_features: list[Literal["syn_ratio", "failed", "reverse_packets", "reverse_bytes"]] = Field(default_factory=list, max_length=4)

    @model_validator(mode="before")
    @classmethod
    def declare_missing_measurements(cls, value):
        if isinstance(value, dict):
            value = dict(value)
            declared = value.get("missing_features", [])
            if isinstance(declared, list) and len(declared) <= 4 and all(isinstance(x, str) for x in declared):
                value["missing_features"] = sorted(set(declared) | {name for name in ("syn_ratio", "failed", "reverse_packets", "reverse_bytes") if name not in value})
        return value

    @field_validator("source", "destination")
    @classmethod
    def canonical_address(cls, value: str) -> str:
        if "%" in value:
            raise ValueError("Scoped addresses are unsupported; use a canonical IP address")
        return str(ipaddress.ip_address(value))

    @field_validator("timestamp")
    @classmethod
    def aware_time(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timestamp must include a timezone")
        return value.astimezone(timezone.utc)
