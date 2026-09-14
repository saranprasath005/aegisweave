"""Audited response policy. The sole adapter records simulations; no live adapter exists."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import ipaddress
import threading
from typing import Literal
import uuid

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .storage import Store, utc_now


class Policy(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    simulation: Literal[True] = True
    kill_switch: bool = False
    allowlist: list[str] = Field(default_factory=lambda: ["127.0.0.0/8", "::1/128"], max_length=200)
    max_actions_per_minute: int = Field(default=5, ge=1, le=60)
    min_risk: float = Field(default=70.0, ge=0, le=100)
    min_confidence: float = Field(default=0.8, ge=0, le=1)
    ttl_seconds: int = Field(default=300, ge=30, le=3600)

    @field_validator("allowlist")
    @classmethod
    def validate_allowlist(cls, values):
        return sorted({str(ipaddress.ip_network(value, strict=False)) for value in values})

    @field_validator("simulation", mode="before")
    @classmethod
    def enforce_simulation(cls, value):
        if value is not True:
            raise ValueError("Simulation is mandatory; live response is not implemented")
        return value


class ResponseRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    event_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_.:-]+$")
    action: Literal["block_source", "isolate_host", "notify"]
    reason: str = Field(min_length=3, max_length=1000)
    ttl_seconds: int = Field(default=300, ge=30, le=3600)

    @field_validator("reason")
    @classmethod
    def validate_reason(cls, value):
        if any(ord(c) < 32 for c in value) or len(value.strip()) < 3:
            raise ValueError("Reason must contain printable text")
        return value.strip()


class ActionReason(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    reason: str = Field(min_length=3, max_length=1000)
    validate_reason = field_validator("reason")(ResponseRequest.validate_reason.__func__)


class ResponseConflict(ValueError):
    pass


class ResponseEngine:
    def __init__(self, store: Store):
        self.store = store
        self.lock = threading.RLock()
        self.policy = Policy.model_validate(store.setting("response_policy", {}))

    def _transition(self, item, status, actor, reason):
        stamp = utc_now()
        item["status"] = status
        entry = {"timestamp": stamp, "actor": actor, "status": status, "reason": reason}
        item.setdefault("audit", []).append(entry)
        if status == "simulated":
            item["executed_at"] = stamp
            item["verification"] = "Recorded in simulation ledger; no device, host or firewall was modified."
        if status in {"expired", "rolled_back"}:
            item["verification"] = "Simulation state cleared; no live network action existed."
        self.store.record_response(item, actor, "response." + status, {"reason": reason, "action": item["action"], "simulated": True})
        return item

    def expire(self):
        with self.lock:
            now = datetime.now(timezone.utc)
            count = 0
            for item in self.store.active_responses():
                if datetime.fromisoformat(item["expires_at"]) <= now:
                    self._transition(item, "expired", "system", "Action lease expired; simulation state automatically cleared")
                    count += 1
            return count

    def _deny_reason(self, event, action, check_rate=True):
        policy = self.policy
        if policy.kill_switch:
            return "Emergency kill switch is enabled"
        if check_rate:
            since = (datetime.now(timezone.utc) - timedelta(seconds=60)).isoformat()
            if self.store.recent_actions("response.simulated", since) >= policy.max_actions_per_minute:
                return "Response execution rate limit reached"
        if action != "notify":
            # The decision gate is checked first: it is the most fundamental reason and
            # names why unattributed or uncertain evidence can never be contained.
            if event["fusion"]["decision"] != "malicious":
                return "Containment requires a malicious decision with an attributed attack type; suspicious, anomalous and uncertain evidence is investigation-only"
            address = ipaddress.ip_address(event["source"])
            # Mapped IPv6 addresses must not bypass IPv4 network allowlists.
            addresses = [address]
            if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
                addresses.append(address.ipv4_mapped)
            if any(a in ipaddress.ip_network(network) for a in addresses for network in policy.allowlist if a.version == ipaddress.ip_network(network).version):
                return "Target is protected by the allowlist"
            if event["risk"]["score"] < policy.min_risk:
                return "Risk is below the containment threshold"
            if event["prediction"]["confidence"] < policy.min_confidence:
                return "Classification confidence is below the containment threshold"
        return None

    def propose(self, request: ResponseRequest, actor):
        with self.lock:
            self.expire()
            event = self.store.event(request.event_id)
            if event is None:
                raise KeyError("Event not found")
            now = datetime.now(timezone.utc)
            ttl = min(request.ttl_seconds, self.policy.ttl_seconds)
            item = {"id": str(uuid.uuid4()), "event_id": request.event_id, "action": request.action,
                    "target": event["source"], "status": "pending_approval", "simulated": True,
                    "created_at": now.isoformat(), "expires_at": (now + timedelta(seconds=ttl)).isoformat(),
                    "reason": request.reason, "approval_required": request.action != "notify", "audit": []}
            since = (now - timedelta(seconds=60)).isoformat()
            denied = self._deny_reason(event, request.action)
            if self.store.recent_actions("response.proposed", since) >= self.policy.max_actions_per_minute * 2:
                denied = "Response proposal rate limit reached"
            self.store.audit(actor, "response.proposed", item["id"], {"event_id": request.event_id, "action": request.action, "reason": request.reason, "simulated": True})
            if denied:
                return self._transition(item, "denied", actor, denied)
            if item["approval_required"]:
                return self._transition(item, "pending_approval", actor, "Human approval required before recording simulated containment")
            return self._transition(item, "simulated", actor, request.reason)

    def approve(self, response_id, actor, reason):
        with self.lock:
            self.expire()
            item = self.store.response(response_id)
            if item is None:
                raise KeyError("Response not found")
            if item["status"] != "pending_approval":
                raise ResponseConflict("Only pending responses can be approved")
            event = self.store.event(item["event_id"])
            denied = self._deny_reason(event, item["action"]) if event else "Source event no longer retained; approval cannot be verified"
            # Approval re-evaluates the current policy, not a proposal-time policy snapshot.
            if denied:
                return self._transition(item, "denied", actor, denied)
            # A later policy can shorten a lease; approval never extends a proposal's expiry.
            policy_expiry = datetime.now(timezone.utc) + timedelta(seconds=self.policy.ttl_seconds)
            item["expires_at"] = min(datetime.fromisoformat(item["expires_at"]), policy_expiry).isoformat()
            return self._transition(item, "simulated", actor, reason)

    def rollback(self, response_id, actor, reason):
        with self.lock:
            self.expire()
            item = self.store.response(response_id)
            if item is None:
                raise KeyError("Response not found")
            if item["status"] not in {"pending_approval", "simulated"}:
                raise ResponseConflict("Only pending or active simulated responses can be rolled back")
            return self._transition(item, "rolled_back", actor, reason)

    def update_policy(self, policy: Policy, actor):
        with self.lock:
            before = self.policy.model_dump()
            self.store.record_policy(policy.model_dump(), actor, before)
            self.policy = policy
            if policy.kill_switch:
                for item in self.store.active_responses():
                    status = "rolled_back" if item["status"] == "simulated" else "denied"
                    self._transition(item, status, actor, "Emergency kill switch activated")
            return policy.model_dump()
