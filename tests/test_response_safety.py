from datetime import datetime, timedelta, timezone

import pytest

from aegisweave.response import Policy, ResponseConflict, ResponseEngine, ResponseRequest
from aegisweave.schema import Flow
from aegisweave.storage import Store
from test_api_security import FakeEngine, flow


@pytest.fixture
def responder(tmp_path):
    store = Store(tmp_path / "response.db")
    yield ResponseEngine(store)
    store.close()


def add(responder, event_id="event", source="10.0.0.9", confidence=0.95, risk=92, decision="malicious"):
    event = FakeEngine().process(Flow.model_validate(flow(event_id, source=source)))
    event["prediction"]["confidence"] = confidence
    event["risk"]["score"] = risk
    event["fusion"]["decision"] = decision
    responder.store.add_event(event)
    return ResponseRequest(event_id=event_id, action="block_source", reason="Investigated related evidence")


@pytest.mark.parametrize("changes,expected", [({"source": "127.0.0.1"}, "allowlist"), ({"source": "::ffff:127.0.0.1"}, "allowlist"), ({"confidence": 0.2}, "confidence"), ({"risk": 30}, "Risk"), ({"decision": "unknown"}, "uncertain"), ({"decision": "anomalous"}, "anomalous"), ({"decision": "suspicious", "risk": 69}, "malicious decision")])
def test_containment_denies_unsafe_evidence(responder, changes, expected):
    result = responder.propose(add(responder, **changes), "analyst:test")
    assert result["status"] == "denied"
    assert expected in result["audit"][-1]["reason"]
    assert responder.store.audits()[0]["action"] == "response.denied"


def test_approval_rechecks_changed_allowlist(responder):
    item = responder.propose(add(responder), "analyst:test")
    responder.update_policy(Policy(allowlist=["10.0.0.0/8"]), "admin:test")
    result = responder.approve(item["id"], "analyst:reviewer", "Approve evidence")
    assert result["status"] == "denied"
    assert "allowlist" in result["audit"][-1]["reason"]


def test_kill_switch_rolls_back_active_and_denies_pending(responder):
    first = responder.propose(add(responder, "a"), "analyst:test")
    second = responder.propose(add(responder, "b"), "analyst:test")
    responder.approve(first["id"], "analyst:test", "Review complete")
    responder.update_policy(Policy(kill_switch=True), "admin:test")
    assert responder.store.response(first["id"])["status"] == "rolled_back"
    assert responder.store.response(second["id"])["status"] == "denied"
    assert responder.propose(add(responder, "c"), "analyst:test")["status"] == "denied"
    with pytest.raises(ResponseConflict):
        responder.approve(second["id"], "analyst:test", "Try again")


def test_rate_limit_rechecked_on_approval(responder):
    responder.update_policy(Policy(max_actions_per_minute=1), "admin:test")
    first = responder.propose(add(responder, "a"), "analyst:test")
    second = responder.propose(add(responder, "b"), "analyst:test")
    assert responder.approve(first["id"], "analyst:test", "Approved after review")["status"] == "simulated"
    blocked = responder.approve(second["id"], "analyst:test", "Approved after review")
    assert blocked["status"] == "denied" and "rate limit" in blocked["audit"][-1]["reason"]


def test_expiry_is_automatic_and_idempotent(responder):
    item = responder.propose(add(responder), "analyst:test")
    item = responder.approve(item["id"], "analyst:test", "Review complete")
    item["expires_at"] = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
    responder.store.save_response(item)
    assert responder.expire() == 1
    assert responder.expire() == 0
    assert responder.store.response(item["id"])["status"] == "expired"
    assert responder.store.audits()[0]["action"] == "response.expired"


def test_expired_pending_approval_cannot_execute(responder):
    item = responder.propose(add(responder), "analyst:test")
    item["expires_at"] = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
    responder.store.save_response(item)
    with pytest.raises(ResponseConflict):
        responder.approve(item["id"], "analyst:test", "Too late")
    assert responder.store.response(item["id"])["status"] == "expired"


def test_missing_event_prevents_approval(responder):
    item = responder.propose(add(responder), "analyst:test")
    with responder.store.lock, responder.store.db:
        responder.store.db.execute("DELETE FROM events")
    result = responder.approve(item["id"], "analyst:test", "Review complete")
    assert result["status"] == "denied" and "no longer retained" in result["audit"][-1]["reason"]


def test_rollback_is_not_repeatable_and_policy_persists(responder):
    item = responder.propose(add(responder), "analyst:test")
    result = responder.rollback(item["id"], "analyst:test", "Cancel proposal")
    assert result["status"] == "rolled_back"
    with pytest.raises(ResponseConflict):
        responder.rollback(item["id"], "analyst:test", "Cancel again")
    responder.update_policy(Policy(min_risk=95), "admin:test")
    assert ResponseEngine(responder.store).policy.min_risk == 95
