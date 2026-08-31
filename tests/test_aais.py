from __future__ import annotations

import copy
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from aais import (
    ApprovalStore,
    ConflictError,
    ValidationError,
    action_digest,
    create_decision,
    validate,
)

ROOT = Path(__file__).resolve().parents[1]


def load_example(name: str) -> dict:
    return json.loads((ROOT / "examples" / name).read_text(encoding="utf-8"))


def test_example_and_digest_are_valid() -> None:
    request = load_example("shell-approval.json")
    assert action_digest(request["request"]["action"]) == request["request"]["action_digest"]
    assert validate(request) == request
    assert validate(load_example("approve-once.json"))["type"] == "approval.decided"


def test_digest_is_key_order_independent() -> None:
    assert action_digest({"b": 2, "a": 1}) == action_digest({"a": 1, "b": 2})


def test_store_approves_and_replays_idempotently() -> None:
    request = load_example("shell-approval.json")
    decision = load_example("approve-once.json")
    store = ApprovalStore()
    store.add(request)
    first = store.decide(decision, now=datetime(2026, 8, 30, 18, 1, tzinfo=timezone.utc))
    second = store.decide(decision, now=datetime(2026, 8, 30, 18, 2, tzinfo=timezone.utc))
    assert first == second
    assert first["resolution"]["outcome"] == "approved"


def test_conflicting_second_decision_is_rejected() -> None:
    request = load_example("shell-approval.json")
    decision = load_example("approve-once.json")
    store = ApprovalStore()
    store.add(request)
    store.decide(decision, now=datetime(2026, 8, 30, 18, 1, tzinfo=timezone.utc))
    changed = copy.deepcopy(decision)
    changed["decision"]["id"] = "dec_002"
    changed["decision"]["decision"] = "deny"
    with pytest.raises(ConflictError):
        store.decide(changed)


def test_expired_and_stale_fail_closed() -> None:
    request = load_example("shell-approval.json")
    decision = load_example("approve-once.json")
    expired = ApprovalStore()
    expired.add(request)
    result = expired.decide(decision, now=datetime(2026, 8, 30, 19, 0, tzinfo=timezone.utc))
    assert result["resolution"]["outcome"] == "expired"

    stale = ApprovalStore()
    stale.add(request)
    result = stale.decide(
        decision,
        now=datetime(2026, 8, 30, 18, 1, tzinfo=timezone.utc),
        current_action={"kind": "process.exec", "name": "shell.exec", "summary": "changed", "arguments": {}},
    )
    assert result["resolution"]["outcome"] == "stale"


def test_unoffered_scope_is_invalid() -> None:
    request = load_example("shell-approval.json")
    decision = create_decision(
        request,
        decision="approve",
        scope="persistent",
        actor={"id": "alex", "type": "human"},
        sequence=42,
        decided_at="2026-08-30T18:01:00Z",
    )
    store = ApprovalStore()
    store.add(request)
    result = store.decide(decision, now=datetime(2026, 8, 30, 18, 1, tzinfo=timezone.utc))
    assert result["resolution"]["outcome"] == "invalid"


def test_snapshot_round_trip() -> None:
    store = ApprovalStore()
    store.add(load_example("shell-approval.json"))
    restored = ApprovalStore.from_snapshot(
        store.snapshot(
            stream="session_s1", now=datetime(2026, 8, 30, 18, 1, tzinfo=timezone.utc)
        )
    )
    assert list(restored.pending) == ["apr_shell_001"]


def test_rejects_wrong_digest_and_missing_denial() -> None:
    request = load_example("shell-approval.json")
    request["request"]["action_digest"] = "sha256:" + "0" * 64
    with pytest.raises(ValidationError, match="canonical action"):
        validate(request)

    request = load_example("shell-approval.json")
    request["request"]["choices"] = [request["request"]["choices"][0]]
    with pytest.raises(ValidationError, match="deny or cancel"):
        validate(request)
