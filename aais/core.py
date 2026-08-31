"""Validation, builders, digests, and a reference in-memory approval store."""

from __future__ import annotations

import copy
import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from importlib.resources import files
from pathlib import Path
from typing import Any
from uuid import uuid4

import jsonschema
import rfc8785

JsonObject = dict[str, Any]


class ApprovalError(Exception):
    """Base class for AAIS errors."""


class ValidationError(ApprovalError):
    """An AAIS document or state transition is invalid."""


class ConflictError(ApprovalError):
    """A request has already been resolved by a different decision."""


def _schema() -> JsonObject:
    installed = files("aais").joinpath("schema/aais-1.0.schema.json")
    if installed.is_file():
        return json.loads(installed.read_text(encoding="utf-8"))
    source = Path(__file__).resolve().parents[1] / "schema/v1/aais-1.0.schema.json"
    return json.loads(source.read_text(encoding="utf-8"))


_VALIDATOR = jsonschema.Draft202012Validator(
    _schema(), format_checker=jsonschema.FormatChecker()
)


def _parse_time(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValidationError(f"invalid RFC 3339 timestamp: {value}") from exc
    if parsed.tzinfo is None:
        raise ValidationError("timestamps must include an explicit UTC offset")
    return parsed


def validate(document: Mapping[str, Any]) -> JsonObject:
    """Validate and return a defensive copy of an AAIS envelope."""

    candidate = copy.deepcopy(dict(document))
    errors = sorted(_VALIDATOR.iter_errors(candidate), key=lambda error: list(error.path))
    if errors:
        error = errors[0]
        location = "/" + "/".join(str(part) for part in error.absolute_path)
        raise ValidationError(f"{location or '/'}: {error.message}")
    if candidate["type"] == "approval.requested":
        request = candidate["request"]
        if not any(c["decision"] in {"deny", "cancel"} for c in request["choices"]):
            raise ValidationError("/request/choices: at least one deny or cancel choice is required")
        expected = action_digest(request["action"])
        if request["action_digest"] != expected:
            raise ValidationError("/request/action_digest: does not match the canonical action")
        if "expires_at" in request and _parse_time(request["expires_at"]) <= _parse_time(
            request["created_at"]
        ):
            raise ValidationError("/request/expires_at: must be later than created_at")
    return candidate


def action_digest(action: Mapping[str, Any]) -> str:
    """Return the AAIS RFC 8785 / SHA-256 binding for an action."""

    canonical = rfc8785.dumps(dict(action))
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _id(prefix: str) -> str:
    return f"{prefix}_{uuid4().hex}"


def create_request(
    *,
    action: Mapping[str, Any],
    origin: Mapping[str, Any],
    risk: Mapping[str, Any],
    choices: list[Mapping[str, Any]],
    sequence: int,
    stream: str | None = None,
    request_id: str | None = None,
    event_id: str | None = None,
    created_at: str | None = None,
    expires_at: str | None = None,
) -> JsonObject:
    """Create and validate an ``approval.requested`` envelope."""

    created = created_at or _now()
    request: JsonObject = {
        "id": request_id or _id("apr"),
        "created_at": created,
        "status": "pending",
        "origin": dict(origin),
        "action": dict(action),
        "action_digest": action_digest(action),
        "risk": dict(risk),
        "choices": [dict(choice) for choice in choices],
    }
    if expires_at is not None:
        request["expires_at"] = expires_at
    envelope: JsonObject = {
        "aais": "1.0",
        "type": "approval.requested",
        "id": event_id or _id("evt"),
        "occurred_at": created,
        "sequence": sequence,
        "request": request,
    }
    if stream is not None:
        envelope["stream"] = stream
    return validate(envelope)


def create_decision(
    request: Mapping[str, Any],
    *,
    decision: str,
    scope: str,
    actor: Mapping[str, Any],
    sequence: int,
    decision_id: str | None = None,
    event_id: str | None = None,
    decided_at: str | None = None,
    replacement_arguments: Mapping[str, Any] | None = None,
) -> JsonObject:
    """Create a decision bound to a requested envelope."""

    requested = validate(request)
    if requested["type"] != "approval.requested":
        raise ValidationError("create_decision requires an approval.requested envelope")
    at = decided_at or _now()
    body: JsonObject = {
        "id": decision_id or _id("dec"),
        "request_id": requested["request"]["id"],
        "action_digest": requested["request"]["action_digest"],
        "decided_at": at,
        "decision": decision,
        "scope": scope,
        "actor": dict(actor),
    }
    if replacement_arguments is not None:
        body["replacement_arguments"] = dict(replacement_arguments)
    envelope: JsonObject = {
        "aais": "1.0",
        "type": "approval.decided",
        "id": event_id or _id("evt"),
        "occurred_at": at,
        "sequence": sequence,
        "decision": body,
    }
    if "stream" in requested:
        envelope["stream"] = requested["stream"]
    return validate(envelope)


@dataclass
class ApprovalStore:
    """Reference fail-closed state machine for pending approvals."""

    pending: dict[str, JsonObject] = field(default_factory=dict)
    resolutions: dict[str, JsonObject] = field(default_factory=dict)
    decision_fingerprints: dict[str, str] = field(default_factory=dict)
    last_sequence: int = 0

    def add(self, envelope: Mapping[str, Any]) -> JsonObject:
        requested = validate(envelope)
        if requested["type"] != "approval.requested":
            raise ValidationError("store.add requires approval.requested")
        request_id = requested["request"]["id"]
        existing = self.pending.get(request_id)
        if existing is not None and existing != requested:
            raise ConflictError(f"request {request_id} already exists with different content")
        self.pending[request_id] = requested
        self.last_sequence = max(self.last_sequence, requested["sequence"])
        return copy.deepcopy(requested)

    def decide(
        self,
        envelope: Mapping[str, Any],
        *,
        now: datetime | None = None,
        current_action: Mapping[str, Any] | None = None,
        sequence: int | None = None,
    ) -> JsonObject:
        decided = validate(envelope)
        if decided["type"] != "approval.decided":
            raise ValidationError("store.decide requires approval.decided")
        body = decided["decision"]
        request_id = body["request_id"]
        fingerprint = action_digest(body)
        if request_id in self.resolutions:
            if self.decision_fingerprints[request_id] == fingerprint:
                return copy.deepcopy(self.resolutions[request_id])
            raise ConflictError(f"request {request_id} was already resolved")
        requested = self.pending.get(request_id)
        if requested is None:
            raise ValidationError(f"unknown pending request: {request_id}")
        request = requested["request"]
        instant = now or datetime.now(timezone.utc)
        outcome = "approved" if body["decision"] == "approve" else (
            "denied" if body["decision"] == "deny" else "cancelled"
        )
        message = {
            "approved": "Approval accepted.",
            "denied": "Action denied.",
            "cancelled": "Approval cancelled.",
        }[outcome]
        if "expires_at" in request and instant >= _parse_time(request["expires_at"]):
            outcome, message = "expired", "Approval request expired."
        elif body["action_digest"] != request["action_digest"]:
            outcome, message = "stale", "Decision does not match the requested action."
        elif current_action is not None and action_digest(current_action) != request["action_digest"]:
            outcome, message = "stale", "The action changed after it was presented."
        else:
            offered = next(
                (
                    choice
                    for choice in request["choices"]
                    if choice["decision"] == body["decision"] and choice["scope"] == body["scope"]
                ),
                None,
            )
            if offered is None:
                outcome, message = "invalid", "The selected decision and scope were not offered."
            elif "replacement_arguments" in body and not offered.get("allow_edits", False):
                outcome, message = "invalid", "This approval choice does not allow argument edits."
        resolved_at = instant.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
        result: JsonObject = {
            "aais": "1.0",
            "type": "approval.resolved",
            "id": _id("evt"),
            "occurred_at": resolved_at,
            "sequence": sequence if sequence is not None else max(self.last_sequence + 1, decided["sequence"]),
            "resolution": {
                "id": _id("res"),
                "request_id": request_id,
                "decision_id": body["id"],
                "action_digest": request["action_digest"],
                "resolved_at": resolved_at,
                "outcome": outcome,
                "message": message,
            },
        }
        if outcome in {"approved", "denied"}:
            result["resolution"]["effective_scope"] = body["scope"]
        if "stream" in requested:
            result["stream"] = requested["stream"]
        result = validate(result)
        self.pending.pop(request_id)
        self.resolutions[request_id] = result
        self.decision_fingerprints[request_id] = fingerprint
        self.last_sequence = max(self.last_sequence, result["sequence"])
        return copy.deepcopy(result)

    def snapshot(
        self,
        *,
        stream: str | None = None,
        event_id: str | None = None,
        now: datetime | None = None,
    ) -> JsonObject:
        """Return a validated snapshot of unresolved requests."""

        instant = now or datetime.now(timezone.utc)
        timestamp = instant.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
        pending = [
            copy.deepcopy(item["request"])
            for item in self.pending.values()
            if "expires_at" not in item["request"]
            or instant < _parse_time(item["request"]["expires_at"])
        ]
        envelope: JsonObject = {
            "aais": "1.0",
            "type": "approval.snapshot",
            "id": event_id or _id("evt"),
            "occurred_at": timestamp,
            "sequence": self.last_sequence,
            "snapshot": {
                "as_of_sequence": self.last_sequence,
                "pending": pending,
            },
        }
        if stream is not None:
            envelope["stream"] = stream
        return validate(envelope)

    @classmethod
    def from_snapshot(cls, envelope: Mapping[str, Any]) -> ApprovalStore:
        restored = validate(envelope)
        if restored["type"] != "approval.snapshot":
            raise ValidationError("from_snapshot requires approval.snapshot")
        store = cls(last_sequence=restored["snapshot"]["as_of_sequence"])
        for request in restored["snapshot"]["pending"]:
            wrapper: JsonObject = {
                "aais": "1.0",
                "type": "approval.requested",
                "id": f"restore_{request['id']}",
                "occurred_at": request["created_at"],
                "sequence": store.last_sequence,
                "request": request,
            }
            if "stream" in restored:
                wrapper["stream"] = restored["stream"]
            store.add(wrapper)
        return store
