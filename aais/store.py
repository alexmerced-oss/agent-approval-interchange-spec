"""Durable, cross-process AAIS approval authority backed by one JSON file.

:class:`FileApprovalStore` persists pending requests, decisions, resolutions
(receipts), owner identities, and the ordered event log for one approval
stream. Several processes may open the same file: every read-modify-write runs
as a transaction under an exclusive OS file lock (``fcntl.flock`` on POSIX,
``msvcrt.locking`` on Windows), so sequence allocation, pending insertion,
resolution, and receipts can never interleave.

Durability and failure handling:

* writes go to a unique temporary file in the same directory, are fsynced, and
  atomically replace the state file; the directory is fsynced on POSIX;
* an unreadable state file is moved to ``<file>.corrupt-<UTC timestamp>`` and
  the store enters a *recovery required* state (a ``<file>.recovery-required``
  marker). Every later call raises :class:`RecoveryRequired` until an operator
  calls :meth:`FileApprovalStore.acknowledge_recovery`; the store never treats
  a damaged file as empty;
* resolved entries and old events are compacted according to a
  :class:`RetentionPolicy`; :meth:`FileApprovalStore.events_after` reports a
  ``gap`` when the caller asks for events that were compacted away.

The store is an implementation aid. It does not change AAIS 1.0 semantics:
every envelope it emits is produced and validated by :mod:`aais.core`.
"""

from __future__ import annotations

import contextlib
import copy
import json
import os
import re
import sys
import tempfile
import threading
import time
import uuid
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .core import (
    ApprovalError,
    ApprovalStore,
    ConflictError,
    ValidationError,
    _parse_time,
    create_decision,
    create_request,
    validate,
)
from .liveness import Liveness, OwnerIdentity, owner_liveness

__all__ = [
    "SCHEMA",
    "CompactionReport",
    "EventPage",
    "FileApprovalStore",
    "LockTimeout",
    "OwnerStoppedError",
    "RecoveryReport",
    "RecoveryRequired",
    "RetentionPolicy",
    "StaleDecisionError",
    "StoreError",
    "StoreTransaction",
    "UnknownRequestError",
    "UnsupportedStoreVersion",
]

Envelope = dict[str, Any]
Clock = Callable[[], datetime]

#: Schema tag written into every state file.
SCHEMA = "aais.store.v1"
_SCHEMA_PREFIX = "aais.store."

_DEFAULT_GUIDANCE = (
    "Stopped owners are not restarted. Inspect completed effects before creating a new run."
)
_POLICY_ACTOR: dict[str, str] = {"type": "policy", "authenticated_by": "authority"}


# ----------------------------------------------------------------------- errors


class StoreError(ApprovalError):
    """The approval store could not complete an operation."""


class RecoveryRequired(StoreError):
    """The state file was unreadable and has been quarantined.

    The store refuses every operation until
    :meth:`FileApprovalStore.acknowledge_recovery` is called.
    """

    def __init__(
        self,
        path: Path,
        *,
        reason: str,
        quarantined_to: Path | None,
        detected_at: str,
        sequence_hint: int,
    ) -> None:
        where = f"; the damaged file was moved to {quarantined_to}" if quarantined_to else ""
        super().__init__(
            f"Approval state at {path} requires recovery ({reason}){where}. "
            "Inspect it, then call acknowledge_recovery() to start a fresh store."
        )
        self.path = path
        self.reason = reason
        self.quarantined_to = quarantined_to
        self.detected_at = detected_at
        self.sequence_hint = sequence_hint

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": str(self.path),
            "reason": self.reason,
            "quarantined_to": str(self.quarantined_to) if self.quarantined_to else None,
            "detected_at": self.detected_at,
            "sequence_hint": self.sequence_hint,
        }


class UnsupportedStoreVersion(StoreError):
    """The state file was written by a newer, incompatible store version."""


class LockTimeout(StoreError):
    """Another thread or process held the store lock for too long."""


class UnknownRequestError(ValidationError, ValueError):
    """The request is neither pending nor resolved (or was compacted away)."""


class OwnerStoppedError(ConflictError):
    """An approval was refused because the owning process has stopped."""


class StaleDecisionError(ConflictError):
    """The reviewed action digest does not match the pending request."""


# ------------------------------------------------------------------ value types


@dataclass(frozen=True)
class RetentionPolicy:
    """How much resolved history and event log to keep.

    Resolved requests (with their decision, resolution receipt, and owner
    record) are removed when they are older than ``max_resolved_age`` or when
    more than ``max_resolved`` exist (oldest first). Events are removed from the
    head of the log when older than ``max_event_age`` or beyond ``max_events``.
    ``None`` disables a limit. Pending requests are never compacted.
    """

    max_resolved: int | None = 1000
    max_resolved_age: timedelta | None = timedelta(days=30)
    max_events: int | None = 1000
    max_event_age: timedelta | None = timedelta(days=30)

    def __post_init__(self) -> None:
        for name in ("max_resolved", "max_events"):
            value = getattr(self, name)
            if value is not None and (not isinstance(value, int) or value < 0):
                raise ValueError(f"{name} must be a non-negative integer or None")
        for name in ("max_resolved_age", "max_event_age"):
            value = getattr(self, name)
            if value is not None and (not isinstance(value, timedelta) or value < timedelta(0)):
                raise ValueError(f"{name} must be a non-negative timedelta or None")


@dataclass(frozen=True)
class EventPage:
    """Result of :meth:`FileApprovalStore.events_after`.

    ``gap`` is ``True`` when events after the requested sequence may be missing:
    either they were compacted (``after < compacted_through``) or the caller's
    sequence is ahead of this store (the store was reset after recovery). A
    client that sees a gap must resynchronize from a snapshot. ``store_id`` is
    a random identifier assigned on the first write (empty before that) and
    replaced when the store is reset by :meth:`FileApprovalStore.acknowledge_recovery`.
    """

    events: list[Envelope]
    gap: bool
    compacted_through: int
    latest_sequence: int
    store_id: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "events": copy.deepcopy(self.events),
            "gap": self.gap,
            "compacted_through": self.compacted_through,
            "latest_sequence": self.latest_sequence,
            "store_id": self.store_id,
        }


@dataclass(frozen=True)
class RecoveryReport:
    """Pending requests whose owners stopped, plus recent receipts."""

    orphaned: list[str]
    unknown_owner: list[str]
    unverified_owner: list[str]
    receipts: list[Envelope]
    guidance: str = _DEFAULT_GUIDANCE

    def to_dict(self) -> dict[str, Any]:
        return {
            "orphaned": list(self.orphaned),
            "unknown_owner": list(self.unknown_owner),
            "unverified_owner": list(self.unverified_owner),
            "receipts": copy.deepcopy(self.receipts),
            "guidance": self.guidance,
        }


@dataclass(frozen=True)
class CompactionReport:
    """What one compaction pass removed."""

    removed_resolved: list[str] = field(default_factory=list)
    removed_events: int = 0
    removed_owners: int = 0
    compacted_through: int = 0

    @property
    def changed(self) -> bool:
        return bool(self.removed_resolved or self.removed_events or self.removed_owners)


# ---------------------------------------------------------------------- helpers


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _empty_state(sequence: int = 0) -> dict[str, Any]:
    # ``store_id`` stays empty until the first write assigns one, so reads of a
    # store that does not exist yet report a stable (empty) identity.
    return {
        "schema": SCHEMA,
        "store_id": "",
        "sequence": sequence,
        "presenter_sequence": sequence,
        "compacted_through": sequence,
        "pending": {},
        "owners": {},
        "decisions": {},
        "resolutions": {},
        "events": [],
        "extensions": {},
    }


_SEQUENCE_PATTERN = re.compile(
    rb'"(?:sequence|presenter_sequence|as_of_sequence)"\s*:\s*(\d{1,18})'
)


def _sequence_hint(raw: bytes) -> int:
    """Best-effort highest sequence found in a damaged file."""

    return max((int(match) for match in _SEQUENCE_PATTERN.findall(raw)), default=0)


def _copy_envelope(value: Any) -> Envelope | None:
    return None if value is None else dict(copy.deepcopy(value))


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _check_state(value: object) -> str | None:
    """Return a reason string if ``value`` is not a structurally valid state."""

    if not isinstance(value, dict):
        return "state is not a JSON object"
    for key in ("sequence", "presenter_sequence", "compacted_through"):
        if not _is_int(value.get(key)) or value[key] < 0:
            return f"{key} is not a non-negative integer"
    if not isinstance(value.get("store_id"), str) or not value["store_id"]:
        return "store_id is missing"
    for key in ("pending", "owners", "decisions", "resolutions", "extensions"):
        if not isinstance(value.get(key), dict):
            return f"{key} is not an object"
    if not isinstance(value.get("events"), list):
        return "events is not a list"
    for request_id, envelope in value["pending"].items():
        if (
            not isinstance(envelope, dict)
            or not isinstance(envelope.get("request"), dict)
            or envelope["request"].get("id") != request_id
        ):
            return f"pending entry {request_id!r} is malformed"
    for name in ("decisions", "resolutions"):
        for request_id, envelope in value[name].items():
            if not isinstance(envelope, dict) or not _is_int(envelope.get("sequence")):
                return f"{name} entry {request_id!r} is malformed"
    for request_id, owner in value["owners"].items():
        try:
            OwnerIdentity.from_dict(owner)
        except (TypeError, ValueError) as error:
            return f"owner for {request_id!r} is malformed: {error}"
    for event in value["events"]:
        if not isinstance(event, dict) or not _is_int(event.get("sequence")):
            return "event log contains a malformed event"
    return None


# ---------------------------------------------------------------------- locking

_REGISTRY_GUARD = threading.Lock()
_PATH_LOCKS: dict[str, threading.Lock] = {}
_HELD = threading.local()


def _thread_lock_for(key: str) -> threading.Lock:
    with _REGISTRY_GUARD:
        lock = _PATH_LOCKS.get(key)
        if lock is None:
            lock = _PATH_LOCKS[key] = threading.Lock()
        return lock


def _held_paths() -> set[str]:
    held: set[str] | None = getattr(_HELD, "paths", None)
    if held is None:
        held = set()
        _HELD.paths = held
    return held


def _try_lock(descriptor: int) -> bool:
    """Try once to take an exclusive lock; ``False`` means it is contended."""

    if sys.platform == "win32":  # pragma: no cover - exercised on Windows CI
        import msvcrt

        os.lseek(descriptor, 0, os.SEEK_SET)
        try:
            msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
        except OSError:
            return False
        return True
    import fcntl

    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        return False
    return True


def _unlock(descriptor: int) -> None:
    if sys.platform == "win32":  # pragma: no cover - exercised on Windows CI
        import msvcrt

        os.lseek(descriptor, 0, os.SEEK_SET)
        msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
        return
    import fcntl

    fcntl.flock(descriptor, fcntl.LOCK_UN)


def _fsync_directory(directory: Path) -> None:
    if sys.platform == "win32":  # pragma: no cover - directories cannot be opened on Windows
        return
    with contextlib.suppress(OSError):
        descriptor = os.open(directory, os.O_RDONLY)
        try:
            _fsync(descriptor)
        finally:
            os.close(descriptor)


def _replace(source: Path, target: Path) -> None:
    """``os.replace`` with a short retry for Windows sharing violations."""

    attempts = 20 if sys.platform == "win32" else 1
    for attempt in range(attempts):
        try:
            os.replace(source, target)
            return
        except PermissionError:
            if attempt == attempts - 1:
                raise
            time.sleep(0.05)  # pragma: no cover - Windows only


def _fsync(descriptor: int) -> None:
    """Flush a file to stable storage (``F_FULLFSYNC`` on macOS)."""

    if sys.platform == "darwin":  # pragma: no cover - exercised on macOS CI
        import fcntl

        try:
            fcntl.fcntl(descriptor, fcntl.F_FULLFSYNC)
            return
        except OSError:
            pass
    os.fsync(descriptor)


def _atomic_write(path: Path, payload: bytes) -> None:
    descriptor, name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            _fsync(handle.fileno())
        _replace(temporary, path)
    except BaseException:
        with contextlib.suppress(OSError):
            temporary.unlink()
        raise
    _fsync_directory(path.parent)


# ------------------------------------------------------------------ transaction


class StoreTransaction:
    """A locked read-modify-write view of the store state.

    Obtain one from :meth:`FileApprovalStore.transaction`. Changes are written
    atomically when the ``with`` block exits without an exception; if it raises,
    nothing is written. Getter methods return deep copies.
    """

    def __init__(self, store: FileApprovalStore, state: dict[str, Any]) -> None:
        self._store = store
        self._state = state
        self._dirty = False

    # ------------------------------------------------------------- sequences

    @property
    def store_id(self) -> str:
        return str(self._state["store_id"])

    @property
    def sequence(self) -> int:
        """Last sequence allocated on the authority stream."""

        return int(self._state["sequence"])

    def next_sequence(self) -> int:
        """Allocate the next authority-stream sequence."""

        self._state["sequence"] = int(self._state["sequence"]) + 1
        self._dirty = True
        return int(self._state["sequence"])

    def next_presenter_sequence(self) -> int:
        """Allocate the next sequence for decisions on the presenter stream."""

        self._state["presenter_sequence"] = int(self._state["presenter_sequence"]) + 1
        self._dirty = True
        return int(self._state["presenter_sequence"])

    # ---------------------------------------------------------------- reads

    def pending(self) -> dict[str, Envelope]:
        return copy.deepcopy(self._state["pending"])

    def get_pending(self, request_id: str) -> Envelope | None:
        return _copy_envelope(self._state["pending"].get(request_id))

    def get_decision(self, request_id: str) -> Envelope | None:
        return _copy_envelope(self._state["decisions"].get(request_id))

    def get_resolution(self, request_id: str) -> Envelope | None:
        return _copy_envelope(self._state["resolutions"].get(request_id))

    def get_owner(self, request_id: str) -> OwnerIdentity | None:
        owner = self._state["owners"].get(request_id)
        return None if owner is None else OwnerIdentity.from_dict(owner)

    def owner_liveness(self, request_id: str) -> Liveness | None:
        """Liveness of the request's owner, or ``None`` if none is recorded."""

        owner = self.get_owner(request_id)
        return None if owner is None else owner_liveness(owner, host_id=self._store.host_id)

    # ------------------------------------------------------------ extensions

    def get_extension(self, name: str, default: Any = None) -> Any:
        """Read consumer-owned JSON stored alongside the approval state."""

        extensions = self._state["extensions"]
        return copy.deepcopy(extensions[name]) if name in extensions else default

    def set_extension(self, name: str, value: Any) -> None:
        """Store consumer-owned JSON (for example remembered grants)."""

        json.dumps(value)  # fail early on values that cannot be persisted
        self._state["extensions"][name] = copy.deepcopy(value)
        self._dirty = True

    def delete_extension(self, name: str) -> None:
        if self._state["extensions"].pop(name, None) is not None:
            self._dirty = True

    # --------------------------------------------------------------- writes

    def add_request(
        self,
        *,
        action: Mapping[str, Any],
        origin: Mapping[str, Any],
        risk: Mapping[str, Any],
        choices: list[Mapping[str, Any]],
        request_id: str | None = None,
        event_id: str | None = None,
        created_at: str | None = None,
        expires_at: str | None = None,
        ttl: float | timedelta | None = None,
        owner: OwnerIdentity | None = None,
    ) -> Envelope:
        """Create, validate, and persist a pending ``approval.requested`` event.

        The sequence is allocated inside this transaction. ``ttl`` (seconds or a
        timedelta) sets ``expires_at`` relative to ``created_at`` when
        ``expires_at`` is not given. ``owner`` defaults to the calling process.
        """

        if request_id is not None and (
            request_id in self._state["pending"] or request_id in self._state["resolutions"]
        ):
            raise ConflictError(f"request {request_id} already exists")
        created = _parse_time(created_at) if created_at else self._store.clock()
        if expires_at is None and ttl is not None:
            delta = ttl if isinstance(ttl, timedelta) else timedelta(seconds=float(ttl))
            expires_at = _timestamp(created + delta)
        envelope = create_request(
            action=action,
            origin=origin,
            risk=risk,
            choices=choices,
            sequence=self.sequence + 1,
            stream=self._store.stream,
            request_id=request_id,
            event_id=event_id,
            created_at=created_at or _timestamp(created),
            expires_at=expires_at,
        )
        self.next_sequence()
        identifier = str(envelope["request"]["id"])
        if identifier in self._state["pending"] or identifier in self._state["resolutions"]:
            raise ConflictError(f"request {identifier} already exists")
        self._state["pending"][identifier] = envelope
        self._state["owners"][identifier] = (owner or self._store.owner).to_dict()
        self._state["events"].append(envelope)
        return copy.deepcopy(envelope)

    def decide(
        self,
        request_id: str,
        *,
        decision: str,
        scope: str,
        actor: Mapping[str, Any],
        decision_id: str | None = None,
        reviewed_digest: str | None = None,
        current_action: Mapping[str, Any] | None = None,
        require_live_owner: bool = True,
    ) -> Envelope:
        """Record a decision and return the ``approval.resolved`` receipt.

        Replaying the same ``(decision, scope)`` for an already resolved request
        returns the original receipt; a different choice raises
        :class:`~aais.ConflictError`. A mismatched ``reviewed_digest`` raises
        :class:`StaleDecisionError`. An approval is refused with
        :class:`OwnerStoppedError` when the owning process is known to have
        stopped (unless ``require_live_owner`` is ``False``); owners on another
        host are *not* treated as stopped. ``current_action`` lets the caller
        prove the action has not changed since it was presented.
        """

        prior = self._state["resolutions"].get(request_id)
        if prior is not None:
            previous = self._state["decisions"].get(request_id)
            if previous is not None and (
                previous["decision"]["decision"],
                previous["decision"]["scope"],
            ) == (decision, scope):
                return copy.deepcopy(prior)
            raise ConflictError(f"request {request_id} was already resolved")
        pending = self._state["pending"].get(request_id)
        if pending is None:
            raise UnknownRequestError(f"unknown pending approval: {request_id}")
        if reviewed_digest is not None and reviewed_digest != pending["request"]["action_digest"]:
            raise StaleDecisionError("Decision digest does not match the reviewed action")
        if (
            decision == "approve"
            and require_live_owner
            and self.owner_liveness(request_id) is Liveness.DEAD
        ):
            raise OwnerStoppedError(
                "The issuing process stopped; inspect recovery before starting new work"
            )
        decided = create_decision(
            pending,
            decision=decision,
            scope=scope,
            actor=dict(actor),
            sequence=self._state["presenter_sequence"] + 1,
            stream=self._store.presenter_stream,
            decision_id=decision_id,
        )
        machine = ApprovalStore()
        machine.add(pending)
        resolution = machine.decide(
            decided,
            now=self._store.clock(),
            current_action=(
                current_action if current_action is not None else pending["request"]["action"]
            ),
            sequence=self.sequence + 1,
        )
        self.next_presenter_sequence()
        self.next_sequence()
        del self._state["pending"][request_id]
        self._state["decisions"][request_id] = decided
        self._state["resolutions"][request_id] = resolution
        self._state["events"].append(resolution)
        return dict(copy.deepcopy(resolution))

    def cancel(self, request_id: str, *, actor_id: str = "aais.cancel") -> Envelope:
        """Withdraw a pending request without authorizing it.

        Uses a ``cancel``/``once`` decision when the request offers one and
        otherwise ``deny``/``once`` (AAIS requires every request to offer at
        least one of them), so the receipt is ``cancelled`` or ``denied`` rather
        than ``invalid``. If the request is already resolved without approval,
        the existing receipt is returned; if it was approved,
        :class:`~aais.ConflictError` is raised.
        """

        prior = self._state["resolutions"].get(request_id)
        if prior is not None:
            if prior["resolution"]["outcome"] == "approved":
                raise ConflictError(f"request {request_id} was already approved")
            return dict(copy.deepcopy(prior))
        pending = self._state["pending"].get(request_id)
        if pending is None:
            raise UnknownRequestError(f"unknown pending approval: {request_id}")
        offered = {(c["decision"], c["scope"]) for c in pending["request"]["choices"]}
        decision = "cancel" if ("cancel", "once") in offered else "deny"
        return self.decide(
            request_id, decision=decision, scope="once", actor={"id": actor_id, **_POLICY_ACTOR}
        )


# ------------------------------------------------------------------------ store


class FileApprovalStore:
    """Cross-process, durable AAIS approval authority stored in one JSON file.

    ``stream`` names the authority stream written into requested and resolved
    events; ``presenter_stream`` names the stream used for decisions (defaults
    to ``"<stream>.presenter"``). ``owner`` and ``host_id`` default to the
    calling process and host; tests may inject them, along with ``clock``.
    """

    def __init__(
        self,
        path: str | os.PathLike[str],
        *,
        stream: str,
        presenter_stream: str | None = None,
        retention: RetentionPolicy | None = None,
        lock_timeout: float = 10.0,
        max_bytes: int | None = 64 * 1024 * 1024,
        clock: Clock | None = None,
        owner: OwnerIdentity | None = None,
        host_id: str | None = None,
    ) -> None:
        self.path = Path(path).expanduser().absolute()
        self.lock_path = self.path.with_name(self.path.name + ".lock")
        self.marker_path = self.path.with_name(self.path.name + ".recovery-required")
        self.stream = stream
        self.presenter_stream = presenter_stream or f"{stream}.presenter"
        self.retention = retention if retention is not None else RetentionPolicy()
        self.lock_timeout = float(lock_timeout)
        self.max_bytes = max_bytes
        self.clock: Clock = clock or _utc_now
        self._owner = owner
        self._host_id = host_id
        self._cache: tuple[tuple[int, int, int, int], dict[str, Any]] | None = None
        self._parse_count = 0

    # ------------------------------------------------------------ identities

    @property
    def owner(self) -> OwnerIdentity:
        return self._owner or OwnerIdentity.current()

    @property
    def host_id(self) -> str:
        return self._host_id or self.owner.host_id

    # --------------------------------------------------------------- locking

    @contextlib.contextmanager
    def _locked(self) -> Iterator[None]:
        key = str(self.path)
        held = _held_paths()
        if key in held:
            raise StoreError(
                f"nested transaction on {self.path}; reuse the open transaction instead"
            )
        for candidate in (self.path, self.lock_path):
            if candidate.is_symlink():
                raise StoreError(f"approval store paths cannot be symlinks: {candidate}")
        deadline = time.monotonic() + self.lock_timeout
        thread_lock = _thread_lock_for(key)
        if not thread_lock.acquire(timeout=max(0.0, self.lock_timeout)):
            raise LockTimeout(f"timed out waiting for {self.lock_path}")
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0)
            flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
            try:
                descriptor = os.open(self.lock_path, flags, 0o600)
            except OSError as error:
                raise StoreError(f"unable to open lock file {self.lock_path}: {error}") from error
            try:
                if sys.platform == "win32":  # pragma: no cover - msvcrt locks a byte range
                    if os.fstat(descriptor).st_size == 0:
                        os.write(descriptor, b"0")
                delay = 0.001
                while not _try_lock(descriptor):
                    if time.monotonic() >= deadline:
                        raise LockTimeout(
                            f"timed out after {self.lock_timeout:g}s waiting for {self.lock_path}"
                        )
                    time.sleep(delay)
                    delay = min(delay * 2, 0.02)
                held.add(key)
                try:
                    yield
                finally:
                    held.discard(key)
                    with contextlib.suppress(OSError):
                        _unlock(descriptor)
            finally:
                os.close(descriptor)
        finally:
            thread_lock.release()

    # ------------------------------------------------------------- file I/O

    def _signature(self) -> tuple[int, int, int, int] | None:
        try:
            stat = os.stat(self.path)
        except FileNotFoundError:
            return None
        return (stat.st_ino, stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns)

    def _raise_if_marked(self) -> None:
        if not self.marker_path.exists():
            return
        try:
            loaded = json.loads(self.marker_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            loaded = None
        marker: dict[str, Any] = loaded if isinstance(loaded, dict) else {}
        quarantined = marker.get("quarantined_to")
        raise RecoveryRequired(
            self.path,
            reason=str(marker.get("reason") or "recovery marker present"),
            quarantined_to=Path(quarantined) if isinstance(quarantined, str) else None,
            detected_at=str(marker.get("detected_at") or ""),
            sequence_hint=int(marker.get("sequence_hint") or 0),
        )

    def _quarantine(self, raw: bytes, reason: str) -> RecoveryRequired:
        detected = self.clock()
        stamp = detected.astimezone(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        target = self.path.with_name(f"{self.path.name}.corrupt-{stamp}")
        counter = 1
        while target.exists():
            target = self.path.with_name(f"{self.path.name}.corrupt-{stamp}-{counter}")
            counter += 1
        moved: Path | None = target
        try:
            os.replace(self.path, target)
        except OSError:
            moved = None
        _fsync_directory(self.path.parent)
        error = RecoveryRequired(
            self.path,
            reason=reason,
            quarantined_to=moved,
            detected_at=_timestamp(detected),
            sequence_hint=_sequence_hint(raw),
        )
        _atomic_write(self.marker_path, json.dumps(error.to_dict(), sort_keys=True).encode())
        self._cache = None
        return error

    def _load(self, *, mutable: bool = True) -> dict[str, Any]:
        """Read and validate the state. Must be called with the lock held.

        With ``mutable=False`` the cached state object itself is returned and
        the caller must not modify it.
        """

        self._raise_if_marked()
        signature = self._signature()
        if signature is None:
            self._cache = None
            return _empty_state()
        if self._cache is not None and self._cache[0] == signature:
            return copy.deepcopy(self._cache[1]) if mutable else self._cache[1]
        if self.max_bytes is not None and signature[1] > self.max_bytes:
            raise StoreError(
                f"approval state {self.path} is {signature[1]} bytes, above max_bytes="
                f"{self.max_bytes}; tighten the retention policy or raise the limit"
            )
        try:
            raw = self.path.read_bytes()
        except FileNotFoundError:
            return _empty_state()
        except OSError as error:
            raise StoreError(f"could not read {self.path}: {error}") from error
        self._parse_count += 1
        try:
            value = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise self._quarantine(raw, f"invalid JSON: {error}") from error
        schema = value.get("schema") if isinstance(value, dict) else None
        if isinstance(schema, str) and schema.startswith(_SCHEMA_PREFIX) and schema != SCHEMA:
            raise UnsupportedStoreVersion(
                f"{self.path} uses {schema}; this library understands {SCHEMA}. "
                "Upgrade agent-approval-interchange."
            )
        reason = "unrecognized schema" if schema != SCHEMA else _check_state(value)
        if reason is not None:
            raise self._quarantine(raw, reason)
        self._cache = (signature, value)
        return copy.deepcopy(value) if mutable else value

    def _save(self, state: dict[str, Any]) -> None:
        if not state["store_id"]:
            state["store_id"] = uuid.uuid4().hex
        payload = json.dumps(state, sort_keys=True, separators=(",", ":")).encode("utf-8")
        self._remove_stale_temporaries()
        _atomic_write(self.path, payload)
        signature = self._signature()
        self._cache = None if signature is None else (signature, copy.deepcopy(state))

    def _remove_stale_temporaries(self) -> None:
        # Temporary files are only created while the lock is held, so any that
        # exist now were left behind by a crashed writer.
        for leftover in self.path.parent.glob(f".{self.path.name}.*.tmp"):
            with contextlib.suppress(OSError):
                leftover.unlink()

    # ---------------------------------------------------------- transactions

    @contextlib.contextmanager
    def transaction(self) -> Iterator[StoreTransaction]:
        """Hold the cross-process lock for a whole read-modify-write cycle."""

        with self._locked():
            state = self._load()
            tx = StoreTransaction(self, state)
            yield tx
            report = self._compact_state(state, self.clock())
            if tx._dirty or report.changed:
                self._save(state)

    def _read(self) -> dict[str, Any]:
        """Locked read for read-only operations (no copy, never mutated)."""

        with self._locked():
            return self._load(mutable=False)

    # ------------------------------------------------------------ compaction

    def _compact_state(self, state: dict[str, Any], now: datetime) -> CompactionReport:
        policy = self.retention
        resolved: list[tuple[datetime, int, str]] = []
        for request_id, receipt in state["resolutions"].items():
            try:
                at = _parse_time(str(receipt.get("occurred_at")))
            except ValidationError:
                at = now
            resolved.append((at, int(receipt.get("sequence", 0)), request_id))
        resolved.sort()
        doomed: set[str] = set()
        if policy.max_resolved_age is not None:
            cutoff = now - policy.max_resolved_age
            doomed.update(request_id for at, _, request_id in resolved if at < cutoff)
        if policy.max_resolved is not None and len(resolved) > policy.max_resolved:
            excess = len(resolved) - policy.max_resolved
            doomed.update(request_id for _, _, request_id in resolved[:excess])
        for request_id in doomed:
            state["resolutions"].pop(request_id, None)
            state["decisions"].pop(request_id, None)
        stale_owners = [
            key
            for key in state["owners"]
            if key not in state["pending"] and key not in state["resolutions"]
        ]
        for key in stale_owners:
            del state["owners"][key]
        for key in [k for k in state["decisions"] if k not in state["resolutions"]]:
            del state["decisions"][key]
        events: list[Envelope] = state["events"]
        drop = 0
        if policy.max_events is not None and len(events) > policy.max_events:
            drop = len(events) - policy.max_events
        if policy.max_event_age is not None:
            cutoff = now - policy.max_event_age
            while drop < len(events):
                try:
                    at = _parse_time(str(events[drop].get("occurred_at")))
                except ValidationError:
                    break
                if at >= cutoff:
                    break
                drop += 1
        if drop:
            removed = events[:drop]
            del events[:drop]
            state["compacted_through"] = max(
                int(state["compacted_through"]),
                max(int(event["sequence"]) for event in removed),
            )
        return CompactionReport(
            removed_resolved=sorted(doomed),
            removed_events=drop,
            removed_owners=len(stale_owners),
            compacted_through=int(state["compacted_through"]),
        )

    def compact(self) -> CompactionReport:
        """Apply the retention policy now (it also runs on every write)."""

        with self._locked():
            state = self._load()
            report = self._compact_state(state, self.clock())
            if report.changed:
                self._save(state)
            return report

    # ------------------------------------------------------ high-level API

    def add_request(
        self,
        *,
        action: Mapping[str, Any],
        origin: Mapping[str, Any],
        risk: Mapping[str, Any],
        choices: list[Mapping[str, Any]],
        request_id: str | None = None,
        event_id: str | None = None,
        created_at: str | None = None,
        expires_at: str | None = None,
        ttl: float | timedelta | None = None,
        owner: OwnerIdentity | None = None,
    ) -> Envelope:
        """Persist a new pending request; see :meth:`StoreTransaction.add_request`."""

        with self.transaction() as tx:
            return tx.add_request(
                action=action,
                origin=origin,
                risk=risk,
                choices=choices,
                request_id=request_id,
                event_id=event_id,
                created_at=created_at,
                expires_at=expires_at,
                ttl=ttl,
                owner=owner,
            )

    def decide(
        self,
        request_id: str,
        *,
        decision: str,
        scope: str,
        actor: Mapping[str, Any],
        decision_id: str | None = None,
        reviewed_digest: str | None = None,
        current_action: Mapping[str, Any] | None = None,
        require_live_owner: bool = True,
    ) -> Envelope:
        """Resolve a request atomically; see :meth:`StoreTransaction.decide`."""

        with self.transaction() as tx:
            return tx.decide(
                request_id,
                decision=decision,
                scope=scope,
                actor=actor,
                decision_id=decision_id,
                reviewed_digest=reviewed_digest,
                current_action=current_action,
                require_live_owner=require_live_owner,
            )

    def deny(self, request_id: str, *, actor_id: str = "aais.policy") -> Envelope:
        """Deny with a policy actor (for timeouts and policy refusals)."""

        return self.decide(
            request_id, decision="deny", scope="once", actor={"id": actor_id, **_POLICY_ACTOR}
        )

    def cancel(self, request_id: str, *, actor_id: str = "aais.cancel") -> Envelope:
        """Withdraw a request with a policy actor; see :meth:`StoreTransaction.cancel`."""

        with self.transaction() as tx:
            return tx.cancel(request_id, actor_id=actor_id)

    def get_pending(self, request_id: str) -> Envelope | None:
        return _copy_envelope(self._read()["pending"].get(request_id))

    def get_decision(self, request_id: str) -> Envelope | None:
        return _copy_envelope(self._read()["decisions"].get(request_id))

    def get_resolution(self, request_id: str) -> Envelope | None:
        return _copy_envelope(self._read()["resolutions"].get(request_id))

    def get_owner(self, request_id: str) -> OwnerIdentity | None:
        owner = self._read()["owners"].get(request_id)
        return None if owner is None else OwnerIdentity.from_dict(owner)

    def owner_liveness(self, request_id: str) -> Liveness | None:
        owner = self.get_owner(request_id)
        return None if owner is None else owner_liveness(owner, host_id=self.host_id)

    def pending_requests(self) -> list[Envelope]:
        """All pending ``approval.requested`` envelopes in sequence order."""

        pending = self._read()["pending"].values()
        return [copy.deepcopy(item) for item in sorted(pending, key=lambda e: e["sequence"])]

    def get_extension(self, name: str, default: Any = None) -> Any:
        extensions = self._read()["extensions"]
        return copy.deepcopy(extensions[name]) if name in extensions else default

    def snapshot(
        self,
        *,
        now: datetime | None = None,
        include_orphaned: bool = False,
        event_id: str | None = None,
    ) -> Envelope:
        """Return a validated ``approval.snapshot`` of unresolved requests.

        Expired requests are omitted (as in :class:`~aais.ApprovalStore`), and
        so are requests whose owner has stopped unless ``include_orphaned``.
        """

        state = self._read()
        machine = ApprovalStore(last_sequence=int(state["sequence"]))
        for request_id, envelope in sorted(
            state["pending"].items(), key=lambda item: item[1]["sequence"]
        ):
            owner = state["owners"].get(request_id)
            if (
                not include_orphaned
                and owner is not None
                and owner_liveness(OwnerIdentity.from_dict(owner), host_id=self.host_id)
                is Liveness.DEAD
            ):
                continue
            machine.add(validate(envelope))
        return machine.snapshot(stream=self.stream, event_id=event_id, now=now or self.clock())

    def events_after(self, sequence: int) -> EventPage:
        """Events with a sequence greater than ``sequence``, plus a gap flag."""

        state = self._read()
        latest = int(state["sequence"])
        compacted = int(state["compacted_through"])
        return EventPage(
            events=[
                copy.deepcopy(event) for event in state["events"] if event["sequence"] > sequence
            ],
            gap=sequence < compacted or sequence > latest,
            compacted_through=compacted,
            latest_sequence=latest,
            store_id=str(state["store_id"]),
        )

    def recovery(self, *, receipt_limit: int = 100) -> RecoveryReport:
        """Classify pending requests by owner liveness and list recent receipts."""

        state = self._read()
        orphaned: list[str] = []
        unknown: list[str] = []
        unverified: list[str] = []
        for request_id in state["pending"]:
            raw_owner = state["owners"].get(request_id)
            if raw_owner is None:
                unknown.append(request_id)
                continue
            status = owner_liveness(OwnerIdentity.from_dict(raw_owner), host_id=self.host_id)
            if status is Liveness.DEAD:
                orphaned.append(request_id)
            elif status is Liveness.UNKNOWN:
                unverified.append(request_id)
        receipts = sorted(state["resolutions"].values(), key=lambda e: e["sequence"])
        return RecoveryReport(
            orphaned=orphaned,
            unknown_owner=unknown,
            unverified_owner=unverified,
            receipts=copy.deepcopy(receipts[-receipt_limit:] if receipt_limit > 0 else []),
        )

    def cancel_orphaned(self, *, actor_id: str = "aais.recovery") -> list[Envelope]:
        """Cancel every pending request whose owner is known to have stopped."""

        receipts: list[Envelope] = []
        with self.transaction() as tx:
            for request_id in list(tx._state["pending"]):
                if tx.owner_liveness(request_id) is Liveness.DEAD:
                    receipts.append(tx.cancel(request_id, actor_id=actor_id))
        return receipts

    # --------------------------------------------------------------- waiting

    def wait_for_resolution(
        self,
        request_id: str,
        *,
        timeout: float,
        poll_interval: float = 0.1,
        cancelled: threading.Event | None = None,
        refresh_interval: float = 2.0,
    ) -> Envelope | None:
        """Block until ``request_id`` is resolved by any process.

        Returns the ``approval.resolved`` envelope, or ``None`` on timeout or
        when ``cancelled`` is set. The file is re-parsed only when its inode,
        size, mtime, or ctime changes, plus once every ``refresh_interval``
        seconds as protection against filesystems with coarse timestamps.
        Raises :class:`UnknownRequestError` if the request is neither pending
        nor resolved.
        """

        deadline = time.monotonic() + max(0.0, timeout)
        last_signature: tuple[int, int, int, int] | None | bool = False
        last_refresh = float("-inf")
        while True:
            signature = self._signature()
            refresh_due = time.monotonic() - last_refresh >= refresh_interval
            if signature != last_signature or refresh_due:
                if signature == last_signature:
                    self._cache = None  # periodic re-read even if metadata looks unchanged
                state = self._read()
                last_signature = self._cache[0] if self._cache is not None else None
                last_refresh = time.monotonic()
                resolution = state["resolutions"].get(request_id)
                if resolution is not None:
                    return _copy_envelope(resolution)
                if request_id not in state["pending"]:
                    raise UnknownRequestError(f"unknown approval request: {request_id}")
            if cancelled is not None and cancelled.is_set():
                return None
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            pause = min(max(poll_interval, 0.001), remaining)
            if cancelled is not None:
                cancelled.wait(pause)
            else:
                time.sleep(pause)

    # -------------------------------------------------------------- recovery

    def recovery_status(self) -> RecoveryRequired | None:
        """The pending recovery condition, or ``None`` when the store is usable."""

        try:
            self._raise_if_marked()
        except RecoveryRequired as condition:
            return condition
        return None

    def acknowledge_recovery(self, *, start_sequence: int | None = None) -> None:
        """Leave the recovery-required state after an operator has inspected it.

        If the state file was restored by hand it is validated as usual.
        Otherwise a fresh store starts at ``start_sequence`` (default: the
        highest sequence salvaged from the damaged file), so reconnecting
        clients see a gap rather than silently reused sequence numbers.
        """

        with self._locked():
            condition = self.recovery_status()
            if condition is None:
                return
            if self.path.exists():
                self.marker_path.unlink()
                _fsync_directory(self.path.parent)
                self._load()
                return
            base = condition.sequence_hint if start_sequence is None else int(start_sequence)
            if base < 0:
                raise ValueError("start_sequence must be non-negative")
            self._save(_empty_state(sequence=base))
            self.marker_path.unlink()
            _fsync_directory(self.path.parent)

    def import_legacy_state(
        self,
        legacy: Mapping[str, Any],
        *,
        overwrite: bool = False,
    ) -> None:
        """Import a pre-0.2 harness state file (Loro or MagAgent layout).

        Recognized keys are ``sequence``, ``presenter_sequence``, ``pending``,
        ``decisions``, ``resolutions``, ``events``, and ``owners`` (bare PIDs are
        converted to local owners with no start time). Any other key except
        ``schema`` is preserved as an extension of the same name (for example
        MagAgent's ``grants``). Refuses to overwrite existing state unless
        ``overwrite`` is ``True``.
        """

        known = {
            "schema",
            "sequence",
            "presenter_sequence",
            "pending",
            "decisions",
            "resolutions",
            "events",
            "owners",
        }
        with self._locked():
            if not overwrite and (self.path.exists() or self.marker_path.exists()):
                raise StoreError(f"{self.path} already exists; pass overwrite=True to replace it")
            state = _empty_state()
            state["sequence"] = int(legacy.get("sequence", 0))
            state["presenter_sequence"] = int(legacy.get("presenter_sequence", 0))
            for name in ("pending", "decisions", "resolutions"):
                value = legacy.get(name, {})
                if not isinstance(value, Mapping):
                    raise ValidationError(f"legacy {name} must be an object")
                state[name] = copy.deepcopy(dict(value))
            for envelope in state["pending"].values():
                validate(envelope)
            events = legacy.get("events", [])
            if not isinstance(events, list):
                raise ValidationError("legacy events must be a list")
            try:
                state["events"] = sorted(copy.deepcopy(events), key=lambda e: int(e["sequence"]))
            except (TypeError, ValueError, KeyError) as error:
                raise ValidationError("legacy events must carry integer sequences") from error
            if state["events"]:
                state["compacted_through"] = max(0, int(state["events"][0]["sequence"]) - 1)
            else:
                state["compacted_through"] = state["sequence"]
            owners = legacy.get("owners", {})
            if not isinstance(owners, Mapping):
                raise ValidationError("legacy owners must be an object")
            try:
                state["owners"] = {
                    key: (
                        OwnerIdentity(value, None, self.host_id)
                        if _is_int(value)
                        else OwnerIdentity.from_dict(value)
                    ).to_dict()
                    for key, value in owners.items()
                }
            except (TypeError, ValueError) as error:
                raise ValidationError(f"legacy owners are invalid: {error}") from error
            state["extensions"] = {
                key: copy.deepcopy(value) for key, value in legacy.items() if key not in known
            }
            state["store_id"] = uuid.uuid4().hex
            reason = _check_state(state)
            if reason is not None:
                raise ValidationError(f"legacy state is invalid: {reason}")
            if self.marker_path.exists():
                self.marker_path.unlink()
            self._save(state)
