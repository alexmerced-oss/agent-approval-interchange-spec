"""Pluggable persistence for :class:`aais.store.ApprovalAuthority`.

The approval authority keeps all AAIS state logic (sequence allocation,
decisions, retention, replay gaps, owner liveness, corruption handling) in one
place and delegates only locking and storage to a *backend*. A backend stores
one JSON document, the authority state, and offers:

* :meth:`ApprovalStateBackend.transaction`, an exclusive, cross-process
  critical section that yields a :class:`BackendTransaction` for loading and
  saving that document;
* :meth:`ApprovalStateBackend.version`, a cheap change marker used by
  ``wait_for_resolution`` to avoid re-reading unchanged state;
* :meth:`ApprovalStateBackend.exists` and
  :meth:`ApprovalStateBackend.recovery_status`, lock-free inspection.

Two backends ship with the library: :class:`FileBackend` (the default, used by
:class:`aais.store.FileApprovalStore`) and :class:`MemoryBackend` (a reference
implementation for tests and single-process use). Third-party backends, such as
a Postgres row store, implement the two protocols below and can verify
themselves with :mod:`aais.testing`.
"""

from __future__ import annotations

import contextlib
import copy
import json
import os
import sys
import tempfile
import threading
import time
from collections.abc import Hashable, Iterator
from contextlib import AbstractContextManager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from .core import ApprovalError

__all__ = [
    "ApprovalStateBackend",
    "BackendTransaction",
    "CorruptState",
    "FileBackend",
    "LockTimeout",
    "MemoryBackend",
    "RecoveryRequired",
    "StoreError",
]


# ----------------------------------------------------------------------- errors


class StoreError(ApprovalError):
    """The approval store could not complete an operation."""


class LockTimeout(StoreError):
    """Another thread or process held the store lock for too long."""


class RecoveryRequired(StoreError):
    """The stored state was unreadable and has been quarantined.

    The store refuses every operation until
    :meth:`aais.store.ApprovalAuthority.acknowledge_recovery` is called.
    ``path`` is the file path for :class:`FileBackend` and the backend's
    ``description`` for other backends.
    """

    def __init__(
        self,
        path: Path | str,
        *,
        reason: str,
        quarantined_to: Path | str | None,
        detected_at: str,
        sequence_hint: int,
    ) -> None:
        where = f"; the damaged data was moved to {quarantined_to}" if quarantined_to else ""
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


class CorruptState(StoreError):
    """Raised by :meth:`BackendTransaction.load` when stored data cannot be decoded.

    ``raw`` carries the undecodable bytes when available; the authority scans
    them for a sequence number to resume from after recovery.
    """

    def __init__(self, reason: str, raw: bytes | None = None) -> None:
        super().__init__(reason)
        self.reason = reason
        self.raw = raw


# -------------------------------------------------------------------- protocols


@runtime_checkable
class BackendTransaction(Protocol):
    """The locked view of the stored document for one transaction.

    The authority calls these methods only while the enclosing
    :meth:`ApprovalStateBackend.transaction` context is open. It calls
    :meth:`save` at most once and only as the last data operation of a
    transaction (optionally followed by :meth:`clear_recovery`), and never
    raises after it. Writes must be durable when the context exits normally;
    if the context exits with an exception the backend should discard them.
    """

    def recovery_marker(self) -> RecoveryRequired | None:
        """The persistent recovery-required condition, or ``None``."""

    def load(self) -> Any:
        """Return the stored JSON document, or ``None`` if nothing is stored.

        Raise :class:`CorruptState` if the stored data cannot be decoded. The
        returned object may be shared with a cache: the authority never
        mutates it (it deep-copies before changing state).
        """

    def save(self, state: dict[str, Any]) -> None:
        """Replace the stored document with ``state`` (a JSON-serializable dict)."""

    def quarantine(
        self, *, reason: str, detected_at: datetime, sequence_hint: int
    ) -> RecoveryRequired:
        """Preserve the damaged document elsewhere and enter recovery-required.

        Afterwards :meth:`load` returns ``None`` and :meth:`recovery_marker`
        (in this and every later transaction, from any process) returns the
        returned condition until :meth:`clear_recovery`. The authority exits
        the transaction normally after calling this, so the backend commits
        it, and then raises the condition to its caller.
        """

    def clear_recovery(self) -> None:
        """Remove the recovery-required condition (after operator review)."""


@runtime_checkable
class ApprovalStateBackend(Protocol):
    """Persistence and locking for one approval authority's state document."""

    #: Human-readable location used in error messages (a path, a DSN and key).
    description: str

    def transaction(self) -> AbstractContextManager[BackendTransaction]:
        """Hold an exclusive lock across threads and processes for the block.

        Opening a second transaction on the same storage from the same thread
        while one is open must raise :class:`StoreError` (not deadlock).
        Waiting too long for the lock must raise :class:`LockTimeout`.
        """

    def version(self) -> Hashable | None:
        """Cheap, lock-free change marker (it may be ``None`` when nothing is stored).

        It must differ whenever committed state differs. False positives
        (a changed marker for unchanged state) only cost an extra read.
        """

    def invalidate(self) -> None:
        """Drop any cached copy so the next :meth:`BackendTransaction.load` re-reads."""

    def exists(self) -> bool:
        """Whether a state document is stored (lock-free)."""

    def recovery_status(self) -> RecoveryRequired | None:
        """The recovery-required condition, lock-free, or ``None``."""


# ---------------------------------------------------------------- memory backend


class _MemoryTransaction:
    def __init__(self, backend: MemoryBackend) -> None:
        self._backend = backend
        self._staged_state: Any = _UNSET
        self._staged_marker: Any = _UNSET
        self._staged_quarantine: list[Any] = []

    def recovery_marker(self) -> RecoveryRequired | None:
        marker = self._backend._marker if self._staged_marker is _UNSET else self._staged_marker
        return marker if isinstance(marker, RecoveryRequired) else None

    def load(self) -> Any:
        value = self._backend._value if self._staged_state is _UNSET else self._staged_state
        if isinstance(value, _Raw):
            raise CorruptState("stored data is not valid JSON", value.data)
        return value

    def save(self, state: dict[str, Any]) -> None:
        self._staged_state = json.loads(json.dumps(state))

    def quarantine(
        self, *, reason: str, detected_at: datetime, sequence_hint: int
    ) -> RecoveryRequired:
        current = self._backend._value if self._staged_state is _UNSET else self._staged_state
        slot = f"memory:quarantine/{len(self._backend.quarantined) + len(self._staged_quarantine)}"
        self._staged_quarantine.append(current)
        condition = RecoveryRequired(
            self._backend.description,
            reason=reason,
            quarantined_to=slot,
            detected_at=_timestamp(detected_at),
            sequence_hint=sequence_hint,
        )
        self._staged_state = None
        self._staged_marker = condition
        return condition

    def clear_recovery(self) -> None:
        self._staged_marker = None

    def _commit(self) -> None:
        backend = self._backend
        changed = False
        if self._staged_quarantine:
            backend.quarantined.extend(self._staged_quarantine)
        if self._staged_state is not _UNSET:
            backend._value = self._staged_state
            changed = True
        if self._staged_marker is not _UNSET:
            backend._marker = self._staged_marker
            changed = True
        if changed:
            backend._version += 1


class _Unset:
    pass


_UNSET: Any = _Unset()


class _Raw:
    def __init__(self, data: bytes) -> None:
        self.data = data


class MemoryBackend:
    """Reference in-process backend: a JSON document guarded by a thread lock.

    Every :class:`~aais.store.ApprovalAuthority` given the same instance shares
    the same state. It is not shared across processes. Writes are staged and
    applied only when the transaction exits normally. ``quarantined`` keeps
    every document moved aside by a quarantine, oldest first.
    """

    def __init__(self, *, lock_timeout: float = 10.0, description: str = "memory") -> None:
        self.description = description
        self.lock_timeout = float(lock_timeout)
        self.quarantined: list[Any] = []
        self._value: Any = None
        self._marker: RecoveryRequired | None = None
        self._version = 0
        self._lock = threading.Lock()
        self._held = threading.local()

    @contextlib.contextmanager
    def transaction(self) -> Iterator[BackendTransaction]:
        if getattr(self._held, "active", False):
            raise StoreError(
                f"nested transaction on {self.description}; reuse the open transaction instead"
            )
        if not self._lock.acquire(timeout=max(0.0, self.lock_timeout)):
            raise LockTimeout(
                f"timed out after {self.lock_timeout:g}s waiting for {self.description}"
            )
        self._held.active = True
        try:
            tx = _MemoryTransaction(self)
            yield tx
            tx._commit()
        finally:
            self._held.active = False
            self._lock.release()

    def version(self) -> Hashable | None:
        return self._version

    def invalidate(self) -> None:
        return None

    def exists(self) -> bool:
        return self._value is not None

    def recovery_status(self) -> RecoveryRequired | None:
        return self._marker

    def store_raw(self, data: bytes) -> None:
        """Test helper: replace the stored document with undecodable bytes."""

        with self._lock:
            self._value = _Raw(bytes(data))
            self._version += 1


# ------------------------------------------------------------------ file locking

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


def _timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


# ------------------------------------------------------------------ file backend

Signature = tuple[int, int, int, int]


class _FileTransaction:
    def __init__(self, backend: FileBackend) -> None:
        self._backend = backend

    def recovery_marker(self) -> RecoveryRequired | None:
        return self._backend.recovery_status()

    def load(self) -> Any:
        return self._backend._load()

    def save(self, state: dict[str, Any]) -> None:
        self._backend._save(state)

    def quarantine(
        self, *, reason: str, detected_at: datetime, sequence_hint: int
    ) -> RecoveryRequired:
        return self._backend._quarantine(reason, detected_at, sequence_hint)

    def clear_recovery(self) -> None:
        backend = self._backend
        with contextlib.suppress(FileNotFoundError):
            backend.marker_path.unlink()
        _fsync_directory(backend.path.parent)


class FileBackend:
    """One JSON file guarded by ``fcntl.flock`` (POSIX) or ``msvcrt.locking`` (Windows).

    * the lock is ``<file>.lock``; a per-path thread lock serializes threads
      first, and a second transaction on the same path from the same thread
      raises :class:`StoreError`;
    * writes go to a unique ``mkstemp`` file in the same directory, are
      fsynced (``F_FULLFSYNC`` on macOS), atomically replace the state file,
      and the directory is fsynced on POSIX; leftovers from crashed writers
      are removed on the next write;
    * quarantine moves the file to ``<file>.corrupt-<UTC timestamp>`` and
      writes a ``<file>.recovery-required`` marker;
    * parsed state is cached and re-read only when the file's inode, size,
      mtime, or ctime changes; ``parse_count`` counts actual parses.
    """

    def __init__(
        self,
        path: str | os.PathLike[str],
        *,
        lock_timeout: float = 10.0,
        max_bytes: int | None = 64 * 1024 * 1024,
    ) -> None:
        self.path = Path(path).expanduser().absolute()
        self.lock_path = self.path.with_name(self.path.name + ".lock")
        self.marker_path = self.path.with_name(self.path.name + ".recovery-required")
        self.description = str(self.path)
        self.lock_timeout = float(lock_timeout)
        self.max_bytes = max_bytes
        self.parse_count = 0
        self._cache: tuple[Signature, Any] | None = None

    # ------------------------------------------------------------- protocol

    @contextlib.contextmanager
    def transaction(self) -> Iterator[BackendTransaction]:
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
                # On Windows msvcrt locks byte 0. Windows lets a process lock a byte
                # past end-of-file, so the lock file stays empty. Writing a placeholder
                # byte first raced with a process that already held byte 0 locked and
                # failed with PermissionError.
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
                    yield _FileTransaction(self)
                finally:
                    held.discard(key)
                    with contextlib.suppress(OSError):
                        _unlock(descriptor)
            finally:
                os.close(descriptor)
        finally:
            thread_lock.release()

    def version(self) -> Hashable | None:
        return self._signature()

    def invalidate(self) -> None:
        self._cache = None

    def exists(self) -> bool:
        return self.path.exists()

    def recovery_status(self) -> RecoveryRequired | None:
        if not self.marker_path.exists():
            return None
        try:
            loaded = json.loads(self.marker_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            loaded = None
        marker: dict[str, Any] = loaded if isinstance(loaded, dict) else {}
        quarantined = marker.get("quarantined_to")
        return RecoveryRequired(
            self.path,
            reason=str(marker.get("reason") or "recovery marker present"),
            quarantined_to=Path(quarantined) if isinstance(quarantined, str) else None,
            detected_at=str(marker.get("detected_at") or ""),
            sequence_hint=int(marker.get("sequence_hint") or 0),
        )

    # ------------------------------------------------------------ internals

    def _signature(self) -> Signature | None:
        try:
            stat = os.stat(self.path)
        except FileNotFoundError:
            return None
        return (stat.st_ino, stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns)

    def _load(self) -> Any:
        signature = self._signature()
        if signature is None:
            self._cache = None
            return None
        if self._cache is not None and self._cache[0] == signature:
            return self._cache[1]
        if self.max_bytes is not None and signature[1] > self.max_bytes:
            raise StoreError(
                f"approval state {self.path} is {signature[1]} bytes, above max_bytes="
                f"{self.max_bytes}; tighten the retention policy or raise the limit"
            )
        try:
            raw = self.path.read_bytes()
        except FileNotFoundError:
            return None
        except OSError as error:
            raise StoreError(f"could not read {self.path}: {error}") from error
        self.parse_count += 1
        try:
            value = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise CorruptState(f"invalid JSON: {error}", raw) from error
        self._cache = (signature, value)
        return value

    def _save(self, state: dict[str, Any]) -> None:
        payload = json.dumps(state, sort_keys=True, separators=(",", ":")).encode("utf-8")
        # Temporary files are only created while the lock is held, so any that
        # exist now were left behind by a crashed writer.
        for leftover in self.path.parent.glob(f".{self.path.name}.*.tmp"):
            with contextlib.suppress(OSError):
                leftover.unlink()
        _atomic_write(self.path, payload)
        signature = self._signature()
        self._cache = None if signature is None else (signature, copy.deepcopy(state))

    def _quarantine(self, reason: str, detected: datetime, sequence_hint: int) -> RecoveryRequired:
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
        condition = RecoveryRequired(
            self.path,
            reason=reason,
            quarantined_to=moved,
            detected_at=_timestamp(detected),
            sequence_hint=sequence_hint,
        )
        _atomic_write(self.marker_path, json.dumps(condition.to_dict(), sort_keys=True).encode())
        self._cache = None
        return condition
