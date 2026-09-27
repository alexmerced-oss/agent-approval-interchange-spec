"""Conformance kit for third-party approval-state backends.

Subclass :class:`BackendConformance` in your own test suite and implement
:meth:`~BackendConformance.make_backend` (and, where your backend supports
them, the optional hooks). The class name must start with ``Test`` for pytest
to collect it::

    from aais.testing import BackendConformance

    class TestPostgresBackend(BackendConformance):
        def make_backend(self):
            return PostgresBackend(DSN, key=f"conformance-{uuid.uuid4().hex}")

        def reopen_backend(self, backend):
            return PostgresBackend(DSN, key=backend.key)

The kit uses only the standard library. Without pytest, call
:func:`run_backend_conformance` with an instance of your subclass. Skips are
raised as :class:`unittest.SkipTest`, which pytest and unittest both honor.

What the kit checks:

* the backend and its transactions satisfy the runtime-checkable protocols;
* empty storage, save/load round trips, and visibility through a second handle;
* ``version()`` is stable without writes and changes on every commit;
* an exception before ``save`` leaves the stored document unchanged;
* a nested transaction on the same thread raises :class:`~aais.backends.StoreError`;
* transactions exclude each other across threads (a racing counter);
* quarantine persists a recovery condition, empties the live document, and
  ``clear_recovery`` removes it;
* the full :class:`~aais.store.ApprovalAuthority` behavior on top of the
  backend: request/decide/replay/conflict, contiguous sequences, retention
  gaps, cross-thread waiting, extensions, legacy import, unsupported versions,
  and corruption quarantine plus acknowledgement;
* optionally, undecodable stored bytes (``corrupt_backend``) and contiguous
  sequences across real processes (``subprocess_backend_factory``).
"""

from __future__ import annotations

import multiprocessing
import threading
import time
import traceback
import unittest
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from .backends import (
    ApprovalStateBackend,
    BackendTransaction,
    RecoveryRequired,
    StoreError,
)
from .core import ConflictError
from .liveness import Liveness, OwnerIdentity
from .store import (
    ApprovalAuthority,
    RetentionPolicy,
    UnsupportedStoreVersion,
)

__all__ = [
    "BackendConformance",
    "ConformanceReport",
    "run_backend_conformance",
]

BackendFactory = Callable[..., ApprovalStateBackend]

_ACTION: dict[str, Any] = {
    "kind": "tool.call",
    "name": "shell.exec",
    "summary": "Run the syntax check",
    "arguments": {"command": "node --check script.js"},
}
_CHOICES: list[dict[str, Any]] = [
    {"decision": "approve", "scope": "once", "label": "Allow once"},
    {"decision": "deny", "scope": "once", "label": "Deny"},
]
_HUMAN = {"id": "conformance_user", "type": "human", "authenticated_by": "conformance"}


def _request(index: int = 0, **extra: Any) -> dict[str, Any]:
    values: dict[str, Any] = {
        "action": dict(_ACTION, arguments={"command": f"node --check script-{index}.js"}),
        "origin": {"harness": "conformance", "session_id": "s-1"},
        "risk": {"level": "low", "reasons": ["conformance test"]},
        "choices": _CHOICES,
        "ttl": 600,
    }
    values.update(extra)
    return values


def _subprocess_worker(
    factory: BackendFactory,
    args: tuple[Any, ...],
    stream: str,
    count: int,
    barrier: Any,
    results: Any,
) -> None:
    """Run in a spawned child: add ``count`` requests and report their sequences."""

    authority = ApprovalAuthority(factory(*args), stream=stream)
    barrier.wait()
    results.put([authority.add_request(**_request(i))["sequence"] for i in range(count)])


class BackendConformance:
    """Backend conformance tests. Subclass as ``Test...`` and implement the hooks."""

    #: Authority stream used by the authority-level checks.
    stream = "conformance.approvals"
    #: Threads and increments used by the mutual-exclusion check.
    contention_threads = 4
    contention_increments = 15

    # ----------------------------------------------------------------- hooks

    def make_backend(self) -> ApprovalStateBackend:
        """Return a backend over fresh, empty storage (required)."""

        raise NotImplementedError("implement make_backend()")

    def reopen_backend(self, backend: ApprovalStateBackend) -> ApprovalStateBackend:
        """Return another handle to the same storage (default: the same object).

        For a file backend this is a new instance for the same path; for a
        database backend, a new instance with the same connection and key.
        """

        return backend

    def corrupt_backend(self, backend: ApprovalStateBackend, raw: bytes) -> None:
        """Store undecodable ``raw`` bytes as the state (optional)."""

        raise unittest.SkipTest("corrupt_backend() is not implemented for this backend")

    def subprocess_backend_factory(
        self, backend: ApprovalStateBackend
    ) -> tuple[BackendFactory, tuple[Any, ...]] | None:
        """A picklable ``(factory, args)`` that opens the same storage in a child process.

        Return ``None`` (the default) for backends that are not shared across
        processes; the multi-process check is then skipped.
        """

        return None

    def make_authority(self, backend: ApprovalStateBackend, **kwargs: Any) -> ApprovalAuthority:
        return ApprovalAuthority(backend, stream=self.stream, **kwargs)

    # --------------------------------------------------------- setup helpers

    def setup_method(self, method: Any = None) -> None:
        self._cleanups: list[tuple[Callable[..., Any], tuple[Any, ...]]] = []

    def teardown_method(self, method: Any = None) -> None:
        while getattr(self, "_cleanups", None):
            function, args = self._cleanups.pop()
            function(*args)

    def add_cleanup(self, function: Callable[..., Any], *args: Any) -> None:
        """Register a callable to run after the current check (LIFO)."""

        if not hasattr(self, "_cleanups"):
            self._cleanups = []
        self._cleanups.append((function, args))

    # ------------------------------------------------------ backend contract

    def test_backend_satisfies_protocols(self) -> None:
        backend = self.make_backend()
        assert isinstance(backend, ApprovalStateBackend)
        assert isinstance(backend.description, str) and backend.description
        with backend.transaction() as tx:
            assert isinstance(tx, BackendTransaction)

    def test_empty_backend(self) -> None:
        backend = self.make_backend()
        assert backend.exists() is False
        assert backend.recovery_status() is None
        with backend.transaction() as tx:
            assert tx.recovery_marker() is None
            assert tx.load() is None

    def test_save_load_round_trip_and_second_handle(self) -> None:
        backend = self.make_backend()
        document = {"schema": "x", "nested": {"list": [1, 2.5, None, True]}, "text": "é ✓"}
        with backend.transaction() as tx:
            tx.save(dict(document))
        assert backend.exists() is True
        with backend.transaction() as tx:
            assert tx.load() == document
        other = self.reopen_backend(backend)
        assert other.exists() is True
        with other.transaction() as tx:
            assert tx.load() == document

    def test_version_is_stable_without_writes_and_changes_on_commit(self) -> None:
        backend = self.make_backend()
        other = self.reopen_backend(backend)
        seen = [other.version()]
        for index in range(3):
            with backend.transaction() as tx:
                tx.save({"n": index})
            current = other.version()
            assert current not in seen, "version() must change on every commit"
            seen.append(current)
        with backend.transaction() as tx:
            tx.load()
        assert other.version() == seen[-1], "version() must not change without a write"

    def test_exception_before_save_changes_nothing(self) -> None:
        backend = self.make_backend()
        with backend.transaction() as tx:
            tx.save({"n": 1})
        before = backend.version()
        try:
            with backend.transaction() as tx:
                tx.load()
                raise RuntimeError("abort")
        except RuntimeError:
            pass
        assert backend.version() == before
        with backend.transaction() as tx:
            assert tx.load() == {"n": 1}

    def test_nested_transaction_on_same_handle_raises(self) -> None:
        backend = self.make_backend()
        with backend.transaction():
            started = time.monotonic()
            try:
                with backend.transaction():
                    pass
            except StoreError:
                pass
            else:
                raise AssertionError("a nested transaction must raise StoreError")
            assert time.monotonic() - started < 5, "nested transactions must fail fast"

    def test_nested_transaction_on_second_handle_raises(self) -> None:
        backend = self.make_backend()
        other = self.reopen_backend(backend)
        with backend.transaction():
            try:
                with other.transaction():
                    pass
            except StoreError:  # includes LockTimeout
                pass
            else:
                raise AssertionError("a second handle must not enter a held transaction")

    def test_transactions_exclude_each_other_across_threads(self) -> None:
        backend = self.make_backend()
        with backend.transaction() as tx:
            tx.save({"counter": 0})
        errors: list[BaseException] = []

        def work() -> None:
            handle = self.reopen_backend(backend)
            try:
                for _ in range(self.contention_increments):
                    with handle.transaction() as tx:
                        value = tx.load()["counter"]
                        time.sleep(0.001)  # widen the race window
                        tx.save({"counter": value + 1})
            except BaseException as error:  # noqa: BLE001 - reported below
                errors.append(error)

        threads = [threading.Thread(target=work) for _ in range(self.contention_threads)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        assert not errors, errors
        with backend.transaction() as tx:
            final = tx.load()["counter"]
        expected = self.contention_threads * self.contention_increments
        assert final == expected, f"lost updates: {final} != {expected}"

    def test_quarantine_persists_until_cleared(self) -> None:
        backend = self.make_backend()
        with backend.transaction() as tx:
            tx.save({"damaged": True})
        detected = datetime(2026, 9, 27, 15, 4, 5, tzinfo=timezone.utc)
        with backend.transaction() as tx:
            condition = tx.quarantine(reason="test damage", detected_at=detected, sequence_hint=7)
        assert isinstance(condition, RecoveryRequired)
        assert condition.reason == "test damage" and condition.sequence_hint == 7
        for handle in (backend, self.reopen_backend(backend)):
            status = handle.recovery_status()
            assert status is not None
            assert status.reason == "test damage" and status.sequence_hint == 7
        with self.reopen_backend(backend).transaction() as tx:
            marker = tx.recovery_marker()
            assert marker is not None and marker.reason == "test damage"
            assert tx.load() is None, "quarantine must move the damaged document aside"
            tx.clear_recovery()
        assert backend.recovery_status() is None

    # ---------------------------------------------------- authority behavior

    def test_authority_lifecycle(self) -> None:
        backend = self.make_backend()
        authority = self.make_authority(backend)
        requested = authority.add_request(**_request())
        request_id = requested["request"]["id"]
        assert requested["sequence"] == 1
        other = self.make_authority(self.reopen_backend(backend))
        assert other.get_pending(request_id) == requested
        assert other.owner_liveness(request_id) is Liveness.ALIVE
        assert [r["id"] for r in other.snapshot()["snapshot"]["pending"]] == [request_id]
        resolved = other.decide(request_id, decision="approve", scope="once", actor=_HUMAN)
        assert resolved["resolution"]["outcome"] == "approved"
        assert authority.decide(request_id, decision="approve", scope="once", actor=_HUMAN) == (
            resolved
        )
        try:
            authority.decide(request_id, decision="deny", scope="once", actor=_HUMAN)
        except ConflictError:
            pass
        else:
            raise AssertionError("a different decision must conflict")
        page = authority.events_after(0)
        assert [event["sequence"] for event in page.events] == [1, 2]
        assert page.gap is False and page.store_id
        assert authority.recovery().receipts == [resolved]
        assert authority.exists() is True

    def test_authority_sequences_are_contiguous_across_threads(self) -> None:
        backend = self.make_backend()
        sequences: list[int] = []
        guard = threading.Lock()
        errors: list[BaseException] = []

        def work(worker: int) -> None:
            authority = self.make_authority(self.reopen_backend(backend))
            try:
                for index in range(5):
                    value = authority.add_request(**_request(worker * 100 + index))["sequence"]
                    with guard:
                        sequences.append(value)
            except BaseException as error:  # noqa: BLE001 - reported below
                errors.append(error)

        threads = [threading.Thread(target=work, args=(n,)) for n in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        assert not errors, errors
        assert sorted(sequences) == list(range(1, 21))

    def test_authority_retention_reports_gap(self) -> None:
        authority = self.make_authority(
            self.make_backend(), retention=RetentionPolicy(max_events=2, max_resolved=1)
        )
        ids = [authority.add_request(**_request(i))["request"]["id"] for i in range(3)]
        for request_id in ids:
            authority.deny(request_id)
        page = authority.events_after(0)
        assert page.gap is True and len(page.events) == 2
        assert authority.get_resolution(ids[0]) is None
        assert authority.get_resolution(ids[2]) is not None

    def test_authority_wait_for_resolution_across_handles(self) -> None:
        backend = self.make_backend()
        authority = self.make_authority(backend)
        request_id = authority.add_request(**_request())["request"]["id"]
        decider = self.make_authority(self.reopen_backend(backend))

        def decide_later() -> None:
            time.sleep(0.1)
            decider.decide(request_id, decision="deny", scope="once", actor=_HUMAN)

        thread = threading.Thread(target=decide_later)
        thread.start()
        try:
            resolution = authority.wait_for_resolution(request_id, timeout=30, poll_interval=0.01)
        finally:
            thread.join()
        assert resolution is not None and resolution["resolution"]["outcome"] == "denied"

    def test_authority_extensions_share_the_transaction(self) -> None:
        authority = self.make_authority(self.make_backend())
        try:
            with authority.transaction() as tx:
                tx.add_request(**_request())
                tx.set_extension("grants", [{"scope": "session"}])
                raise RuntimeError("abort")
        except RuntimeError:
            pass
        assert authority.get_extension("grants") is None
        assert authority.pending_requests() == []
        with authority.transaction() as tx:
            tx.set_extension("grants", [{"scope": "session"}])
        assert authority.get_extension("grants") == [{"scope": "session"}]

    def test_authority_owner_on_other_host_is_unknown(self) -> None:
        authority = self.make_authority(self.make_backend())
        remote = OwnerIdentity(4_000_000, 1.0, "host-elsewhere")
        request_id = authority.add_request(**_request(), owner=remote)["request"]["id"]
        assert authority.owner_liveness(request_id) is Liveness.UNKNOWN
        assert authority.recovery().unverified_owner == [request_id]

    def test_authority_import_legacy_state(self) -> None:
        source = self.make_authority(self.make_backend())
        live = source.add_request(**_request())
        authority = self.make_authority(self.make_backend())
        authority.import_legacy_state(
            {"sequence": 1, "pending": {live["request"]["id"]: live}, "events": [live]}
        )
        assert authority.get_pending(live["request"]["id"]) == live
        try:
            authority.import_legacy_state({"sequence": 1})
        except StoreError:
            pass
        else:
            raise AssertionError("import must refuse to overwrite existing state")
        assert authority.add_request(**_request(1))["sequence"] == 2

    def test_authority_newer_schema_is_refused_not_quarantined(self) -> None:
        backend = self.make_backend()
        with backend.transaction() as tx:
            tx.save({"schema": "aais.store.v99"})
        authority = self.make_authority(backend)
        try:
            authority.pending_requests()
        except UnsupportedStoreVersion:
            pass
        else:
            raise AssertionError("a newer schema must raise UnsupportedStoreVersion")
        assert backend.recovery_status() is None and backend.exists()

    def test_authority_invalid_state_is_quarantined(self) -> None:
        backend = self.make_backend()
        authority = self.make_authority(backend)
        for index in range(5):
            authority.add_request(**_request(index))
        with backend.transaction() as tx:
            broken = dict(tx.load())
            broken["events"] = {"not": "a list"}
            tx.save(broken)
        for _ in range(2):  # it stays failed; it is never read as empty
            try:
                authority.pending_requests()
            except RecoveryRequired as error:
                assert error.sequence_hint == 5
            else:
                raise AssertionError("invalid state must raise RecoveryRequired")
        other = self.make_authority(self.reopen_backend(backend))
        status = other.recovery_status()
        assert status is not None and "events" in status.reason
        other.acknowledge_recovery()
        assert other.recovery_status() is None
        assert other.events_after(1).gap is True
        assert authority.add_request(**_request(9))["sequence"] == 6

    def test_authority_undecodable_state_is_quarantined(self) -> None:
        backend = self.make_backend()
        self.corrupt_backend(backend, b'{"schema": "aais.store.v1", "sequence": 9, "pend')
        authority = self.make_authority(backend)
        try:
            authority.snapshot()
        except RecoveryRequired as error:
            assert error.sequence_hint == 9
        else:
            raise AssertionError("undecodable state must raise RecoveryRequired")
        try:
            authority.add_request(**_request())
        except RecoveryRequired:
            pass
        else:
            raise AssertionError("the store must stay in recovery until acknowledged")
        authority.acknowledge_recovery(start_sequence=20)
        assert authority.add_request(**_request())["sequence"] == 21

    def test_authority_across_processes(self) -> None:
        backend = self.make_backend()
        spec = self.subprocess_backend_factory(backend)
        if spec is None:
            raise unittest.SkipTest("backend is not shared across processes")
        factory, args = spec
        context = multiprocessing.get_context("spawn")
        processes, count = 3, 5
        barrier = context.Barrier(processes)
        results = context.Queue()
        children = [
            context.Process(
                target=_subprocess_worker,
                args=(factory, args, self.stream, count, barrier, results),
            )
            for _ in range(processes)
        ]
        for child in children:
            child.start()
        sequences = [value for _ in children for value in results.get(timeout=120)]
        for child in children:
            child.join(120)
            assert child.exitcode == 0, f"worker exited with {child.exitcode}"
        assert sorted(sequences) == list(range(1, processes * count + 1))


@dataclass
class ConformanceReport:
    """Outcome of :func:`run_backend_conformance`."""

    passed: list[str] = field(default_factory=list)
    skipped: dict[str, str] = field(default_factory=dict)
    failed: dict[str, str] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return not self.failed


def run_backend_conformance(
    suite: BackendConformance, *, raise_on_failure: bool = True
) -> ConformanceReport:
    """Run every check in ``suite`` without pytest and return a report.

    Raises :class:`AssertionError` listing the failures when
    ``raise_on_failure`` is true (the default).
    """

    report = ConformanceReport()
    for name in sorted(dir(suite)):
        if not name.startswith("test_"):
            continue
        check = getattr(suite, name)
        if not callable(check):
            continue
        suite.setup_method(check)
        try:
            check()
        except unittest.SkipTest as skip:
            report.skipped[name] = str(skip)
        except Exception:  # noqa: BLE001 - collected into the report
            report.failed[name] = traceback.format_exc()
        else:
            report.passed.append(name)
        finally:
            suite.teardown_method(check)
    if raise_on_failure and report.failed:
        details = "\n\n".join(f"{name}:\n{text}" for name, text in report.failed.items())
        raise AssertionError(f"{len(report.failed)} backend conformance check(s) failed\n{details}")
    return report
