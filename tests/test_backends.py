"""The pluggable backend API, its reference backends, and the conformance kit."""

from __future__ import annotations

import contextlib
import os
import shutil
import sys
import tempfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from aais import backends
from aais.backends import (
    ApprovalStateBackend,
    BackendTransaction,
    FileBackend,
    MemoryBackend,
    StoreError,
)
from aais.store import ApprovalAuthority, FileApprovalStore
from aais.testing import BackendConformance, run_backend_conformance


def _scratch_dir() -> str:
    shm = "/dev/shm"
    if sys.platform.startswith("linux") and os.path.isdir(shm) and os.access(shm, os.W_OK):
        return tempfile.mkdtemp(prefix="aais-conformance-", dir=shm)
    return tempfile.mkdtemp(prefix="aais-conformance-")


class TestMemoryBackendConformance(BackendConformance):
    def make_backend(self) -> ApprovalStateBackend:
        return MemoryBackend()

    def corrupt_backend(self, backend: ApprovalStateBackend, raw: bytes) -> None:
        assert isinstance(backend, MemoryBackend)
        backend.store_raw(raw)


class TestFileBackendConformance(BackendConformance):
    def make_backend(self) -> ApprovalStateBackend:
        directory = _scratch_dir()
        self.add_cleanup(shutil.rmtree, directory, True)
        return FileBackend(Path(directory) / "approvals.json")

    def reopen_backend(self, backend: ApprovalStateBackend) -> ApprovalStateBackend:
        assert isinstance(backend, FileBackend)
        return FileBackend(backend.path)

    def corrupt_backend(self, backend: ApprovalStateBackend, raw: bytes) -> None:
        assert isinstance(backend, FileBackend)
        backend.path.write_bytes(raw)

    def subprocess_backend_factory(self, backend: ApprovalStateBackend) -> Any:
        assert isinstance(backend, FileBackend)
        return FileBackend, (str(backend.path),)


class _UnlockedBackend(MemoryBackend):
    """A deliberately broken backend: no mutual exclusion, no nesting check."""

    @contextlib.contextmanager
    def transaction(self) -> Iterator[BackendTransaction]:
        tx = backends._MemoryTransaction(self)
        yield tx
        tx._commit()


class _BrokenSuite(BackendConformance):
    def make_backend(self) -> ApprovalStateBackend:
        return _UnlockedBackend()


def test_kit_runs_without_pytest_and_reports_skips() -> None:
    report = run_backend_conformance(TestMemoryBackendConformance())
    assert report.ok
    assert "test_authority_across_processes" in report.skipped
    assert len(report.passed) >= 18


def test_kit_catches_a_backend_without_locking() -> None:
    report = run_backend_conformance(_BrokenSuite(), raise_on_failure=False)
    assert not report.ok
    assert "test_nested_transaction_on_same_handle_raises" in report.failed
    assert "test_transactions_exclude_each_other_across_threads" in report.failed
    with pytest.raises(AssertionError, match="conformance check"):
        run_backend_conformance(_BrokenSuite())


def test_file_approval_store_is_an_authority_over_a_file_backend(tmp_path: Path) -> None:
    store = FileApprovalStore(tmp_path / "a.json", stream="s", lock_timeout=3, max_bytes=100)
    assert isinstance(store, ApprovalAuthority)
    assert isinstance(store.backend, FileBackend)
    assert store.path == store.backend.path == (tmp_path / "a.json")
    assert store.lock_path.name == "a.json.lock"
    assert store.marker_path.name == "a.json.recovery-required"
    assert (store.lock_timeout, store.max_bytes) == (3.0, 100)
    store.lock_timeout = 5
    store.max_bytes = None
    assert (store.backend.lock_timeout, store.backend.max_bytes) == (5.0, None)
    assert store.exists() is False


def test_authority_over_memory_backend_shares_state_between_instances() -> None:
    backend = MemoryBackend()
    first = ApprovalAuthority(backend, stream="mem.approvals")
    second = ApprovalAuthority(backend, stream="mem.approvals")
    envelope = first.add_request(
        action={"kind": "tool.call", "name": "x", "summary": "y", "arguments": {}},
        origin={"harness": "h", "session_id": "s"},
        risk={"level": "low", "reasons": ["r"]},
        choices=[{"decision": "deny", "scope": "once", "label": "Deny"}],
    )
    assert second.get_pending(envelope["request"]["id"]) == envelope
    assert envelope["stream"] == "mem.approvals"


def test_memory_backend_lock_timeout_and_staged_writes() -> None:
    backend = MemoryBackend(lock_timeout=0.05)
    import threading

    entered, release = threading.Event(), threading.Event()

    def hold() -> None:
        with backend.transaction():
            entered.set()
            release.wait(5)

    thread = threading.Thread(target=hold)
    thread.start()
    try:
        assert entered.wait(5)
        with pytest.raises(backends.LockTimeout), backend.transaction():
            pass
    finally:
        release.set()
        thread.join()
    with pytest.raises(RuntimeError), backend.transaction() as tx:
        tx.save({"a": 1})
        raise RuntimeError("abort")
    assert backend.exists() is False
    assert isinstance(backends.LockTimeout("x"), StoreError)
