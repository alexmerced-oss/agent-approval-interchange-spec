"""Single-process behavior of the durable file store."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest
import store_workers as workers

from aais import ConflictError, ValidationError, action_digest
from aais import backends as backend_module
from aais.liveness import Liveness, OwnerIdentity, current_host_id, process_start_time
from aais.store import (
    SCHEMA,
    FileApprovalStore,
    LockTimeout,
    OwnerStoppedError,
    RecoveryRequired,
    RetentionPolicy,
    StaleDecisionError,
    StoreError,
    UnknownRequestError,
    UnsupportedStoreVersion,
)

HUMAN = workers.HUMAN


class Clock:
    def __init__(self, start: datetime) -> None:
        self.now = start

    def __call__(self) -> datetime:
        return self.now

    def advance(self, **kwargs: float) -> None:
        self.now += timedelta(**kwargs)


def make(path: Path, **kwargs: Any) -> FileApprovalStore:
    return FileApprovalStore(path / "approvals.json", stream="test.approvals", **kwargs)


def dead_pid() -> int:
    process = subprocess.Popen([sys.executable, "-c", "pass"])
    process.wait()
    return process.pid


def add(store: FileApprovalStore, index: int = 0, **extra: Any) -> dict[str, Any]:
    return store.add_request(**workers.request_kwargs(index, **extra))


# ----------------------------------------------------------------- lifecycle


def test_add_and_decide_round_trip(store_dir: Path) -> None:
    store = make(store_dir)
    requested = add(store)
    request_id = requested["request"]["id"]
    assert requested["sequence"] == 1
    assert requested["stream"] == "test.approvals"
    assert store.get_pending(request_id) == requested
    assert store.get_owner(request_id) == OwnerIdentity.current()

    resolved = store.decide(request_id, decision="approve", scope="session", actor=HUMAN)
    body = resolved["resolution"]
    assert body["outcome"] == "approved" and body["effective_scope"] == "session"
    assert resolved["sequence"] == 2
    decision = store.get_decision(request_id)
    assert decision is not None
    assert decision["stream"] == "test.approvals.presenter"
    assert decision["sequence"] == 1
    assert store.get_pending(request_id) is None
    assert store.get_resolution(request_id) == resolved
    assert store.pending_requests() == []


def test_decide_replays_identical_choice_and_rejects_different_one(store_dir: Path) -> None:
    store = make(store_dir)
    request_id = add(store)["request"]["id"]
    first = store.decide(request_id, decision="deny", scope="once", actor=HUMAN)
    assert store.decide(request_id, decision="deny", scope="once", actor=HUMAN) == first
    with pytest.raises(ConflictError):
        store.decide(request_id, decision="approve", scope="once", actor=HUMAN)
    assert len(store.events_after(0).events) == 2


def test_unknown_request_and_duplicate_ids(store_dir: Path) -> None:
    store = make(store_dir)
    with pytest.raises(UnknownRequestError):
        store.decide("apr_missing", decision="deny", scope="once", actor=HUMAN)
    with pytest.raises(ValueError):  # compatible with callers that catch ValueError
        store.cancel("apr_missing")
    add(store, request_id="apr_fixed")
    with pytest.raises(ConflictError):
        add(store, request_id="apr_fixed")


def test_reviewed_digest_mismatch_is_stale(store_dir: Path) -> None:
    store = make(store_dir)
    requested = add(store)
    request_id = requested["request"]["id"]
    with pytest.raises(StaleDecisionError):
        store.decide(
            request_id, decision="approve", scope="once", actor=HUMAN, reviewed_digest="sha256:0"
        )
    resolved = store.decide(
        request_id,
        decision="approve",
        scope="once",
        actor=HUMAN,
        reviewed_digest=requested["request"]["action_digest"],
    )
    assert resolved["resolution"]["outcome"] == "approved"


def test_changed_current_action_resolves_stale(store_dir: Path) -> None:
    store = make(store_dir)
    request_id = add(store)["request"]["id"]
    changed = dict(workers.ACTION, arguments={"command": "rm -rf /"})
    resolved = store.decide(
        request_id, decision="approve", scope="once", actor=HUMAN, current_action=changed
    )
    assert resolved["resolution"]["outcome"] == "stale"


def test_expired_request_resolves_expired(store_dir: Path) -> None:
    clock = Clock(datetime(2026, 9, 27, 12, tzinfo=timezone.utc))
    store = make(store_dir, clock=clock)
    request_id = add(store, ttl=60)["request"]["id"]
    assert store.snapshot()["snapshot"]["pending"][0]["id"] == request_id
    clock.advance(seconds=61)
    assert store.snapshot()["snapshot"]["pending"] == []
    resolved = store.decide(request_id, decision="approve", scope="once", actor=HUMAN)
    assert resolved["resolution"]["outcome"] == "expired"


def test_cancel_prefers_offered_cancel_then_deny(store_dir: Path) -> None:
    store = make(store_dir)
    with_cancel = add(
        store,
        1,
        choices=[
            {"decision": "approve", "scope": "once", "label": "Allow"},
            {"decision": "cancel", "scope": "once", "label": "Cancel"},
        ],
    )["request"]["id"]
    deny_only = add(store, 2)["request"]["id"]
    cancelled = store.cancel(with_cancel)
    assert cancelled["resolution"]["outcome"] == "cancelled"
    assert store.cancel(with_cancel) == cancelled
    assert store.cancel(deny_only)["resolution"]["outcome"] == "denied"
    approved = add(store, 3)["request"]["id"]
    store.decide(approved, decision="approve", scope="once", actor=HUMAN)
    with pytest.raises(ConflictError):
        store.cancel(approved)
    assert store.deny(add(store, 4)["request"]["id"])["resolution"]["outcome"] == "denied"


# ------------------------------------------------------------------ owners


def test_reused_pid_with_different_start_time_blocks_approval(store_dir: Path) -> None:
    store = make(store_dir)
    me = OwnerIdentity.current()
    assert me.process_start_time is not None
    impostor = OwnerIdentity(me.pid, me.process_start_time - 3600, me.host_id)
    request_id = add(store, owner=impostor)["request"]["id"]
    assert store.owner_liveness(request_id) is Liveness.DEAD
    with pytest.raises(OwnerStoppedError):
        store.decide(request_id, decision="approve", scope="once", actor=HUMAN)
    # Denial and cancellation do not need a live owner.
    assert store.deny(request_id)["resolution"]["outcome"] == "denied"


def test_dead_owner_is_orphaned_and_hidden_from_snapshot(store_dir: Path) -> None:
    store = make(store_dir)
    ghost = OwnerIdentity(dead_pid(), None, current_host_id())
    orphan = add(store, 1, owner=ghost)["request"]["id"]
    live = add(store, 2)["request"]["id"]
    assert [item["id"] for item in store.snapshot()["snapshot"]["pending"]] == [live]
    assert {
        item["id"] for item in store.snapshot(include_orphaned=True)["snapshot"]["pending"]
    } == {orphan, live}
    report = store.recovery()
    assert report.orphaned == [orphan]
    assert report.to_dict()["guidance"].startswith("Stopped owners")
    resolved = store.decide(
        orphan, decision="approve", scope="once", actor=HUMAN, require_live_owner=False
    )
    assert resolved["resolution"]["outcome"] == "approved"


def test_owner_on_another_host_is_unknown_not_dead(store_dir: Path) -> None:
    store = make(store_dir)
    remote = OwnerIdentity(dead_pid(), 1.0, "host-elsewhere")
    request_id = add(store, owner=remote)["request"]["id"]
    assert store.owner_liveness(request_id) is Liveness.UNKNOWN
    report = store.recovery()
    assert report.unverified_owner == [request_id] and report.orphaned == []
    assert store.snapshot()["snapshot"]["pending"][0]["id"] == request_id
    assert store.cancel_orphaned() == []
    resolved = store.decide(request_id, decision="approve", scope="once", actor=HUMAN)
    assert resolved["resolution"]["outcome"] == "approved"


def test_injected_host_id_and_owner(store_dir: Path) -> None:
    owner = OwnerIdentity(os.getpid(), process_start_time(os.getpid()), "host-test")
    store = make(store_dir, owner=owner, host_id="host-test")
    request_id = add(store)["request"]["id"]
    assert store.get_owner(request_id) == owner
    assert store.owner_liveness(request_id) is Liveness.ALIVE
    assert make(store_dir).owner_liveness(request_id) is Liveness.UNKNOWN


# ------------------------------------------------------------- durability


def test_writes_use_unique_same_directory_temp_files_and_fsync(
    store_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    temp_dirs: list[str] = []
    real_mkstemp = backend_module.tempfile.mkstemp

    def spy_mkstemp(*args: Any, **kwargs: Any) -> tuple[int, str]:
        temp_dirs.append(str(kwargs.get("dir")))
        return real_mkstemp(*args, **kwargs)

    synced: list[str] = []
    real_fsync = os.fsync

    def spy_fsync(descriptor: int) -> None:
        synced.append(os.readlink(f"/proc/self/fd/{descriptor}") if os.path.isdir("/proc") else "?")
        real_fsync(descriptor)

    monkeypatch.setattr(backend_module.tempfile, "mkstemp", spy_mkstemp)
    monkeypatch.setattr(backend_module.os, "fsync", spy_fsync)
    store = make(store_dir)
    add(store)
    assert temp_dirs == [str(store.path.parent)]
    if os.path.isdir("/proc"):
        assert any(".approvals.json." in name for name in synced)  # the temp file
        assert str(store.path.parent) in synced  # the directory entry
    assert not list(store.path.parent.glob(".approvals.json.*.tmp"))
    assert json.loads(store.path.read_text())["schema"] == SCHEMA
    if os.name == "posix":
        assert store.path.stat().st_mode & 0o777 == 0o600


def test_failed_write_leaves_previous_state_and_no_temp_file(
    store_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = make(store_dir)
    first = add(store, 1)
    before = store.path.read_bytes()

    def broken_replace(*_args: Any) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(backend_module.os, "replace", broken_replace)
    with pytest.raises(OSError, match="disk full"):
        add(store, 2)
    monkeypatch.undo()
    assert store.path.read_bytes() == before
    assert not list(store.path.parent.glob(".approvals.json.*.tmp"))
    assert [item["request"]["id"] for item in store.pending_requests()] == [first["request"]["id"]]


def test_stale_temp_files_from_crashed_writers_are_removed(store_dir: Path) -> None:
    store = make(store_dir)
    add(store)
    leftover = store.path.parent / ".approvals.json.crashed.tmp"
    leftover.write_text("partial")
    add(store, 1)
    assert not leftover.exists()


def test_exception_inside_transaction_writes_nothing(store_dir: Path) -> None:
    store = make(store_dir)
    add(store)
    before = store.path.read_bytes()
    with pytest.raises(RuntimeError), store.transaction() as tx:
        tx.add_request(**workers.request_kwargs(5))
        tx.set_extension("grants", [{"x": 1}])
        raise RuntimeError("abort")
    assert store.path.read_bytes() == before


def test_nested_transaction_is_refused(store_dir: Path) -> None:
    store = make(store_dir)
    other = make(store_dir)
    with store.transaction(), pytest.raises(StoreError, match="nested"), other.transaction():
        pass


def test_extensions_share_the_transaction(store_dir: Path) -> None:
    store = make(store_dir)
    with store.transaction() as tx:
        requested = tx.add_request(**workers.request_kwargs())
        tx.set_extension("grants", [{"action_digest": requested["request"]["action_digest"]}])
        with pytest.raises(TypeError):
            tx.set_extension("bad", {1, 2})
    assert store.get_extension("grants") == [
        {"action_digest": action_digest(requested["request"]["action"])}
    ]
    assert store.get_extension("missing", "default") == "default"
    with store.transaction() as tx:
        assert tx.get_extension("grants")
        tx.delete_extension("grants")
    assert store.get_extension("grants") is None


def test_threads_with_separate_instances_serialize(store_dir: Path) -> None:
    errors: list[BaseException] = []
    sequences: list[int] = []
    guard = threading.Lock()

    def work(worker: int) -> None:
        try:
            store = make(store_dir)
            for index in range(10):
                envelope = add(store, worker * 100 + index)
                with guard:
                    sequences.append(envelope["sequence"])
        except BaseException as error:  # noqa: BLE001  # pragma: no cover - reported below
            errors.append(error)

    threads = [threading.Thread(target=work, args=(n,)) for n in range(6)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert not errors
    assert sorted(sequences) == list(range(1, 61))


def test_lock_timeout_between_threads(store_dir: Path) -> None:
    store = make(store_dir)
    impatient = make(store_dir, lock_timeout=0.05)
    entered = threading.Event()
    release = threading.Event()

    def hold() -> None:
        with store.transaction():
            entered.set()
            release.wait(5)

    thread = threading.Thread(target=hold)
    thread.start()
    try:
        assert entered.wait(5)
        with pytest.raises(LockTimeout):
            add(impatient)
    finally:
        release.set()
        thread.join()


@pytest.mark.skipif(not hasattr(os, "symlink") or os.name == "nt", reason="POSIX symlinks")
def test_symlinked_state_is_refused(store_dir: Path) -> None:
    target = store_dir / "elsewhere.json"
    target.write_text("{}")
    (store_dir / "approvals.json").symlink_to(target)
    with pytest.raises(StoreError, match="symlink"):
        add(make(store_dir))


def test_max_bytes_is_an_error_not_a_quarantine(store_dir: Path) -> None:
    store = make(store_dir)
    add(store)
    small = make(store_dir, max_bytes=10)
    with pytest.raises(StoreError, match="max_bytes") as raised:
        small.pending_requests()
    assert not isinstance(raised.value, RecoveryRequired)
    assert store.path.exists()


# --------------------------------------------------------------- corruption


@pytest.mark.parametrize(
    ("content", "reason"),
    [
        (b'{"schema": "aais.store.v1", "sequence": 4', "invalid JSON"),
        (b"\xff\xfe not utf8", "invalid JSON"),
        (b"[]", "unrecognized schema"),
        (b'{"schema": "aais.store.v1", "sequence": "x"}', "sequence"),
    ],
)
def test_corrupt_state_is_quarantined_and_requires_recovery(
    store_dir: Path, content: bytes, reason: str
) -> None:
    clock = Clock(datetime(2026, 9, 27, 15, 4, 5, tzinfo=timezone.utc))
    store = make(store_dir, clock=clock)
    store.path.write_bytes(content)
    with pytest.raises(RecoveryRequired) as raised:
        store.pending_requests()
    error = raised.value
    assert reason in error.reason
    assert error.quarantined_to == store.path.with_name("approvals.json.corrupt-20260927T150405Z")
    assert error.quarantined_to.read_bytes() == content
    assert not store.path.exists()
    # The store never falls back to an empty state: every call keeps failing.
    for call in (
        lambda: add(store),
        lambda: store.snapshot(),
        lambda: store.events_after(0),
        lambda: store.recovery(),
        lambda: store.wait_for_resolution("apr_x", timeout=0),
        lambda: make(store_dir).pending_requests(),
    ):
        with pytest.raises(RecoveryRequired):
            call()
    status = store.recovery_status()
    assert status is not None and status.to_dict()["quarantined_to"].endswith("150405Z")


def test_second_quarantine_in_the_same_second_gets_a_unique_name(store_dir: Path) -> None:
    clock = Clock(datetime(2026, 9, 27, 15, 4, 5, tzinfo=timezone.utc))
    store = make(store_dir, clock=clock)
    for expected in ("corrupt-20260927T150405Z", "corrupt-20260927T150405Z-1"):
        store.path.write_text("not json")
        with pytest.raises(RecoveryRequired) as raised:
            store.pending_requests()
        assert raised.value.quarantined_to is not None
        assert raised.value.quarantined_to.name.endswith(expected)
        store.acknowledge_recovery()


def test_acknowledge_recovery_starts_after_salvaged_sequence(store_dir: Path) -> None:
    store = make(store_dir)
    for index in range(3):
        add(store, index)
    damaged = store.path.read_bytes()[:-40]
    store.path.write_bytes(damaged)
    with pytest.raises(RecoveryRequired) as raised:
        store.pending_requests()
    assert raised.value.sequence_hint == 3
    assert store.recovery_status() is not None
    store.acknowledge_recovery()
    assert store.recovery_status() is None
    page = store.events_after(1)
    assert page.gap is True  # the client missed events that are gone
    assert store.events_after(3).gap is False
    assert add(store, 9)["sequence"] == 4
    store.acknowledge_recovery()  # no-op when healthy


def test_acknowledge_recovery_with_explicit_start_and_restored_file(store_dir: Path) -> None:
    store = make(store_dir)
    add(store)
    good = store.path.read_bytes()
    store.path.write_text("garbage")
    with pytest.raises(RecoveryRequired):
        store.pending_requests()
    # An operator restores a known-good copy, then acknowledges.
    store.path.write_bytes(good)
    store.acknowledge_recovery()
    assert len(store.pending_requests()) == 1

    store.path.write_text("garbage")
    with pytest.raises(RecoveryRequired):
        store.pending_requests()
    with pytest.raises(ValueError):
        store.acknowledge_recovery(start_sequence=-1)
    store.acknowledge_recovery(start_sequence=100)
    assert add(store, 2)["sequence"] == 101


def test_newer_schema_is_not_quarantined(store_dir: Path) -> None:
    store = make(store_dir)
    store.path.write_text(json.dumps({"schema": "aais.store.v9"}))
    with pytest.raises(UnsupportedStoreVersion):
        store.pending_requests()
    assert store.path.exists()
    assert store.recovery_status() is None


def test_unreadable_marker_still_blocks(store_dir: Path) -> None:
    store = make(store_dir)
    store.marker_path.write_text("{not json")
    with pytest.raises(RecoveryRequired):
        store.pending_requests()


# ---------------------------------------------------------------- retention


def test_retention_by_count_compacts_resolved_entries_and_owners(store_dir: Path) -> None:
    store = make(store_dir, retention=RetentionPolicy(max_resolved=2, max_events=None))
    ids = []
    for index in range(4):
        request_id = add(store, index)["request"]["id"]
        store.decide(request_id, decision="deny", scope="once", actor=HUMAN)
        ids.append(request_id)
    keep = add(store, 9)["request"]["id"]
    state = json.loads(store.path.read_text())
    assert set(state["resolutions"]) == set(ids[2:])
    assert set(state["decisions"]) == set(ids[2:])
    assert set(state["owners"]) == {*ids[2:], keep}
    assert set(state["pending"]) == {keep}
    with pytest.raises(UnknownRequestError):
        store.decide(ids[0], decision="deny", scope="once", actor=HUMAN)


def test_retention_by_age_uses_resolution_time(store_dir: Path) -> None:
    clock = Clock(datetime(2026, 9, 1, tzinfo=timezone.utc))
    policy = RetentionPolicy(
        max_resolved=None,
        max_resolved_age=timedelta(days=7),
        max_events=None,
        max_event_age=timedelta(days=7),
    )
    store = make(store_dir, clock=clock, retention=policy)
    old = add(store, 1)["request"]["id"]
    store.decide(old, decision="deny", scope="once", actor=HUMAN)
    clock.advance(days=5)
    pending_old = add(store, 2, ttl=30 * 86400)["request"]["id"]
    clock.advance(days=3)
    report = store.compact()
    assert report.removed_resolved == [old]
    assert report.removed_events == 2
    assert report.compacted_through == 2
    assert store.get_resolution(old) is None
    assert store.get_pending(pending_old) is not None  # pending is never compacted
    assert store.compact().changed is False


def test_event_log_compaction_reports_gap(store_dir: Path) -> None:
    store = make(store_dir, retention=RetentionPolicy(max_events=3))
    for index in range(5):
        add(store, index)
    page = store.events_after(0)
    assert [event["sequence"] for event in page.events] == [3, 4, 5]
    assert page.gap is True and page.compacted_through == 2 and page.latest_sequence == 5
    assert store.events_after(1).gap is True
    assert store.events_after(2).gap is False
    assert [event["sequence"] for event in store.events_after(4).events] == [5]
    assert store.events_after(5).to_dict()["events"] == []
    ahead = store.events_after(50)
    assert ahead.gap is True  # caller is ahead of this store: it was reset
    assert ahead.store_id == page.store_id


def test_retention_policy_validation() -> None:
    with pytest.raises(ValueError):
        RetentionPolicy(max_resolved=-1)
    with pytest.raises(ValueError):
        RetentionPolicy(max_event_age=timedelta(seconds=-1))


# ----------------------------------------------------------------- waiting


def test_wait_for_resolution_skips_reparsing_unchanged_file(store_dir: Path) -> None:
    store = make(store_dir)
    request_id = add(store)["request"]["id"]
    waiter = make(store_dir)
    parses_before = waiter.backend.parse_count
    assert waiter.wait_for_resolution(request_id, timeout=0.3, poll_interval=0.01) is None
    # One parse for the first look; ~30 polls of an unchanged file add none.
    assert waiter.backend.parse_count - parses_before == 1

    def resolve_later() -> None:
        time.sleep(0.1)
        make(store_dir).decide(request_id, decision="deny", scope="once", actor=HUMAN)

    thread = threading.Thread(target=resolve_later)
    thread.start()
    resolution = waiter.wait_for_resolution(request_id, timeout=5, poll_interval=0.01)
    thread.join()
    assert resolution is not None and resolution["resolution"]["outcome"] == "denied"
    assert waiter.backend.parse_count - parses_before == 2


def test_wait_for_resolution_periodic_refresh(store_dir: Path) -> None:
    store = make(store_dir)
    request_id = add(store)["request"]["id"]
    before = store.backend.parse_count
    store.backend.invalidate()
    store.wait_for_resolution(request_id, timeout=0.25, poll_interval=0.01, refresh_interval=0.1)
    assert 2 <= store.backend.parse_count - before <= 4


def test_wait_for_resolution_cancel_unknown_and_resolved(store_dir: Path) -> None:
    store = make(store_dir)
    request_id = add(store)["request"]["id"]
    cancelled = threading.Event()
    cancelled.set()
    started = time.monotonic()
    assert store.wait_for_resolution(request_id, timeout=30, cancelled=cancelled) is None
    assert time.monotonic() - started < 1
    with pytest.raises(UnknownRequestError):
        store.wait_for_resolution("apr_nope", timeout=1)
    resolved = store.deny(request_id)
    assert store.wait_for_resolution(request_id, timeout=0) == resolved


# ------------------------------------------------------------------ legacy


def test_import_legacy_loro_or_magagent_state(store_dir: Path) -> None:
    source = make(store_dir / "source")
    live = add(source, 1)
    resolved_id = add(source, 2)["request"]["id"]
    receipt = source.decide(resolved_id, decision="deny", scope="once", actor=HUMAN)
    with source.transaction() as tx:
        decision = tx.get_decision(resolved_id)
    legacy = {
        "schema": "magent.aais-store.v1",
        "sequence": 3,
        "presenter_sequence": 1,
        "pending": {live["request"]["id"]: live},
        "decisions": {resolved_id: decision},
        "resolutions": {resolved_id: receipt},
        "grants": [{"action_digest": "sha256:abc", "scope": "persistent"}],
        "events": [live, receipt],
        "owners": {live["request"]["id"]: os.getpid(), resolved_id: dead_pid()},
    }
    store = make(store_dir)
    store.import_legacy_state(legacy)
    assert store.get_extension("grants") == legacy["grants"]
    assert store.get_owner(live["request"]["id"]) == OwnerIdentity(
        os.getpid(), None, current_host_id()
    )
    assert store.owner_liveness(live["request"]["id"]) is Liveness.ALIVE
    assert store.decide(resolved_id, decision="deny", scope="once", actor=HUMAN) == receipt
    assert store.events_after(0).gap is False
    assert add(store, 3)["sequence"] == 4
    with pytest.raises(StoreError, match="already exists"):
        store.import_legacy_state(legacy)
    store.import_legacy_state({"sequence": 7}, overwrite=True)
    assert store.events_after(0).latest_sequence == 7


def test_import_legacy_rejects_bad_shapes(store_dir: Path) -> None:
    store = make(store_dir)
    for legacy in (
        {"pending": []},
        {"events": {}},
        {"events": [{"no": "sequence"}]},
        {"owners": []},
        {"owners": {"apr_1": "pid"}},
        {"owners": {"apr_1": {"pid": 0, "host_id": "h"}}},
    ):
        with pytest.raises(ValidationError):
            store.import_legacy_state(legacy)
    assert not store.path.exists()


# --------------------------------------------------------- Windows locking


def test_windows_lock_path_uses_msvcrt_byte_range(
    store_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Exercise the msvcrt branch with a fake module (real Windows runs in CI)."""

    calls: list[tuple[int, int]] = []
    contended = {"value": True}

    class FakeMsvcrt:
        LK_NBLCK = 2
        LK_UNLCK = 0

        @staticmethod
        def locking(descriptor: int, mode: int, size: int) -> None:
            assert os.lseek(descriptor, 0, os.SEEK_CUR) == 0
            calls.append((mode, size))
            if mode == FakeMsvcrt.LK_NBLCK and contended["value"]:
                contended["value"] = False
                raise OSError("locked")

    monkeypatch.setitem(sys.modules, "msvcrt", FakeMsvcrt)
    monkeypatch.setattr(backend_module.sys, "platform", "win32")
    descriptor = os.open(store_dir / "fake.lock", os.O_RDWR | os.O_CREAT)
    try:
        assert backend_module._try_lock(descriptor) is False
        assert backend_module._try_lock(descriptor) is True
        backend_module._unlock(descriptor)
    finally:
        os.close(descriptor)
    assert calls == [(2, 1), (2, 1), (0, 1)]


def _valid_state(store_dir: Path) -> dict[str, Any]:
    store = make(store_dir / "template")
    request_id = add(store)["request"]["id"]
    store.deny(add(store, 1)["request"]["id"])
    state: dict[str, Any] = json.loads(store.path.read_text())
    assert request_id in state["pending"]
    return state


@pytest.mark.parametrize(
    ("mutate", "reason"),
    [
        (lambda s: s.pop("store_id"), "store_id"),
        (lambda s: s.update(pending=[]), "pending is not an object"),
        (lambda s: s.update(events={}), "events is not a list"),
        (lambda s: s.update(compacted_through=-1), "compacted_through"),
        (
            lambda s: s["pending"].update({"apr_other": next(iter(s["pending"].values()))}),
            "pending entry",
        ),
        (lambda s: s["resolutions"].update({"apr_r": {"sequence": "1"}}), "resolutions entry"),
        (lambda s: s["owners"].update({"apr_o": {"pid": -4, "host_id": "h"}}), "owner for"),
        (lambda s: s["events"].append({"sequence": None}), "malformed event"),
    ],
)
def test_structurally_invalid_state_is_quarantined(
    store_dir: Path, mutate: Any, reason: str
) -> None:
    state = _valid_state(store_dir)
    mutate(state)
    store = make(store_dir)
    store.path.write_text(json.dumps(state))
    with pytest.raises(RecoveryRequired, match=reason):
        store.snapshot()
    assert not store.path.exists()


def test_transaction_accessors(store_dir: Path) -> None:
    store = make(store_dir)
    pending_id = add(store)["request"]["id"]
    resolved_id = add(store, 1)["request"]["id"]
    store.deny(resolved_id)
    expected_pending = store.get_pending(pending_id)
    expected_resolution = store.get_resolution(resolved_id)
    store_id = json.loads(store.path.read_text())["store_id"]
    with store.transaction() as tx:
        assert tx.store_id == store_id
        assert list(tx.pending()) == [pending_id]
        assert tx.get_pending(pending_id) == expected_pending
        assert tx.get_resolution(resolved_id) == expected_resolution
        assert tx.get_owner(pending_id) == OwnerIdentity.current()
        assert tx.owner_liveness(pending_id) is Liveness.ALIVE
        assert tx.sequence == 3
        assert tx.next_sequence() == 4  # a caller may reserve sequences for its own events
    assert store.events_after(0).latest_sequence == 4


def test_pending_request_without_owner_is_reported(store_dir: Path) -> None:
    source = make(store_dir / "source")
    requested = add(source)
    store = make(store_dir)
    store.import_legacy_state(
        {"sequence": 1, "pending": {requested["request"]["id"]: requested}, "events": [requested]}
    )
    report = store.recovery()
    assert report.unknown_owner == [requested["request"]["id"]]
    assert store.owner_liveness(requested["request"]["id"]) is None
    assert report.to_dict()["unknown_owner"] == report.unknown_owner


def test_wait_with_unset_cancel_event_times_out(store_dir: Path) -> None:
    store = make(store_dir)
    request_id = add(store)["request"]["id"]
    event = threading.Event()
    assert store.wait_for_resolution(request_id, timeout=0.05, cancelled=event) is None
