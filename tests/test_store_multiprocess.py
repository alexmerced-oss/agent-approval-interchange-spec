"""Real multi-process contention tests using the ``spawn`` start method."""

from __future__ import annotations

import multiprocessing
import time
from pathlib import Path
from typing import Any

import pytest
import store_workers as workers

from aais.liveness import Liveness
from aais.store import LockTimeout, OwnerStoppedError

CTX = multiprocessing.get_context("spawn")
TIMEOUT = 120


def _run(target: Any, arg_sets: list[tuple[Any, ...]]) -> None:
    processes = [CTX.Process(target=target, args=args) for args in arg_sets]
    for process in processes:
        process.start()
    for process in processes:
        process.join(TIMEOUT)
        assert process.exitcode == 0, f"worker exited with {process.exitcode}"


def _drain(results: Any, count: int) -> list[Any]:
    return [results.get(timeout=TIMEOUT) for _ in range(count)]


def test_concurrent_processes_allocate_unique_contiguous_sequences(store_dir: Path) -> None:
    path = str(store_dir / "approvals.json")
    processes, per_process = 4, 15
    barrier = CTX.Barrier(processes)
    results = CTX.Queue()
    arg_sets = [(path, worker, per_process, barrier, results) for worker in range(processes)]
    processes_list = [CTX.Process(target=workers.add_many, args=args) for args in arg_sets]
    for process in processes_list:
        process.start()
    created = [item for batch in _drain(results, processes) for item in batch]
    for process in processes_list:
        process.join(TIMEOUT)
        assert process.exitcode == 0

    sequences = sorted(sequence for _, sequence, _ in created)
    assert sequences == list(range(1, processes * per_process + 1))
    assert len({pid for _, _, pid in created}) == processes

    store = workers.open_store(path)
    pending = store.pending_requests()
    assert len(pending) == processes * per_process
    page = store.events_after(0)
    assert [event["sequence"] for event in page.events] == sequences
    assert page.gap is False
    # Every owning worker has exited, so every request is orphaned now.
    assert sorted(store.recovery().orphaned) == sorted(request_id for request_id, _, _ in created)


def test_concurrent_requests_and_resolutions_never_interleave(store_dir: Path) -> None:
    path = str(store_dir / "approvals.json")
    processes, per_process = 4, 10
    barrier = CTX.Barrier(processes)
    results = CTX.Queue()
    procs = [
        CTX.Process(target=workers.add_and_decide, args=(path, w, per_process, barrier, results))
        for w in range(processes)
    ]
    for process in procs:
        process.start()
    sequences = [value for batch in _drain(results, processes) for value in batch]
    for process in procs:
        process.join(TIMEOUT)
        assert process.exitcode == 0

    total = processes * per_process * 2
    assert sorted(sequences) == list(range(1, total + 1))
    store = workers.open_store(path)
    assert store.pending_requests() == []
    receipts = store.recovery(receipt_limit=1000).receipts
    assert len(receipts) == processes * per_process
    assert {receipt["resolution"]["outcome"] for receipt in receipts} == {"approved"}


def test_racing_different_decisions_resolve_exactly_once(store_dir: Path) -> None:
    path = str(store_dir / "approvals.json")
    store = workers.open_store(path)
    request_id = store.add_request(**workers.request_kwargs())["request"]["id"]
    choices = [("approve", "once"), ("deny", "once"), ("approve", "session")] * 2
    barrier = CTX.Barrier(len(choices))
    results = CTX.Queue()
    _run(
        workers.decide_one,
        [(path, request_id, decision, scope, barrier, results) for decision, scope in choices],
    )
    outcomes = _drain(results, len(choices))
    resolved = [item for item in outcomes if item[0] == "resolved"]
    conflicts = [item for item in outcomes if item[0] == "conflict"]
    winner = (resolved[0][1], resolved[0][2])
    # Every process that chose the winning option replays the same receipt;
    # every other process gets a conflict.
    assert {item[3] for item in resolved} == {store.get_resolution(request_id)["resolution"]["id"]}
    assert all((item[1], item[2]) == winner for item in resolved)
    assert all((item[1], item[2]) != winner for item in conflicts)
    assert len(resolved) == choices.count(winner)
    assert len(store.events_after(0).events) == 2


def test_waiter_in_another_process_sees_resolution(store_dir: Path) -> None:
    path = str(store_dir / "approvals.json")
    store = workers.open_store(path)
    request_id = store.add_request(**workers.request_kwargs())["request"]["id"]
    ready = CTX.Event()
    results = CTX.Queue()
    waiter = CTX.Process(target=workers.wait_for, args=(path, request_id, ready, results))
    waiter.start()
    assert ready.wait(TIMEOUT)
    time.sleep(0.2)
    resolution = store.decide(request_id, decision="deny", scope="once", actor=workers.HUMAN)
    assert results.get(timeout=TIMEOUT) == resolution["resolution"]["id"]
    waiter.join(TIMEOUT)
    assert waiter.exitcode == 0


def test_exited_owner_is_dead_and_blocks_approval(store_dir: Path) -> None:
    path = str(store_dir / "approvals.json")
    results = CTX.Queue()
    _run(workers.add_then_exit, [(path, results)])
    request_id, pid = results.get(timeout=TIMEOUT)
    store = workers.open_store(path)
    owner = store.get_owner(request_id)
    assert owner is not None and owner.pid == pid and owner.process_start_time is not None
    assert store.owner_liveness(request_id) is Liveness.DEAD
    with pytest.raises(OwnerStoppedError):
        store.decide(request_id, decision="approve", scope="once", actor=workers.HUMAN)
    assert store.snapshot()["snapshot"]["pending"] == []
    assert store.recovery().orphaned == [request_id]
    cancelled = store.cancel_orphaned()
    # No cancel choice was offered, so recovery withdraws with deny/once.
    assert [item["resolution"]["outcome"] for item in cancelled] == ["denied"]
    assert store.recovery().orphaned == []


def test_lock_held_by_another_process_times_out(store_dir: Path) -> None:
    path = str(store_dir / "approvals.json")
    ready = CTX.Event()
    holder = CTX.Process(target=workers.hold_lock, args=(path, 3.0, ready))
    holder.start()
    try:
        assert ready.wait(TIMEOUT)
        store = workers.open_store(path, lock_timeout=0.2)
        started = time.monotonic()
        with pytest.raises(LockTimeout):
            store.add_request(**workers.request_kwargs())
        assert time.monotonic() - started < 2.5
    finally:
        holder.join(TIMEOUT)
    assert holder.exitcode == 0
    # Once the holder is gone the lock is free again.
    workers.open_store(path, lock_timeout=5).add_request(**workers.request_kwargs())


def test_crash_inside_transaction_leaves_previous_state(store_dir: Path) -> None:
    path = str(store_dir / "approvals.json")
    store = workers.open_store(path)
    first = store.add_request(**workers.request_kwargs(1))
    ready = CTX.Event()
    crasher = CTX.Process(target=workers.crash_inside_transaction, args=(path, ready))
    crasher.start()
    crasher.join(TIMEOUT)
    assert crasher.exitcode == 3
    assert ready.is_set()
    # The crash released the OS lock and wrote nothing.
    fresh = workers.open_store(path, lock_timeout=5)
    assert [item["request"]["id"] for item in fresh.pending_requests()] == [first["request"]["id"]]
    assert fresh.add_request(**workers.request_kwargs(2))["sequence"] == 2


def test_contention_on_the_real_disk(tmp_path: Path) -> None:
    """Small version of the contention test without tmpfs, with real fsyncs."""

    path = str(tmp_path / "approvals.json")
    barrier = CTX.Barrier(2)
    results = CTX.Queue()
    procs = [
        CTX.Process(target=workers.add_and_decide, args=(path, w, 2, barrier, results))
        for w in range(2)
    ]
    for process in procs:
        process.start()
    sequences = [value for batch in _drain(results, 2) for value in batch]
    for process in procs:
        process.join(TIMEOUT)
        assert process.exitcode == 0
    assert sorted(sequences) == list(range(1, 9))
    assert not list(tmp_path.glob(".approvals.json.*.tmp"))
