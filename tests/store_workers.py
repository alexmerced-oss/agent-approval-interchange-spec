"""Worker functions for multi-process store tests.

They live in an importable module (not the test file) so that the ``spawn``
start method can re-import them in a fresh interpreter, exactly as on Windows
and macOS.
"""

from __future__ import annotations

import os
import time
from typing import Any

from aais.store import FileApprovalStore

STREAM = "test.approvals"

ACTION: dict[str, Any] = {
    "kind": "tool.call",
    "name": "shell.exec",
    "summary": "Run the syntax check",
    "arguments": {"command": "node --check script.js"},
}

CHOICES: list[dict[str, Any]] = [
    {"decision": "approve", "scope": "once", "label": "Allow once"},
    {
        "decision": "approve",
        "scope": "session",
        "label": "Allow for this session",
        "scope_constraints": {"action_name": "shell.exec"},
    },
    {"decision": "deny", "scope": "once", "label": "Deny"},
]

HUMAN = {"id": "user_alex", "type": "human", "authenticated_by": "test"}


def open_store(path: str, **kwargs: Any) -> FileApprovalStore:
    kwargs.setdefault("lock_timeout", 60.0)
    return FileApprovalStore(path, stream=STREAM, **kwargs)


def request_kwargs(index: int = 0, **extra: Any) -> dict[str, Any]:
    action = dict(ACTION, arguments={"command": f"node --check script-{index}.js"})
    values: dict[str, Any] = {
        "action": action,
        "origin": {"harness": "test", "session_id": "s-1", "run_id": f"r-{index}"},
        "risk": {"level": "medium", "reasons": ["executes a local process"]},
        "choices": CHOICES,
        "ttl": 600,
    }
    values.update(extra)
    return values


def add_many(path: str, worker: int, count: int, barrier: Any, results: Any) -> None:
    store = open_store(path)
    barrier.wait()
    created = []
    for index in range(count):
        envelope = store.add_request(**request_kwargs(worker * 1000 + index))
        created.append((envelope["request"]["id"], envelope["sequence"], os.getpid()))
    results.put(created)


def add_and_decide(path: str, worker: int, count: int, barrier: Any, results: Any) -> None:
    store = open_store(path)
    barrier.wait()
    sequences = []
    for index in range(count):
        envelope = store.add_request(**request_kwargs(worker * 1000 + index))
        resolution = store.decide(
            envelope["request"]["id"], decision="approve", scope="once", actor=HUMAN
        )
        sequences.extend([envelope["sequence"], resolution["sequence"]])
    results.put(sequences)


def decide_one(
    path: str, request_id: str, decision: str, scope: str, barrier: Any, results: Any
) -> None:
    from aais import ConflictError

    store = open_store(path)
    barrier.wait()
    try:
        resolution = store.decide(request_id, decision=decision, scope=scope, actor=HUMAN)
    except ConflictError as error:
        results.put(("conflict", decision, scope, str(error)))
    else:
        results.put(
            (
                "resolved",
                decision,
                scope,
                resolution["resolution"]["id"],
                resolution["resolution"]["outcome"],
            )
        )


def wait_for(path: str, request_id: str, ready: Any, results: Any) -> None:
    store = open_store(path)
    ready.set()
    resolution = store.wait_for_resolution(request_id, timeout=60, poll_interval=0.01)
    results.put(None if resolution is None else resolution["resolution"]["id"])


def add_then_exit(path: str, results: Any) -> None:
    store = open_store(path)
    envelope = store.add_request(**request_kwargs(99))
    results.put((envelope["request"]["id"], os.getpid()))


def hold_lock(path: str, seconds: float, ready: Any) -> None:
    store = open_store(path)
    with store.transaction():
        ready.set()
        time.sleep(seconds)


def crash_inside_transaction(path: str, ready: Any) -> None:
    store = open_store(path)
    with store.transaction() as tx:
        tx.add_request(**request_kwargs(7))
        ready.set()
        os._exit(3)  # simulate a crash: no commit, the OS releases the lock
