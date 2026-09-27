# Python durable file store (`aais.store`)

Status: new in the Python library `agent-approval-interchange` 0.2.0 (unreleased).
Python only; the TypeScript, Go, Rust, and Java libraries are unchanged.

`aais.store.FileApprovalStore` is a ready-made approval authority for a harness
that keeps its pending approvals in a local JSON file and may run several
processes against it (a web server, a CLI, a background worker, a stdio bridge).
It wraps the in-memory `ApprovalStore` from `aais.core`. Every envelope it
writes is created and validated by the same `create_request`, `create_decision`,
and `ApprovalStore.decide` code, so AAIS 1.0 semantics are unchanged: exact
action digests, offered choices only, expiry, stale-action detection, and
idempotent replay.

It uses only the standard library (no new runtime dependencies) and ships type
information (`py.typed`).

## Quick start

```python
from datetime import timedelta
from aais.store import FileApprovalStore, RetentionPolicy

store = FileApprovalStore(
    ".myharness/aais-approvals.json",
    stream="myharness.approvals",          # authority stream on requested/resolved events
    retention=RetentionPolicy(max_resolved=1000, max_resolved_age=timedelta(days=30)),
)

requested = store.add_request(
    action={"kind": "tool.call", "name": "shell.exec", "summary": "Run tests",
            "arguments": {"command": "pytest -q"}},
    origin={"harness": "myharness", "session_id": "s-1"},
    risk={"level": "medium", "reasons": ["executes a local process"]},
    choices=[
        {"decision": "approve", "scope": "once", "label": "Allow once"},
        {"decision": "deny", "scope": "once", "label": "Deny"},
    ],
    ttl=600,                               # seconds; sets expires_at
)
request_id = requested["request"]["id"]

# In the process that is waiting on the action:
resolution = store.wait_for_resolution(request_id, timeout=600)

# In any process that receives the human's decision:
store.decide(request_id, decision="approve", scope="once",
             actor={"id": "alex", "type": "human", "authenticated_by": "web-session"},
             reviewed_digest=requested["request"]["action_digest"])
```

## Guarantees

**Whole-transaction locking.** Each operation runs as one transaction under an
exclusive lock on `<file>.lock`: `fcntl.flock` on POSIX and a one-byte
`msvcrt.locking` range on Windows. A per-path thread lock serializes threads in
the same process first. Sequence allocation, pending insertion, owner
recording, resolution, and receipts therefore never interleave, across threads
or processes. Waiting for the lock gives up after `lock_timeout` seconds
(default 10) with `LockTimeout`. Opening a second transaction on the same file
from the same thread raises `StoreError` rather than deadlocking.

For multi-step logic that must be atomic, such as "check remembered grants,
then create the request", use a transaction directly:

```python
with store.transaction() as tx:
    grants = tx.get_extension("grants", [])
    if not any(g["action_digest"] == digest for g in grants):
        tx.add_request(...)
```

Changes are written only if the block exits without an exception. Inside a
transaction, use the `tx` methods. Calling `store.*` methods on the same file
there raises the nested-transaction error.

**Durable writes.** State is written to a unique `mkstemp` file in the same
directory, fsynced (`F_FULLFSYNC` on macOS), and moved over the state file
with `os.replace`. The directory is then fsynced on POSIX. A crash at any
point leaves either the old file or the new one. Temporary files left behind
by a crashed writer are removed by the next write. Files are created with mode
`0600`, and symlinked state or lock paths are refused.

**Corruption is never read as empty.** If the state file is not valid UTF-8 or
JSON, or does not have the expected structure, the store:

1. moves it to `<file>.corrupt-<UTC timestamp>` (for example
   `aais-approvals.json.corrupt-20260927T150405Z`);
2. writes a `<file>.recovery-required` marker;
3. raises `RecoveryRequired`, which has `path`, `reason`, `quarantined_to`,
   `detected_at`, and `sequence_hint` attributes.

Every later call, from any process, raises `RecoveryRequired` until an
operator calls `store.acknowledge_recovery()`. At that point either a file
restored by hand is validated, or a fresh store starts at the highest sequence
salvaged from the damaged bytes (or at an explicit `start_sequence`). Clients
that reconnect then see a gap instead of reused sequence numbers.
`store.recovery_status()` reports the condition without raising. A state file
from a newer store version (`aais.store.v2` and later) raises
`UnsupportedStoreVersion` and is left in place. It is not quarantined.

**Bounded retention.** After every write transaction, and whenever you call
`store.compact()`, the store applies its `RetentionPolicy`:

| Field | Default | Effect |
| --- | --- | --- |
| `max_resolved` | 1000 | Keep at most this many resolved requests, newest first |
| `max_resolved_age` | 30 days | Drop resolved requests older than this |
| `max_events` | 1000 | Keep at most this many events in the log |
| `max_event_age` | 30 days | Drop events older than this |

Removing a resolved request also removes its decision, receipt, and owner
record. Pending requests are never compacted. Set any limit to `None` to
disable it.

**Replay gaps are explicit.** `store.events_after(seq)` returns an `EventPage`
with `events`, `gap`, `compacted_through`, `latest_sequence`, and `store_id`.
`gap` is `True` when `seq < compacted_through` (the caller missed events that
were compacted) or when `seq > latest_sequence` (the caller saw a store that
has since been reset). On a gap, fetch `store.snapshot()` and resume from its
`as_of_sequence`. `store_id` is assigned on the first write (it is empty
before that) and changes when a recovery reset starts a fresh store.

**Owner identity that survives PID reuse.** Each pending request records the
process that owns it as `{pid, process_start_time, host_id}`
(`aais.liveness.OwnerIdentity`). `owner_liveness` returns one of three values:

- `DEAD` when the PID is gone, is a zombie, or now belongs to a process with a
  different start time (PID reuse). Start times are compared within 2 seconds.
- `ALIVE` when the PID exists with the recorded start time, or when it exists
  but is owned by another user (`EPERM`).
- `UNKNOWN` when the owner is on another host or PID namespace. That is never
  treated as dead.

Start times come from `/proc/<pid>/stat` on Linux, `ps -o lstart=` on macOS
and other POSIX systems, and `OpenProcess` plus `GetProcessTimes` (through
`ctypes`) on Windows. The host id is a hash of the machine id (plus the PID
namespace on Linux), so the raw machine id is not written to the file. Set
`AAIS_HOST_ID` to override it.

`decide(..., decision="approve")` raises `OwnerStoppedError` when the owner is
`DEAD`, because nobody is waiting to act on the approval. Pass
`require_live_owner=False` to skip this check. Denials and cancellations are
always allowed. `snapshot()` hides orphaned requests unless you pass
`include_orphaned=True`. `recovery()` lists `orphaned`, `unknown_owner` (no
owner recorded), and `unverified_owner` (owner liveness `UNKNOWN`) request ids,
plus recent receipts. `cancel_orphaned()` withdraws the orphaned requests.

**Cheap waiting.** `wait_for_resolution(request_id, timeout, poll_interval=0.1,
cancelled=None, refresh_interval=2.0)` checks the file's inode, size, mtime,
and ctime on every poll, and re-parses the file only when one of them changes.
It also re-reads the file every `refresh_interval` seconds, to cover
filesystems with coarse timestamps. It returns the `approval.resolved`
envelope, or `None` on timeout or when the `cancelled` event is set. It raises
`UnknownRequestError` for a request that is neither pending nor resolved.

## API reference

Module `aais.store`:

| Name | Kind | Summary |
| --- | --- | --- |
| `FileApprovalStore(path, *, stream, presenter_stream=None, retention=None, lock_timeout=10.0, max_bytes=64 MiB, clock=None, owner=None, host_id=None)` | class | The store. `presenter_stream` defaults to `"<stream>.presenter"` and is used for decision envelopes. |
| `.transaction()` | context manager → `StoreTransaction` | Locked read-modify-write |
| `.add_request(*, action, origin, risk, choices, request_id=None, event_id=None, created_at=None, expires_at=None, ttl=None, owner=None)` | → envelope | Persist a pending `approval.requested` |
| `.decide(request_id, *, decision, scope, actor, decision_id=None, reviewed_digest=None, current_action=None, require_live_owner=True)` | → envelope | Resolve and return the `approval.resolved` receipt |
| `.deny(request_id, *, actor_id="aais.policy")` | → envelope | Policy denial (for timeouts) |
| `.cancel(request_id, *, actor_id="aais.cancel")` | → envelope | Withdraw: `cancel`/`once` if offered, otherwise `deny`/`once`. Idempotent unless the request was approved. |
| `.get_pending / .get_decision / .get_resolution(request_id)` | → envelope or `None` | Reads |
| `.get_owner(request_id)` / `.owner_liveness(request_id)` | → `OwnerIdentity` / `Liveness` or `None` | Owner inspection |
| `.pending_requests()` | → list | Pending envelopes in sequence order |
| `.get_extension(name, default=None)` | → JSON | Consumer data stored alongside the approval state |
| `.snapshot(*, now=None, include_orphaned=False, event_id=None)` | → envelope | Validated `approval.snapshot` |
| `.events_after(sequence)` | → `EventPage` | Replay with a gap flag |
| `.recovery(*, receipt_limit=100)` | → `RecoveryReport` | Orphaned and unverified owners, plus recent receipts |
| `.cancel_orphaned(*, actor_id="aais.recovery")` | → list of receipts | Withdraw requests whose owner is `DEAD` |
| `.compact()` | → `CompactionReport` | Apply retention now |
| `.wait_for_resolution(request_id, *, timeout, poll_interval=0.1, cancelled=None, refresh_interval=2.0)` | → envelope or `None` | Cross-process wait |
| `.recovery_status()` / `.acknowledge_recovery(*, start_sequence=None)` | | Corruption workflow |
| `.import_legacy_state(legacy, *, overwrite=False)` | | One-time import of a pre-0.2 harness state file (see below) |

`StoreTransaction` provides `sequence`, `store_id`, `next_sequence()`,
`next_presenter_sequence()`, `pending()`, `get_pending()`, `get_decision()`,
`get_resolution()`, `get_owner()`, `owner_liveness()`, `get_extension()`,
`set_extension()`, `delete_extension()`, `add_request(...)`, `decide(...)`, and
`cancel(...)`, with the same arguments as the store methods.

Errors: `StoreError` is the base class, and it derives from
`aais.ApprovalError`. Its subclasses are `RecoveryRequired`,
`UnsupportedStoreVersion`, and `LockTimeout`. The other store errors are:

- `UnknownRequestError`, which is also a `ValidationError` and a `ValueError`;
- `OwnerStoppedError` and `StaleDecisionError`, which are both
  `aais.ConflictError`.

Value types: `RetentionPolicy`, `EventPage`, `RecoveryReport`,
`CompactionReport`. Each has `to_dict()` where that is useful.

Module `aais.liveness`: `OwnerIdentity(pid, process_start_time, host_id)` with
`current()`, `to_dict()`, `from_dict()`, and `liveness()`. The module also
provides these functions and constants:

- `Liveness` (`ALIVE`, `DEAD`, `UNKNOWN`);
- `owner_liveness(owner, *, host_id=None)`;
- `pid_liveness(pid)`;
- `process_alive(pid)`, a boolean compatibility helper;
- `process_start_time(pid)`;
- `current_host_id()`;
- `START_TIME_TOLERANCE_SECONDS`.

The package root re-exports `FileApprovalStore`, `RetentionPolicy`,
`RecoveryRequired`, `StoreError`, `OwnerIdentity`, and `Liveness`.

## Migrating an existing harness store

Loro (`loro.aais-store.v1`) and MagAgent (`magent.aais-store.v1`) keep state in
the same shape. `import_legacy_state(json.load(old_file))` converts it:

- `sequence`, `presenter_sequence`, `pending`, `decisions`, `resolutions`, and
  `events` are carried over;
- bare-PID `owners` become local owners with no start time, so they fall back
  to a PID-only check;
- any other key, such as MagAgent's `grants`, becomes an extension of the same
  name.

The import refuses to overwrite an existing store unless `overwrite=True`.

## What it does not do

The store does not authenticate actors, publish events to presenters, run
servers, evaluate local policy, or remember grants. Grants and other
harness-specific data can live in extensions inside the same transaction. The
file must be on a local filesystem. Advisory locks over network filesystems
are not reliable, and the store makes no attempt to detect them.
