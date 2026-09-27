# Changelog

## Unreleased

### Python library 0.2.0 (unreleased)

The specification, schema, and conformance corpus are unchanged. The
TypeScript, Go, Rust, and Java libraries are unchanged and stay at 0.1.0; the
language libraries are versioned independently (see `VERSIONING.md`).

- Set the in-tree Python package version (`pyproject.toml` and
  `aais.__version__`) to 0.2.0 ahead of release, so that dependents that
  require `agent-approval-interchange>=0.2.0,<0.3` can install from a
  checkout. It has not been tagged or published.

- Added `aais.store.FileApprovalStore`, a durable approval authority that
  several processes can share through one JSON file:
  - every transaction holds an `fcntl.flock` or `msvcrt.locking` lock, covering
    sequence allocation, pending insertion, resolution, and receipts;
  - writes use a unique temp file in the same directory, fsync the file and
    the directory (`F_FULLFSYNC` on macOS), and replace atomically;
  - corrupt state is moved to `<file>.corrupt-<UTC timestamp>` and raises
    `RecoveryRequired` until `acknowledge_recovery()`; it is never read as
    empty;
  - `RetentionPolicy` bounds resolved requests, decisions, receipts, owners,
    and the event log by count and age;
  - `events_after(seq)` returns an `EventPage` with an explicit `gap` flag;
  - `wait_for_resolution()` re-parses the file only when its metadata changes;
  - `transaction()` supports atomic multi-step logic, and extensions store
    consumer data such as remembered grants;
  - `import_legacy_state()` migrates Loro and MagAgent state files.
- The package ships `py.typed`, so type checkers now read these annotations.
  `create_request()` and `add_request()` take `choices` as
  `Sequence[Mapping[str, Any]]`, so a caller's `list[dict[str, Any]]` type-checks. A
  `list[Mapping[str, Any]]` annotation would reject it, because `list` is invariant.
- Split state logic from persistence. `aais.store.ApprovalAuthority(backend,
  ...)` holds every AAIS rule, and `aais.backends` defines runtime-checkable
  protocols for storage:
  - `ApprovalStateBackend`: `transaction`, `version`, `invalidate`, `exists`,
    `recovery_status`;
  - `BackendTransaction`: `recovery_marker`, `load`, `save`, `quarantine`,
    `clear_recovery`.
  `FileApprovalStore` is now `ApprovalAuthority` over `FileBackend`, with the
  same constructor, attributes, and behavior. `MemoryBackend` is an
  in-process reference backend.
- Added `aais.testing.BackendConformance` and `run_backend_conformance`, a
  stdlib-only kit that third-party backends (for example a Postgres row store)
  run to prove locking, versioning, quarantine, and full authority behavior,
  optionally across processes.
- Added `aais.liveness`: `OwnerIdentity` records `{pid, process_start_time,
  host_id}`. `owner_liveness` treats a changed start time as dead (PID reuse),
  `EPERM` as alive, and another host as unknown. It uses `/proc` on Linux,
  `ps` on macOS, and `OpenProcess`/`GetProcessTimes` on Windows.
- The package now ships `py.typed` and is checked with `mypy --strict` in CI.
  CI also runs the Python suite, including spawn-based multi-process
  contention tests, on Windows and macOS.

### Specification and docs

- Added a WebMCP integration profile for presenting exact, revision-bound browser actions while
  keeping policy authority in the harness and credentials in the browser context.
- Documented read-only hints, mutating-call confirmation, stale registries, expiry, redaction,
  cancellation, and reconnect-safe presentation requirements.

## 0.1.0 - 2026-08-30

- Define the AAIS 1.0 release-candidate envelope, request, decision,
  resolution, snapshot, and activity events.
- Bind decisions to exact actions using RFC 8785 and SHA-256.
- Define bounded choice scopes, expiry, replay, conflict, redaction, and
  fail-closed security semantics.
- Document AG-UI, MCP, HTTP/SSE, WebSocket, and NDJSON integration profiles.
- Add parity support libraries for Python, TypeScript, Go, Rust, and Java.
- Require edited actions to become new requests instead of weakening exact
  action binding through approve-with-edits.
- Clarify producer-owned sequence streams, opaque credential bindings,
  authorization-versus-execution semantics, saved-scope revocation, and
  resource-rebinding risks.
- Reject ambiguous duplicate decision/scope choice tuples.
