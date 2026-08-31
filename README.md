# Agent Approval Interchange Specification (AAIS)

**A transport-neutral contract for asking a human to authorize an exact agent action.**

Specification `1.0` release candidate · support libraries `0.1.0` · Draft

[Specification](spec/v1/SPEC.md) · [Security](spec/v1/security.md) · [Conformance](spec/v1/conformance.md) · [Integration guide](docs/integration.md)

AAIS lets a harness pause any chat, bot, subagent, or graph node and hand a
portable approval request to a CLI, web UI, desktop app, policy service, or
other trusted decision surface. The response is cryptographically bound to the
exact action shown to the user, is idempotent, expires predictably, and cannot
grant a broader scope than the harness offered.

```json
{
  "aais": "1.0",
  "type": "approval.requested",
  "id": "evt_01JQ8QH80E4M7KJ6J7J7Y2RKSC",
  "occurred_at": "2026-08-30T18:00:00Z",
  "sequence": 41,
  "request": {
    "id": "apr_01JQ8QH80E4M7KJ6J7J7Y2RKSC",
    "created_at": "2026-08-30T18:00:00Z",
    "expires_at": "2026-08-30T18:10:00Z",
    "status": "pending",
    "origin": {"harness": "example", "session_id": "s-1", "run_id": "r-7"},
    "action": {
      "kind": "tool.call",
      "name": "shell.exec",
      "summary": "Run the JavaScript syntax check",
      "arguments": {"command": "node --check script.js"}
    },
    "action_digest": "sha256:...",
    "risk": {"level": "medium", "reasons": ["executes a local process"]},
    "choices": [
      {"decision": "approve", "scope": "once", "label": "Allow once"},
      {"decision": "approve", "scope": "session", "label": "Allow for this session",
       "scope_constraints": {"action_name": "shell.exec"}},
      {"decision": "deny", "scope": "once", "label": "Deny"}
    ]
  }
}
```

## Scope

AAIS standardizes the authority-bearing boundary only:

- exact-action requests, human-readable presentation, risk, and provenance;
- explicit approve, deny, and cancel decisions with bounded scopes;
- action digests, expiry, idempotency, stale-decision rejection, and receipts;
- durable snapshots and ordered events for reconnecting clients;
- adapter mappings for AG-UI interrupts, MCP hosts, HTTP/SSE, WebSocket, and stdio.

It does **not** define chat messages, model reasoning, tool discovery, agent
profiles, workflow graphs, authentication, or a network transport. Those remain
the responsibility of AG-UI, MCP, OAP, AGS, the host application, or another
runtime protocol.

## Support libraries

The repository contains release-candidate libraries with a shared API and
conformance corpus for Python, TypeScript, Go, Rust, and Java. Each library can:

- validate AAIS envelopes;
- compute RFC 8785 / SHA-256 action digests;
- create approval requests and decisions;
- maintain a fail-closed, replay-safe pending-approval store;
- emit and restore durable snapshots.

No package has been published yet. See [release preparation](docs/release.md).

## Repository layout

| Path | Contents |
| --- | --- |
| `spec/v1/` | Normative specification, security, and conformance rules |
| `schema/v1/` | JSON Schema Draft 2020-12 envelope schema |
| `conformance/` | Shared valid and invalid fixtures |
| `python/` | Python 3.10+ support package |
| `typescript/` | Node.js 20+ TypeScript package |
| `go/` | Go 1.23+ module |
| `rust/` | Rust 1.85+ crate |
| `java/` | Java 17+ Maven library |

## Design principles

1. **The harness remains the authority.** A UI conveys a decision; the harness
   revalidates it against current policy and current action state.
2. **Approval is exact by default.** Every approval carries the digest of the
   canonical action reviewed by the user.
3. **Scopes are offered, never invented.** A client may select only a choice
   present in the request.
4. **Reconnect is normal.** Pending approvals are durable state, not a terminal
   prompt waiting on stdin.
5. **No hidden reasoning is required.** AAIS carries concise activity,
   provenance, and risk explanations—not private chain-of-thought.

## License

Apache License 2.0. See [LICENSE](LICENSE).
