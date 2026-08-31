# Support-library API

All five libraries expose the same conceptual surface. Naming follows each
language's conventions.

| Capability | Python | TypeScript | Go | Rust | Java |
| --- | --- | --- | --- | --- | --- |
| Parse/validate | `validate` | `validate` | `Parse`, `Validate` | `parse`, `validate` | `Aais.parse`, `Aais.validate` |
| Action binding | `action_digest` | `actionDigest` | `ActionDigest` | `action_digest` | `Aais.actionDigest` |
| Request builder | `create_request` | `createRequest` | `CreateRequest` | `create_request` | `Aais.createRequest` |
| Decision builder | `create_decision` | `createDecision` | `CreateDecision` | `create_decision` | `Aais.createDecision` |
| State machine | `ApprovalStore` | `ApprovalStore` | `Store` | `ApprovalStore` | `ApprovalStore` |
| Durable snapshot | `snapshot`, `from_snapshot` | `snapshot`, `fromSnapshot` | `Snapshot`, `FromSnapshot` | `snapshot`, `from_snapshot` | `snapshot`, `fromSnapshot` |

## State-machine contract

`add` persists an unresolved request idempotently. `decide` validates the
decision against the request, current time, and optional current action. It
returns an `approval.resolved` envelope and removes the request from the
pending set. An identical decision returns the original resolution; a
different decision raises a conflict. The caller must durably commit the
resolution before executing an approved action.

Snapshot methods accept a current instant (or use the current clock) and omit
expired requests. Restore methods validate every pending request before making
it visible.

## What the libraries do not do

The support libraries do not authenticate actors, persist data, evaluate local
policy, execute actions, or run HTTP/WebSocket servers. A harness supplies
those responsibilities and revalidates policy immediately before execution.
