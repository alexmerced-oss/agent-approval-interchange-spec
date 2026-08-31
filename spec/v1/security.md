# AAIS 1.0 security model

AAIS moves a decision across a trust boundary. It does not make the presenter,
model, or transport trusted.

## Required controls

- Bind every decision to the RFC 8785 digest of the exact action.
- Authenticate the presenter and derive actor identity from that channel.
- Revalidate current policy, action state, offered scope, and expiry at use.
- Persist resolution atomically before executing the action.
- Treat duplicate decisions as idempotent and conflicting decisions as errors.
- Fail closed on unknown authority-bearing fields or constraints.
- Never serialize credentials, authentication secrets, or private reasoning.
- Preserve redaction in events, snapshots, telemetry, and error messages.
- Resolve pending approvals when their session, job, or node is cancelled.

## Threats

### Prompt injection and self-approval

Model output is untrusted. An agent may request an approval but MUST NOT create
an actor decision or claim that prose from a user constitutes protocol consent.
Only the authenticated decision endpoint may produce an effective decision.

### Time-of-check/time-of-use

The authority compares the approved digest with the action immediately before
execution. Changed arguments, working directory, destination, or effect resolve
as `stale`.

### Scope escalation

Clients select a tuple already offered by the authority. They cannot submit a
new scope, edit scope constraints, or convert a one-time approval into a saved
rule. Unknown constraint syntax never matches.

### Replay and races

Decision identifiers and atomic resolution make identical retries safe. A
second, different decision does not alter the first result. Transport-level
anti-replay remains required for authenticated remote clients.

### Misleading presentation

The structured action is authoritative; `summary`, `risk`, and `effects` are
presentation aids. Presenters should render both the summary and the important
structured fields, visibly indicate redaction, and never hide critical risk or
scope information behind an optional expansion.

### Denial of service

Authorities should bound request size, number of pending approvals per actor,
event retention, and activity rate. Presenters should coalesce repeated
notifications without silently deciding them.

## Out of scope

AAIS does not define authentication, authorization policy evaluation,
cryptographic signatures, transport encryption, credential exchange, sandbox
enforcement, or tool correctness. Bindings may add these controls without
changing AAIS documents.
