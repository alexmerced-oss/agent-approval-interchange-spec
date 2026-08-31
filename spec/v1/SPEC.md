# Agent Approval Interchange Specification 1.0

Status: **release candidate**. Normative terms MUST, MUST NOT, SHOULD, SHOULD
NOT, and MAY are interpreted as described by RFC 2119 and RFC 8174.

## 1. Purpose

AAIS defines portable JSON documents for moving authority-bearing approval
requests and their outcomes between an agent harness and a decision surface.
The decision surface may be a terminal, browser, desktop UI, policy service, or
another application acting for an authenticated human.

AAIS is transport-neutral. An implementation may carry AAIS envelopes over
stdio, WebSocket, SSE plus HTTP, an in-process callback, AG-UI metadata, or a
durable message bus.

## 2. Roles

- **Authority**: the harness or policy component that may execute the action.
- **Presenter**: the client that displays a request and collects a decision.
- **Actor**: the authenticated human or policy principal making the decision.
- **Requester**: the agent, subagent, graph node, or system component whose
  proposed action caused the request.

The presenter is not automatically an authority. The authority MUST validate a
decision before acting on it.

## 3. Envelope

Every document is a JSON object with:

- `aais`: the document-model version, exactly `"1.0"`;
- `type`: one of the event types in section 4;
- `id`: a unique event identifier;
- `occurred_at`: an RFC 3339 timestamp with an explicit offset;
- `sequence`: a non-negative integer monotonically increasing within a stream
  owned by one producer;
- `stream`: optional stable stream identifier;
- exactly one event payload selected by `type`;
- optional `extensions`, whose keys contain a reverse-DNS or URI namespace.

Unknown top-level fields are invalid. Consumers MUST ignore unknown keys inside
`extensions`.

A producer MUST NOT write into another producer's stream. In a bidirectional
binding, the authority and each presenter use distinct stream identifiers and
sequence spaces. Sequence establishes order only inside one producer stream,
not a global order. Durable bindings MUST provide `stream`.

## 4. Event types

### 4.1 `approval.requested`

Carries `request`. Required request fields are `id`, `created_at`, `status`,
`origin`, `action`, `action_digest`, `risk`, and `choices`.

`status` MUST be `pending`. `choices` MUST be non-empty and contain at least one
deny or cancel choice. An authority MUST NOT issue an unbounded approval choice.

### 4.2 `approval.decided`

Carries `decision`. Required fields are `id`, `request_id`, `action_digest`,
`decided_at`, `decision`, `scope`, and `actor`.

`decision` is `approve`, `deny`, or `cancel`. `scope` is `once`, `session`, or
`persistent`. A decision tuple `(decision, scope)` MUST exactly match a choice
offered by the request, and choice tuples MUST be unique within a request. Deny
and cancel use `once`.

AAIS 1.0 does not support approve-with-edits. If an actor edits an argument,
the authority MUST cancel or supersede the old request and emit a new request
with a new identifier and action digest. This preserves exact-action consent.

### 4.3 `approval.resolved`

Carries `resolution`, the authority's terminal result. `outcome` is one of:

- `approved`: the decision was accepted;
- `denied`: execution was refused;
- `cancelled`: the presenter or actor abandoned the request;
- `expired`: the request expired before acceptance;
- `stale`: the action no longer matches the approved digest;
- `conflict`: another decision already resolved the request;
- `invalid`: the decision failed validation or policy.

A resolution includes the request and decision identifiers when applicable,
the action digest, resolution time, and a safe human-readable explanation.
`approved` means the authorization decision was accepted. It does not assert
that execution began or succeeded; execution lifecycle belongs to the embedding
runtime.

### 4.4 `approval.snapshot`

Carries `snapshot`, containing `as_of_sequence` and all unresolved requests
visible to the authenticated presenter. A reconnecting presenter uses the
snapshot as its current pending set, then applies events with larger sequence
numbers. A snapshot MUST NOT contain resolved or expired requests.

### 4.5 `approval.activity`

Carries safe, non-authority-bearing progress for a pending request. `message`
MUST be suitable for display and MUST NOT contain private chain-of-thought,
credentials, or unredacted sensitive arguments. Activity never changes
approval state.

## 5. Action binding

`action_digest` is `sha256:` followed by lowercase hexadecimal SHA-256 of the
UTF-8 RFC 8785 canonical JSON encoding of the `action` object. The digest binds
the decision to every standard action field, including arguments.

Producers MUST supply RFC 7493 I-JSON-compatible action values as required by
RFC 8785: no duplicate object names, strings represent Unicode data, and
numbers are interoperable IEEE 754 values. Integers outside the exact range
`-(2^53-1)` through `2^53-1` SHOULD be encoded as strings. Consumers SHOULD
reject non-interoperable inputs before calculating a digest.

The authority MUST compare the decision digest to both the original request
and the action it is about to execute. A mismatch resolves as `stale` and MUST
NOT execute.

## 6. Action and presentation

An action has:

- `kind`: namespaced category such as `tool.call`, `filesystem.write`,
  `process.exec`, `network.request`, or `agent.delegate`;
- `name`: stable implementation action or tool name;
- `summary`: concise description of what will occur;
- `arguments`: exact JSON arguments, with secrets represented by stable opaque
  credential or transaction references;
- optional `resource`, `working_directory`, `effects`, and `presentation`.

The action transmitted in the AAIS document is the action canonicalized for
`action_digest`; a producer MUST NOT hash a different hidden action. Secret
material MUST remain outside AAIS. When a runtime value is represented by an
opaque reference, `presentation.redacted` MUST be true and
`presentation.binding_hint` MUST explain the identity that is bound (for
example, "credential for account 123; token omitted"). The reference, account,
and authority-relevant destination are part of the hashed action. A presenter
MUST visibly indicate the opaque binding. Resolving a reference to a different
account, resource boundary, or principal makes the approval stale.

`effects` is advisory and may list filesystem paths, network origins, subprocess
commands, external recipients, or other expected effects. It does not grant
authority.

## 7. Origin and provenance

`origin.harness` and `origin.session_id` are required. Optional fields include
`run_id`, `task_id`, `graph_id`, `node_id`, `agent_id`, `profile`,
`subagent_run_id`, and `parent_run_id`. Presenters SHOULD show the harness,
project or resource, requester, and action summary before accepting input.

## 8. Risk

`risk.level` is `low`, `medium`, `high`, or `critical`. `risk.reasons` is a
non-empty list of display-safe explanations. Risk is advisory: clients MUST NOT
infer authority from it or silently auto-approve based only on this field.
The authority, not model-authored prose, is responsible for the offered risk,
choices, and structured action presented for approval.

## 9. Scopes

- `once`: only the exact pending request;
- `session`: future matching actions in the same `origin.session_id`, subject
  to the authority's policy and expiry;
- `persistent`: future matching actions within an explicit authority-defined
  rule, subject to policy and revocation.

Session and persistent choices MUST include `scope_constraints`. Constraints
MUST be data interpreted by the authority and SHOULD identify the action name,
resource boundary, argument matcher, and expiry. A client MUST NOT broaden,
merge, or synthesize constraints.

The presenter MUST show the selected scope and an authority-generated,
human-readable explanation of its constraints before submission. An authority
offering `persistent` MUST provide a discoverable way to inspect and revoke the
resulting saved rule. Rule identifiers, CRUD, and policy synchronization remain
outside AAIS 1.0.

AAIS does not define a universal policy language. Authorities MUST treat
unknown constraints as non-matching.

## 10. Lifecycle and concurrency

1. The authority persists the request before emitting `approval.requested`.
2. It may emit display-safe `approval.activity` events while pending.
3. A presenter submits one `approval.decided` document.
4. The authority validates schema, authentication, offered choice, digest,
   expiry, current action, and policy.
5. The authority atomically records one `approval.resolved` outcome before
   handing an approved action to the embedding executor.

Duplicate identical decisions MUST be idempotent and return the same
resolution. A different decision after resolution produces `conflict`. The
authority MUST serialize competing decisions per request.

The authority MUST derive or verify `actor` from the authenticated channel and
MUST NOT trust an actor supplied only in a request body. If multiple presenters
race, the first valid atomic resolution wins and every other presenter receives
or observes the terminal result. A request authorizes one atomic action. Batches,
partial approval, quorum approval, and dependent approvals are orchestrated by
the embedding runtime as separate requests.

## 11. Expiry and cancellation

When `expires_at` is present, a decision at or after that instant MUST resolve
as `expired`. The authority's clock controls; presenter clocks are advisory.
Authorities SHOULD set a finite expiry for blocking requests. A session or job
cancellation MUST atomically resolve its pending requests as `cancelled`; a
concurrent or later approval then loses the race and MUST NOT execute.

## 12. Authentication and transport

AAIS does not authenticate connections. The embedding transport MUST
authenticate presenters and protect integrity and confidentiality. Browser
bindings MUST address CSRF, origin validation, session fixation, and replay.
The actor object is a claim from the authenticated transport, not proof by
itself.

## 13. Sensitive data

Credentials, private keys, bearer tokens, and passwords MUST NOT appear in an
AAIS document. Approval for an external authorization flow may reference an
opaque authorization transaction, but credential collection and token exchange
occur outside AAIS. Logs and snapshots MUST preserve redaction.

## 14. Relationship to adjacent protocols

- **AG-UI** can carry an AAIS request inside interrupt metadata and an AAIS
  decision inside resume metadata. AG-UI owns run lifecycle; AAIS owns approval
  semantics and action binding.
- **MCP** elicitation requests user data from an MCP server. AAIS governs a
  harness's authorization to execute an action and MUST NOT be used by an MCP
  server to bypass its host's permission policy.
- **OAP** describes an agent profile and its maximum requested permissions.
  AAIS decisions can narrow or temporarily authorize within the harness's
  effective OAP/policy ceiling; they never widen that ceiling.
- **AGS** describes workflow graphs. AAIS origin fields correlate approvals to
  graph and node identifiers without changing graph semantics.

## 15. Extensions and compatibility

Extensions belong under `extensions`. Standard fields added compatibly require
a new AAIS minor version. Incompatible semantics require a new major version.
Extensions MUST NOT silently alter core authority semantics. A binding that
defines an authority-bearing extension MUST negotiate support out of band and
fail closed when either peer cannot enforce it; otherwise unknown extensions
are observational and ignored.

## 16. Explicit non-goals and composition

AAIS 1.0 deliberately does not define execution results, chat or model events,
tool discovery, general form input, credential exchange, policy-rule CRUD,
transport authentication, signatures, multi-party quorum, or batch/partial
approval. Runtimes compose those concerns with AAIS and correlate them using
request, run, task, graph, and node identifiers. An approved AAIS resolution is
one authorization fact, never a substitute for those protocols.
