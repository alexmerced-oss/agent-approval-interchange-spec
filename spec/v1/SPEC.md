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
- `sequence`: a non-negative integer monotonically increasing within `stream`;
- `stream`: optional stable stream identifier;
- exactly one event payload selected by `type`;
- optional `extensions`, whose keys contain a reverse-DNS or URI namespace.

Unknown top-level fields are invalid. Consumers MUST ignore unknown keys inside
`extensions`.

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
offered by the request. Deny and cancel use `once`.

The optional `replacement_arguments` represents approve-with-edits. Its full
value replaces the original action arguments. It is allowed only when the
chosen request choice has `allow_edits: true`; the authority MUST recompute the
digest and may require a new approval if policy says the edit is material.

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

The authority MUST compare the decision digest to both the original request
and the action it is about to execute. A mismatch resolves as `stale` and MUST
NOT execute.

## 6. Action and presentation

An action has:

- `kind`: namespaced category such as `tool.call`, `filesystem.write`,
  `process.exec`, `network.request`, or `agent.delegate`;
- `name`: stable implementation action or tool name;
- `summary`: concise description of what will occur;
- `arguments`: exact JSON arguments, possibly replaced by a redacted object;
- optional `resource`, `working_directory`, `effects`, and `presentation`.

If arguments are redacted, `presentation.redacted` MUST be true and the
authority MUST compute `action_digest` from the unredacted action. It MUST also
provide `presentation.binding_hint` that tells the actor what hidden values are
bound (for example, "API token omitted"). A presenter MUST visibly indicate
redaction.

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

AAIS does not define a universal policy language. Authorities MUST treat
unknown constraints as non-matching.

## 10. Lifecycle and concurrency

1. The authority persists the request before emitting `approval.requested`.
2. It may emit display-safe `approval.activity` events while pending.
3. A presenter submits one `approval.decided` document.
4. The authority validates schema, authentication, offered choice, digest,
   expiry, current action, and policy.
5. The authority atomically records one `approval.resolved` outcome before
   executing an approved action.

Duplicate identical decisions MUST be idempotent and return the same
resolution. A different decision after resolution produces `conflict`. The
authority MUST serialize competing decisions per request.

## 11. Expiry and cancellation

When `expires_at` is present, a decision after that instant MUST resolve as
`expired`. Authorities SHOULD set a finite expiry for blocking requests. A
session or job cancellation MUST resolve its pending requests as `cancelled`.

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
An implementation that cannot enforce a received field MUST fail closed when
that field affects authority.
