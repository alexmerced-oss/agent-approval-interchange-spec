# WebMCP approval mapping

AAIS can present WebMCP authorization without extending its envelope. Use `action.kind` =
`tool.call`; use the exact live WebMCP tool name in `action.name`; and include the origin, page URL,
registry revision, and tool arguments in the action arguments used to compute `action_digest`.

The human-facing summary should say what the site tool will do. Risk reasons should identify remote
side effects, credential use, destructive annotations, or missing safety annotations. A read-only
annotation may lower risk only when it came from the registry revision shown in the request; it
does not override host policy.

## Binding and replay safety

- Invocation MUST stop when the page registry revision differs from the approved action.
- Redirects to a different origin require a new discovery and approval boundary.
- `once` is the recommended default scope. A session choice MUST be constrained by origin and tool
  name, and SHOULD also bind the registry revision when the site does not publish a stable tool
  contract.
- Reconnected UIs restore pending requests from the AAIS snapshot/event stream. Closing the UI does
  not imply approval or denial.

## Audit and redaction

Record AAIS request/decision identifiers next to the WebMCP invocation audit entry. Present tool
arguments for review, but redact authorization headers, cookies, tokens, passwords, and fields
identified as secret by host policy. Never place browser storage or credentials into the AAIS
envelope merely to make an invocation reproducible.
