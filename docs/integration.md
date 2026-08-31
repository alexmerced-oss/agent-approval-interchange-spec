# Integration guide

## Harness architecture

Use one approval broker inside the harness for every execution path: normal
chat, bot chat, subagents, graph nodes, background jobs, and direct tools. Tool
execution calls the broker; the broker persists and publishes the request; any
connected presenter may render it; the authenticated decision returns to the
same broker. The terminal presenter is a fallback, not a second policy path.

## AG-UI adapter

Represent the pause as an AG-UI `tool_call` interrupt. Put the complete AAIS
`approval.requested` envelope under `interrupt.metadata.aais`. On resume, put
the AAIS `approval.decided` envelope under `resume.metadata.aais`. The harness
still emits AG-UI snapshots before the interrupt and begins a new AG-UI run on
resume.

## MCP adapter

Do not expose AAIS as an MCP server request. The MCP host/harness creates AAIS
requests when its own policy gates a proposed MCP tool call. MCP elicitation
remains available for non-sensitive structured input requested by the server.

## HTTP/SSE profile

- Stream AAIS envelopes as JSON SSE data in sequence order.
- `GET /approvals/snapshot` returns an `approval.snapshot` envelope.
- `POST /approvals/{request_id}/decisions` accepts one
  `approval.decided` envelope and returns `approval.resolved`.
- Authenticate all endpoints, require CSRF protection for cookie sessions, and
  never trust actor data supplied by an unauthenticated body.

## WebSocket profile

Send one AAIS JSON envelope per text frame. After reconnect, request a snapshot
and then consume events after its `as_of_sequence`. Decisions travel in the
opposite direction on the same authenticated connection.

## NDJSON stdio profile

Write one complete envelope per line to stdout and accept decision envelopes on
stdin. Diagnostic logs go to stderr. This profile is useful for adapters and
tests; interactive terminal rendering should not share stdin with a browser
presenter.
