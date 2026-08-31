# Changelog

## 0.1.0 - Unreleased

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
