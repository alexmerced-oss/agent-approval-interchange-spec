# Agent Approval Interchange for Rust

Rust 1.85+ strongly typed documents, strict JSON parsing, RFC 8785 action
binding, Core validation, and a replay-safe approval state machine for AAIS 1.0.

```rust
let request = agent_approval_interchange::parse(json)?;
let mut store = agent_approval_interchange::ApprovalStore::new();
store.add(request)?;
```
