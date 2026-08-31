# Agent Approval Interchange for TypeScript

Node.js 20+ validation, RFC 8785 action binding, builders, and the reference
in-memory approval state machine for AAIS 1.0.

```ts
import { ApprovalStore, createDecision, validate } from "agent-approval-interchange";

const request = validate(JSON.parse(json));
const store = new ApprovalStore();
store.add(request);
const decision = createDecision(request, {
  decision: "approve",
  scope: "once",
  actor: { id: "user-1", type: "human" },
  sequence: 2,
});
const resolution = store.decide(decision);
```
