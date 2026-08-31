# Agent Approval Interchange for Java

Java 17+ strict parsing, RFC 8785 action binding, Core validation, and a
thread-safe approval state machine for AAIS 1.0.

```java
ObjectNode request = Aais.parse(json);
ApprovalStore store = new ApprovalStore();
store.add(request);
```
