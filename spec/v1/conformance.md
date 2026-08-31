# AAIS 1.0 conformance

An implementation claims **Core** conformance when it:

1. validates every shared valid fixture and rejects every shared invalid fixture;
2. computes every published action digest exactly;
3. rejects decisions that are expired, stale, or not among offered choices;
4. treats identical duplicate decisions idempotently and conflicts atomically;
5. passes through namespaced extensions without interpreting them as authority.
6. rejects duplicate decision/scope choice tuples and edited-action decisions.

It claims **Durable** conformance when it additionally:

1. persists requests before publication;
2. restores the pending set from a snapshot;
3. applies only events after `as_of_sequence` in stream order;
4. excludes terminal and expired requests from snapshots;
5. cancels pending requests when their owning execution is cancelled.

It claims **Secure Approval** conformance when it additionally documents and
tests authenticated actor binding, transport integrity, replay controls,
redaction, atomic resolution, policy revalidation, and fail-closed handling.

Support libraries in this repository provide Core and an in-memory Durable
state machine. A harness must supply persistence, authentication, policy, and
atomic execution integration before claiming Secure Approval.
