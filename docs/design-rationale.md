# Design rationale

## Why this is not another agent runtime protocol

Existing protocols already move runs, messages, tools, state, and interrupts.
AAIS deliberately does not. It defines the smaller object that must retain the
same security meaning when a permission prompt moves from a terminal to a web
UI, desktop client, policy service, or another harness.

## Why the action is hashed

An identifier correlates messages but does not prove the user reviewed the
same command the harness later executes. Canonicalizing and hashing the action
makes that comparison deterministic across five languages and across process
boundaries.

## Why policy is not standardized

Policy engines differ in resource models, identity, matcher syntax, and
administrative controls. AAIS standardizes offered choices and opaque,
fail-closed constraints, leaving rule creation to the authority. This avoids a
weak universal policy language becoming an escalation path.

## Why no chain-of-thought

A user needs current activity, the proposed action, provenance, expected
effects, and a clear risk explanation. Private model reasoning is neither
required for consent nor reliably safe to expose. `approval.activity` is the
portable status surface.

## Why approval and general input are separate

MCP elicitation and AG-UI interrupts already cover structured user input. An
approval changes what an agent may do, so it needs stricter scope, digest,
expiry, audit, concurrency, and revalidation rules.
