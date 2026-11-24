# Agent Approval Interchange Specification maintenance tracker

Audited 2026-11-24 against checkout `606256c`. Python suite passed 132 tests with 3 skips. Isolated CLI checks covered null JSON and an unreadable UTF-8 input.

Claim a row by entering your name or task ID and setting the status to **In progress**. Use **Blocked** with the missing dependency if needed. Set **Done** after the acceptance check passes and record the fix commit or PR, the command or manual check, and its result. If a newer revision already resolves the item, record that evidence and close it. Keep status in this table.

| ID | Priority | Status | Owner | Fix and verification |
| --- | --- | --- | --- | --- |
| AAIS-01 | P2 | Open | — | — |

### AAIS-01 · Return consistent validation diagnostics for invalid envelopes

**Reproduced.** `python -m aais.cli` raised uncaught TypeError for JSON null and UnicodeDecodeError for invalid text encoding. [aais/core.py](../aais/core.py) constructs a dict before validating the root, and [aais/cli.py](../aais/cli.py) handles JSON decoding but omits text decoding errors.

**Acceptance check.** Use temporary input files for null, scalars, arrays and invalid text encoding. The CLI should exit nonzero with a short diagnostic and no traceback. A valid fixture must still pass. Use the library’s ValidationError contract for invalid document roots.
