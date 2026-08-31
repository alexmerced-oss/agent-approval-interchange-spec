# Shared conformance corpus

Every support library consumes the same documents in `../examples`:

- `shell-approval.json` is the canonical valid request and action-digest vector.
- `approve-once.json` is the canonical valid decision and correlation vector.

Each language suite applies the same semantic mutations to these fixtures:
wrong digest, unoffered scope, expiry, changed action, identical replay,
conflicting replay, and snapshot restoration. The fixed digest vector is:

`sha256:157f438a55ce7db6aa61c8515f0b48ce2851b9bad6c5b67bb3eb34ff353fd9d8`

A conforming implementation must accept both source documents, reproduce that
digest exactly, and match the terminal outcomes in `cases.json`.
