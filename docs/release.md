# Release preparation

The initial release is intentionally staged. Repository code may be pushed and
reviewed, but packages and tags are not published until the release discussion.

Release gates:

- [x] Normative specification and schema review complete
- [x] Shared conformance corpus passes in all five libraries
- [x] Python wheel and sdist build and pass `twine check`
- [x] TypeScript package builds, type-checks, tests, audits, and packs
- [x] Go tests and vet pass
- [x] Rust fmt, clippy, tests, docs, and package dry-run pass
- [x] Java tests, static analysis, Javadocs, and package build pass on Java 17
- [x] GitHub CI is green
- [x] Package names and Maven coordinates confirmed
- [x] Release version and tag confirmed

Published 0.1.0 coordinates:

- PyPI: `agent-approval-interchange`
- npm: `agent-approval-interchange`
- Go: `github.com/alexmerced-oss/agent-approval-interchange-spec/go`
- crates.io: `agent-approval-interchange`
- Maven Central: `io.github.alexmercedcoder:agent-approval-interchange`
