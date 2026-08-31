# Release preparation

The initial release is intentionally staged. Repository code may be pushed and
reviewed, but packages and tags are not published until the release discussion.

Release gates:

- [ ] Normative specification and schema review complete
- [ ] Shared conformance corpus passes in all five libraries
- [ ] Python wheel and sdist build and pass `twine check`
- [ ] TypeScript package builds, type-checks, tests, audits, and packs
- [ ] Go tests and vet pass
- [ ] Rust fmt, clippy, tests, docs, and package dry-run pass
- [ ] Java tests, static analysis, Javadocs, and package build pass on Java 17
- [ ] GitHub CI is green
- [ ] Package names and Maven coordinates confirmed
- [ ] Release version and tag confirmed

Proposed initial coordinates:

- PyPI: `agent-approval-interchange`
- npm: `agent-approval-interchange`
- Go: `github.com/alexmerced-oss/agent-approval-interchange-spec/go`
- crates.io: `agent-approval-interchange`
- Maven Central: `io.github.alexmercedcoder:agent-approval-interchange`
