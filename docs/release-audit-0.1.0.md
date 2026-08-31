# 0.1.0 release-candidate audit

## Scope

- Normative AAIS 1.0 model and security requirements
- JSON Schema Draft 2020-12
- Shared canonical action and lifecycle vectors
- Python, TypeScript, Go, Rust, and Java support libraries
- CI, package metadata, documentation, and registry dry runs

## Verified locally

- Python: 8 tests, Ruff, isolated wheel/sdist build, and Twine checks
- TypeScript: typecheck, 7 tests, ESM/CJS/types build, zero-audit result,
  and npm tarball dry run
- Go: tests and vet with Go 1.26.7; module declares Go 1.23
- Rust: fmt, 5 integration tests, Clippy with warnings denied, docs, and
  crate package dry run; MSRV declared as 1.85
- Java: 6 tests, compilation with all lint warnings denied, sources,
  Javadocs, and Maven package on Java 17

## Registry check

On 2026-08-30, the proposed npm, PyPI, crates.io, and Maven coordinates had no
matching published package. Registry ownership is not reserved until publish.

## Release decision still required

- Confirm AAIS name and the 1.0 semantic boundary.
- Decide whether the first package release is `0.1.0` while the specification
  remains a release candidate, or whether all artifacts should begin at 1.0.0.
- Confirm the proposed coordinates in `docs/release.md`.
