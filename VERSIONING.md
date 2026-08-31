# Versioning

AAIS has a document-model version and independently published support-library
versions. The `aais` field uses `MAJOR.MINOR`; editorial and conformance fixes
that do not alter the data model use a specification patch release. New
optional standard fields require a minor release. Incompatible semantics or
required fields require a major release.

Support libraries use semantic versioning and declare the newest AAIS
maintenance release they pass. The initial packages remain `0.1.0` until the
release discussion confirms the public coordinates and spec tag.
