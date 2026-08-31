# Agent Approval Interchange for Go

Go 1.23+ types, strict JSON parsing, RFC 8785 action binding, Core validation,
and a concurrency-safe in-memory approval state machine for AAIS 1.0.

```go
envelope, err := aais.Parse(data)
store := aais.NewStore()
err = store.Add(envelope)
```
