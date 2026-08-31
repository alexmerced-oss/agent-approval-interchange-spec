package aais

import (
	"os"
	"testing"
	"time"
)

func fixture(t *testing.T, name string) Envelope {
	t.Helper()
	data, err := os.ReadFile("../../examples/" + name)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	return envelope
}

func TestSharedDigestAndValidation(t *testing.T) {
	request := fixture(t, "shell-approval.json")
	digest, err := ActionDigest(request.Request.Action)
	if err != nil || digest != request.Request.ActionDigest {
		t.Fatalf("digest mismatch: %s %v", digest, err)
	}
	_ = fixture(t, "approve-once.json")
}
func TestCanonicalKeyOrder(t *testing.T) {
	a, _ := ActionDigest(Action{Kind: "x", Name: "x", Summary: "x", Arguments: map[string]any{"b": 2, "a": 1}})
	b, _ := ActionDigest(Action{Kind: "x", Name: "x", Summary: "x", Arguments: map[string]any{"a": 1, "b": 2}})
	if a != b {
		t.Fatal("key order changed digest")
	}
}
func TestStoreApprovalReplayAndConflict(t *testing.T) {
	store := NewStore()
	request := fixture(t, "shell-approval.json")
	decision := fixture(t, "approve-once.json")
	if err := store.Add(request); err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 8, 30, 18, 1, 0, 0, time.UTC)
	first, err := store.Decide(decision, at, nil)
	if err != nil || first.Resolution.Outcome != "approved" {
		t.Fatalf("%v %#v", err, first.Resolution)
	}
	second, err := store.Decide(decision, at, nil)
	if err != nil || second.Resolution.ID != first.Resolution.ID {
		t.Fatal("identical replay not idempotent")
	}
	changed := decision
	copy := *decision.Decision
	changed.Decision = &copy
	changed.Decision.ID = "dec_other"
	changed.Decision.Decision = "deny"
	if _, err := store.Decide(changed, at, nil); err == nil {
		t.Fatal("expected conflict")
	}
}
func TestExpiryAndUnofferedScope(t *testing.T) {
	request := fixture(t, "shell-approval.json")
	decision := fixture(t, "approve-once.json")
	expired := NewStore()
	_ = expired.Add(request)
	result, err := expired.Decide(decision, time.Date(2026, 8, 30, 19, 0, 0, 0, time.UTC), nil)
	if err != nil || result.Resolution.Outcome != "expired" {
		t.Fatal("expected expired")
	}
	store := NewStore()
	_ = store.Add(request)
	unoffered := decision
	copy := *decision.Decision
	unoffered.Decision = &copy
	unoffered.Decision.ID = "dec_persist"
	unoffered.Decision.Scope = "persistent"
	result, err = store.Decide(unoffered, time.Date(2026, 8, 30, 18, 1, 0, 0, time.UTC), nil)
	if err != nil || result.Resolution.Outcome != "invalid" {
		t.Fatalf("expected invalid: %v %#v", err, result.Resolution)
	}
}
func TestSnapshot(t *testing.T) {
	store := NewStore()
	_ = store.Add(fixture(t, "shell-approval.json"))
	at := time.Date(2026, 8, 30, 18, 1, 0, 0, time.UTC)
	snapshot := store.Snapshot("session_s1", at)
	if err := Validate(snapshot); err != nil || len(snapshot.Snapshot.Pending) != 1 {
		t.Fatalf("invalid snapshot: %v", err)
	}
	restored, err := FromSnapshot(snapshot)
	if err != nil || len(restored.Snapshot("", at).Snapshot.Pending) != 1 {
		t.Fatalf("snapshot restore failed: %v", err)
	}
}

func TestBuilders(t *testing.T) {
	at := time.Date(2026, 8, 30, 18, 0, 0, 0, time.UTC)
	expires := at.Add(10 * time.Minute)
	request, err := CreateRequest(CreateRequestOptions{Action: fixture(t, "shell-approval.json").Request.Action, Origin: Origin{Harness: "example", SessionID: "s-1"}, Risk: Risk{Level: "low", Reasons: []string{"test"}}, Choices: []Choice{{Decision: "approve", Scope: "once", Label: "Allow"}, {Decision: "deny", Scope: "once", Label: "Deny"}}, Sequence: 1, CreatedAt: at, ExpiresAt: &expires})
	if err != nil {
		t.Fatal(err)
	}
	_, err = CreateDecision(request, CreateDecisionOptions{Decision: "approve", Scope: "once", Actor: Actor{ID: "alex", Type: "human"}, Sequence: 2, DecidedAt: at.Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
}
