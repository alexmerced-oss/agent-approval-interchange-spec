// Package aais validates and manages Agent Approval Interchange Specification 1.0 documents.
package aais

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/gowebpki/jcs"
)

var (
	idPattern     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]*$`)
	digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

// ValidationError reports a malformed AAIS document or transition.
type ValidationError struct{ Message string }

func (e *ValidationError) Error() string { return e.Message }

// ConflictError reports a competing resolution for an already resolved request.
type ConflictError struct{ Message string }

func (e *ConflictError) Error() string { return e.Message }

// Origin identifies the execution that requested approval.
type Origin struct {
	Harness       string `json:"harness"`
	SessionID     string `json:"session_id"`
	RunID         string `json:"run_id,omitempty"`
	TaskID        string `json:"task_id,omitempty"`
	GraphID       string `json:"graph_id,omitempty"`
	NodeID        string `json:"node_id,omitempty"`
	AgentID       string `json:"agent_id,omitempty"`
	Profile       string `json:"profile,omitempty"`
	SubagentRunID string `json:"subagent_run_id,omitempty"`
	ParentRunID   string `json:"parent_run_id,omitempty"`
	Project       string `json:"project,omitempty"`
}

// Presentation provides safe display hints.
type Presentation struct {
	Redacted    bool   `json:"redacted,omitempty"`
	BindingHint string `json:"binding_hint,omitempty"`
	Details     string `json:"details,omitempty"`
}

// Action is the exact proposed operation bound by ActionDigest.
type Action struct {
	Kind             string         `json:"kind"`
	Name             string         `json:"name"`
	Summary          string         `json:"summary"`
	Arguments        map[string]any `json:"arguments"`
	Resource         string         `json:"resource,omitempty"`
	WorkingDirectory string         `json:"working_directory,omitempty"`
	Effects          []string       `json:"effects,omitempty"`
	Presentation     *Presentation  `json:"presentation,omitempty"`
}

// Risk is display-safe advisory risk information.
type Risk struct {
	Level   string   `json:"level"`
	Reasons []string `json:"reasons"`
}

// Choice is an authority-offered decision and scope tuple.
type Choice struct {
	Decision         string         `json:"decision"`
	Scope            string         `json:"scope"`
	Label            string         `json:"label"`
	ScopeConstraints map[string]any `json:"scope_constraints,omitempty"`
}

// Request is a pending approval request.
type Request struct {
	ID           string         `json:"id"`
	CreatedAt    string         `json:"created_at"`
	ExpiresAt    string         `json:"expires_at,omitempty"`
	Status       string         `json:"status"`
	Origin       Origin         `json:"origin"`
	Action       Action         `json:"action"`
	ActionDigest string         `json:"action_digest"`
	Risk         Risk           `json:"risk"`
	Choices      []Choice       `json:"choices"`
	Extensions   map[string]any `json:"extensions,omitempty"`
}

// Actor is the authenticated decision principal.
type Actor struct {
	ID              string `json:"id"`
	Type            string `json:"type"`
	DisplayName     string `json:"display_name,omitempty"`
	AuthenticatedBy string `json:"authenticated_by,omitempty"`
}

// Decision is a response bound to one request and action digest.
type Decision struct {
	ID           string         `json:"id"`
	RequestID    string         `json:"request_id"`
	ActionDigest string         `json:"action_digest"`
	DecidedAt    string         `json:"decided_at"`
	Decision     string         `json:"decision"`
	Scope        string         `json:"scope"`
	Actor        Actor          `json:"actor"`
	Extensions   map[string]any `json:"extensions,omitempty"`
}

// Resolution is the authority's terminal result.
type Resolution struct {
	ID             string         `json:"id"`
	RequestID      string         `json:"request_id"`
	DecisionID     string         `json:"decision_id,omitempty"`
	ActionDigest   string         `json:"action_digest"`
	ResolvedAt     string         `json:"resolved_at"`
	Outcome        string         `json:"outcome"`
	Message        string         `json:"message"`
	EffectiveScope string         `json:"effective_scope,omitempty"`
	Extensions     map[string]any `json:"extensions,omitempty"`
}

// Snapshot contains all unresolved requests at a stream sequence.
type Snapshot struct {
	AsOfSequence uint64    `json:"as_of_sequence"`
	Pending      []Request `json:"pending"`
}

// Activity is safe progress associated with a request.
type Activity struct {
	RequestID string `json:"request_id"`
	Message   string `json:"message"`
	Stage     string `json:"stage,omitempty"`
}

// Envelope is the AAIS 1.0 event envelope.
type Envelope struct {
	AAIS       string         `json:"aais"`
	Type       string         `json:"type"`
	ID         string         `json:"id"`
	OccurredAt string         `json:"occurred_at"`
	Sequence   uint64         `json:"sequence"`
	Stream     string         `json:"stream,omitempty"`
	Extensions map[string]any `json:"extensions,omitempty"`
	Request    *Request       `json:"request,omitempty"`
	Decision   *Decision      `json:"decision,omitempty"`
	Resolution *Resolution    `json:"resolution,omitempty"`
	Snapshot   *Snapshot      `json:"snapshot,omitempty"`
	Activity   *Activity      `json:"activity,omitempty"`
}

// Parse decodes one JSON envelope while rejecting unknown fields and trailing data.
func Parse(data []byte) (Envelope, error) {
	var envelope Envelope
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil {
		return Envelope{}, &ValidationError{err.Error()}
	}
	if err := ensureEOF(decoder); err != nil {
		return Envelope{}, err
	}
	if err := Validate(envelope); err != nil {
		return Envelope{}, err
	}
	return envelope, nil
}

func ensureEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return &ValidationError{"document has trailing JSON data"}
	}
	return nil
}

func validID(value string) bool {
	return len(value) > 0 && len(value) <= 200 && idPattern.MatchString(value)
}
func parseTime(value string) (time.Time, error) {
	if !(strings.HasSuffix(value, "Z") || regexp.MustCompile(`[+-]\d\d:\d\d$`).MatchString(value)) {
		return time.Time{}, &ValidationError{"timestamp requires explicit offset"}
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}, &ValidationError{"invalid RFC 3339 timestamp"}
	}
	return parsed, nil
}

// ActionDigest returns the RFC 8785 / SHA-256 binding for an action.
func ActionDigest(action Action) (string, error) {
	data, err := json.Marshal(action)
	if err != nil {
		return "", err
	}
	canonical, err := jcs.Transform(data)
	if err != nil {
		return "", &ValidationError{"action is not canonicalizable JSON"}
	}
	sum := sha256.Sum256(canonical)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func newID(prefix string) string {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		panic("crypto/rand unavailable: " + err.Error())
	}
	return prefix + "_" + hex.EncodeToString(raw)
}

// CreateRequestOptions configures a requested-envelope builder.
type CreateRequestOptions struct {
	Action    Action
	Origin    Origin
	Risk      Risk
	Choices   []Choice
	Sequence  uint64
	Stream    string
	RequestID string
	EventID   string
	CreatedAt time.Time
	ExpiresAt *time.Time
}

// CreateRequest builds and validates an approval.requested envelope.
func CreateRequest(options CreateRequestOptions) (Envelope, error) {
	created := options.CreatedAt
	if created.IsZero() {
		created = time.Now()
	}
	requestID := options.RequestID
	if requestID == "" {
		requestID = newID("apr")
	}
	eventID := options.EventID
	if eventID == "" {
		eventID = newID("evt")
	}
	digest, err := ActionDigest(options.Action)
	if err != nil {
		return Envelope{}, err
	}
	request := &Request{ID: requestID, CreatedAt: created.UTC().Format(time.RFC3339Nano), Status: "pending", Origin: options.Origin, Action: options.Action, ActionDigest: digest, Risk: options.Risk, Choices: options.Choices}
	if options.ExpiresAt != nil {
		request.ExpiresAt = options.ExpiresAt.UTC().Format(time.RFC3339Nano)
	}
	envelope := Envelope{AAIS: "1.0", Type: "approval.requested", ID: eventID, OccurredAt: request.CreatedAt, Sequence: options.Sequence, Stream: options.Stream, Request: request}
	if err := Validate(envelope); err != nil {
		return Envelope{}, err
	}
	return envelope, nil
}

// CreateDecisionOptions configures a decision builder.
type CreateDecisionOptions struct {
	Decision   string
	Scope      string
	Actor      Actor
	Sequence   uint64
	Stream     string
	DecisionID string
	EventID    string
	DecidedAt  time.Time
}

// CreateDecision builds a decision bound to an approval.requested envelope.
func CreateDecision(requested Envelope, options CreateDecisionOptions) (Envelope, error) {
	if err := Validate(requested); err != nil {
		return Envelope{}, err
	}
	if requested.Type != "approval.requested" {
		return Envelope{}, &ValidationError{"CreateDecision requires approval.requested"}
	}
	at := options.DecidedAt
	if at.IsZero() {
		at = time.Now()
	}
	decisionID := options.DecisionID
	if decisionID == "" {
		decisionID = newID("dec")
	}
	eventID := options.EventID
	if eventID == "" {
		eventID = newID("evt")
	}
	decision := &Decision{ID: decisionID, RequestID: requested.Request.ID, ActionDigest: requested.Request.ActionDigest, DecidedAt: at.UTC().Format(time.RFC3339Nano), Decision: options.Decision, Scope: options.Scope, Actor: options.Actor}
	envelope := Envelope{AAIS: "1.0", Type: "approval.decided", ID: eventID, OccurredAt: decision.DecidedAt, Sequence: options.Sequence, Stream: options.Stream, Decision: decision}
	if err := Validate(envelope); err != nil {
		return Envelope{}, err
	}
	return envelope, nil
}

// Validate performs Core AAIS validation.
func Validate(e Envelope) error {
	if e.AAIS != "1.0" {
		return &ValidationError{"aais must equal 1.0"}
	}
	if !validID(e.ID) {
		return &ValidationError{"invalid envelope id"}
	}
	if _, err := parseTime(e.OccurredAt); err != nil {
		return err
	}
	payloads := 0
	for _, present := range []bool{e.Request != nil, e.Decision != nil, e.Resolution != nil, e.Snapshot != nil, e.Activity != nil} {
		if present {
			payloads++
		}
	}
	if payloads != 1 {
		return &ValidationError{"exactly one event payload is required"}
	}
	switch e.Type {
	case "approval.requested":
		if e.Request == nil {
			return &ValidationError{"request payload required"}
		}
		return validateRequest(*e.Request)
	case "approval.decided":
		if e.Decision == nil {
			return &ValidationError{"decision payload required"}
		}
		return validateDecision(*e.Decision)
	case "approval.resolved":
		if e.Resolution == nil {
			return &ValidationError{"resolution payload required"}
		}
		return validateResolution(*e.Resolution)
	case "approval.snapshot":
		if e.Snapshot == nil {
			return &ValidationError{"snapshot payload required"}
		}
		for _, request := range e.Snapshot.Pending {
			if err := validateRequest(request); err != nil {
				return err
			}
		}
		return nil
	case "approval.activity":
		if e.Activity == nil || !validID(e.Activity.RequestID) || e.Activity.Message == "" {
			return &ValidationError{"invalid activity"}
		}
		return nil
	default:
		return &ValidationError{"unknown event type"}
	}
}

func validateRequest(r Request) error {
	if !validID(r.ID) || r.Status != "pending" || !validID(r.Origin.Harness) || !validID(r.Origin.SessionID) {
		return &ValidationError{"invalid request identity or origin"}
	}
	created, err := parseTime(r.CreatedAt)
	if err != nil {
		return err
	}
	if r.ExpiresAt != "" {
		expires, err := parseTime(r.ExpiresAt)
		if err != nil || !expires.After(created) {
			return &ValidationError{"expires_at must be later than created_at"}
		}
	}
	if !validID(r.Action.Kind) || !validID(r.Action.Name) || r.Action.Summary == "" || r.Action.Arguments == nil {
		return &ValidationError{"invalid action"}
	}
	if r.Action.Presentation != nil && r.Action.Presentation.Redacted && r.Action.Presentation.BindingHint == "" {
		return &ValidationError{"redacted action requires binding_hint"}
	}
	digest, err := ActionDigest(r.Action)
	if err != nil {
		return err
	}
	if r.ActionDigest != digest {
		return &ValidationError{"action_digest does not match action"}
	}
	if !digestPattern.MatchString(r.ActionDigest) || !slices.Contains([]string{"low", "medium", "high", "critical"}, r.Risk.Level) || len(r.Risk.Reasons) == 0 || len(r.Choices) == 0 {
		return &ValidationError{"invalid digest, risk, or choices"}
	}
	hasExit := false
	seenChoices := map[string]bool{}
	for _, c := range r.Choices {
		if !slices.Contains([]string{"approve", "deny", "cancel"}, c.Decision) || !slices.Contains([]string{"once", "session", "persistent"}, c.Scope) || c.Label == "" {
			return &ValidationError{"invalid choice"}
		}
		if c.Decision != "approve" {
			hasExit = true
			if c.Scope != "once" {
				return &ValidationError{"deny and cancel choices must use once"}
			}
		}
		key := c.Decision + "\x00" + c.Scope
		if seenChoices[key] {
			return &ValidationError{"decision and scope tuples must be unique"}
		}
		seenChoices[key] = true
		if c.Scope != "once" && len(c.ScopeConstraints) == 0 {
			return &ValidationError{"session and persistent choices require constraints"}
		}
	}
	if !hasExit {
		return &ValidationError{"at least one deny or cancel choice is required"}
	}
	return nil
}

func validateDecision(d Decision) error {
	if !validID(d.ID) || !validID(d.RequestID) || !digestPattern.MatchString(d.ActionDigest) || !slices.Contains([]string{"approve", "deny", "cancel"}, d.Decision) || !slices.Contains([]string{"once", "session", "persistent"}, d.Scope) || !validID(d.Actor.ID) || !slices.Contains([]string{"human", "policy"}, d.Actor.Type) {
		return &ValidationError{"invalid decision"}
	}
	if _, err := parseTime(d.DecidedAt); err != nil {
		return err
	}
	if d.Decision != "approve" && d.Scope != "once" {
		return &ValidationError{"deny and cancel decisions must use once"}
	}
	return nil
}

func validateResolution(r Resolution) error {
	if !validID(r.ID) || !validID(r.RequestID) || !digestPattern.MatchString(r.ActionDigest) || !slices.Contains([]string{"approved", "denied", "cancelled", "expired", "stale", "conflict", "invalid"}, r.Outcome) || r.Message == "" {
		return &ValidationError{"invalid resolution"}
	}
	_, err := parseTime(r.ResolvedAt)
	return err
}

// Store is a concurrency-safe reference in-memory approval state machine.
type Store struct {
	mu           sync.Mutex
	pending      map[string]Envelope
	resolutions  map[string]Envelope
	fingerprints map[string]string
	lastSequence uint64
}

func NewStore() *Store {
	return &Store{pending: map[string]Envelope{}, resolutions: map[string]Envelope{}, fingerprints: map[string]string{}}
}

// Add records a pending request idempotently.
func (s *Store) Add(e Envelope) error {
	if err := Validate(e); err != nil {
		return err
	}
	if e.Type != "approval.requested" {
		return &ValidationError{"Add requires approval.requested"}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	id := e.Request.ID
	if previous, ok := s.pending[id]; ok {
		a, _ := json.Marshal(previous)
		b, _ := json.Marshal(e)
		if !bytes.Equal(a, b) {
			return &ConflictError{fmt.Sprintf("request %s already exists", id)}
		}
		return nil
	}
	s.pending[id] = e
	s.lastSequence = max(s.lastSequence, e.Sequence)
	return nil
}

// Decide validates and atomically resolves a pending request.
func (s *Store) Decide(e Envelope, now time.Time, currentAction *Action) (Envelope, error) {
	if err := Validate(e); err != nil {
		return Envelope{}, err
	}
	if e.Type != "approval.decided" {
		return Envelope{}, &ValidationError{"Decide requires approval.decided"}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	d := e.Decision
	fp, _ := ActionDigest(Action{Kind: "decision", Name: "decision", Summary: "decision", Arguments: map[string]any{"value": d}})
	id := d.RequestID
	if previous, ok := s.resolutions[id]; ok {
		if s.fingerprints[id] == fp {
			return previous, nil
		}
		return Envelope{}, &ConflictError{fmt.Sprintf("request %s already resolved", id)}
	}
	requested, ok := s.pending[id]
	if !ok {
		return Envelope{}, &ValidationError{"unknown pending request"}
	}
	r := requested.Request
	outcome, message := "cancelled", "Approval cancelled."
	if d.Decision == "approve" {
		outcome, message = "approved", "Approval accepted."
	} else if d.Decision == "deny" {
		outcome, message = "denied", "Action denied."
	}
	if r.ExpiresAt != "" {
		expires, _ := parseTime(r.ExpiresAt)
		if !now.Before(expires) {
			outcome, message = "expired", "Approval request expired."
		}
	}
	if outcome != "expired" && d.ActionDigest != r.ActionDigest {
		outcome, message = "stale", "Decision does not match the requested action."
	}
	if outcome != "expired" && currentAction != nil {
		digest, _ := ActionDigest(*currentAction)
		if digest != r.ActionDigest {
			outcome, message = "stale", "The action changed after presentation."
		}
	}
	if outcome != "expired" && outcome != "stale" {
		offered := false
		for _, c := range r.Choices {
			if c.Decision == d.Decision && c.Scope == d.Scope {
				offered = true
			}
		}
		if !offered {
			outcome, message = "invalid", "The selected decision and scope were not offered."
		}
	}
	at := now.UTC().Format(time.RFC3339Nano)
	s.lastSequence = max(s.lastSequence+1, e.Sequence)
	resolution := &Resolution{ID: "res_" + d.ID, RequestID: id, DecisionID: d.ID, ActionDigest: r.ActionDigest, ResolvedAt: at, Outcome: outcome, Message: message}
	if outcome == "approved" || outcome == "denied" {
		resolution.EffectiveScope = d.Scope
	}
	result := Envelope{AAIS: "1.0", Type: "approval.resolved", ID: "evt_res_" + d.ID, OccurredAt: at, Sequence: s.lastSequence, Stream: requested.Stream, Resolution: resolution}
	if err := Validate(result); err != nil {
		return Envelope{}, err
	}
	delete(s.pending, id)
	s.resolutions[id] = result
	s.fingerprints[id] = fp
	return result, nil
}

// Snapshot returns all unresolved requests.
func (s *Store) Snapshot(stream string, now time.Time) Envelope {
	s.mu.Lock()
	defer s.mu.Unlock()
	if now.IsZero() {
		now = time.Now()
	}
	pending := make([]Request, 0, len(s.pending))
	for _, e := range s.pending {
		if e.Request.ExpiresAt == "" {
			pending = append(pending, *e.Request)
			continue
		}
		expires, _ := parseTime(e.Request.ExpiresAt)
		if now.Before(expires) {
			pending = append(pending, *e.Request)
		}
	}
	return Envelope{AAIS: "1.0", Type: "approval.snapshot", ID: newID("evt"), OccurredAt: now.UTC().Format(time.RFC3339Nano), Sequence: s.lastSequence, Stream: stream, Snapshot: &Snapshot{AsOfSequence: s.lastSequence, Pending: pending}}
}

// FromSnapshot restores the unresolved set from a validated snapshot.
func FromSnapshot(envelope Envelope) (*Store, error) {
	if err := Validate(envelope); err != nil {
		return nil, err
	}
	if envelope.Type != "approval.snapshot" {
		return nil, &ValidationError{"FromSnapshot requires approval.snapshot"}
	}
	store := NewStore()
	store.lastSequence = envelope.Snapshot.AsOfSequence
	for index := range envelope.Snapshot.Pending {
		request := envelope.Snapshot.Pending[index]
		wrapper := Envelope{AAIS: "1.0", Type: "approval.requested", ID: "restore_" + request.ID, OccurredAt: request.CreatedAt, Sequence: store.lastSequence, Stream: envelope.Stream, Request: &request}
		if err := store.Add(wrapper); err != nil {
			return nil, err
		}
	}
	return store, nil
}
