//! Agent Approval Interchange Specification 1.0 support library.

use chrono::{DateTime, Utc};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use thiserror::Error;
use uuid::Uuid;

/// Error returned for invalid AAIS documents or state transitions.
#[derive(Debug, Error)]
pub enum ApprovalError {
    #[error("validation error: {0}")]
    Validation(String),
    #[error("conflict: {0}")]
    Conflict(String),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, ApprovalError>;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Origin {
    pub harness: String,
    pub session_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub task_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub graph_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subagent_run_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_run_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Presentation {
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub redacted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub binding_hint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Action {
    pub kind: String,
    pub name: String,
    pub summary: String,
    pub arguments: Map<String, Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub working_directory: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub effects: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub presentation: Option<Presentation>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Risk {
    pub level: String,
    pub reasons: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Choice {
    pub decision: String,
    pub scope: String,
    pub label: String,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub allow_edits: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope_constraints: Option<Map<String, Value>>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub id: String,
    pub created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    pub status: String,
    pub origin: Origin,
    pub action: Action,
    pub action_digest: String,
    pub risk: Risk,
    pub choices: Vec<Choice>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extensions: Option<Map<String, Value>>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Actor {
    pub id: String,
    #[serde(rename = "type")]
    pub actor_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authenticated_by: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Decision {
    pub id: String,
    pub request_id: String,
    pub action_digest: String,
    pub decided_at: String,
    pub decision: String,
    pub scope: String,
    pub actor: Actor,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub replacement_arguments: Option<Map<String, Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extensions: Option<Map<String, Value>>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Resolution {
    pub id: String,
    pub request_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decision_id: Option<String>,
    pub action_digest: String,
    pub resolved_at: String,
    pub outcome: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub effective_scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extensions: Option<Map<String, Value>>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    pub as_of_sequence: u64,
    pub pending: Vec<Request>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Activity {
    pub request_id: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stage: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    pub aais: String,
    #[serde(rename = "type")]
    pub event_type: String,
    pub id: String,
    pub occurred_at: String,
    pub sequence: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stream: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extensions: Option<Map<String, Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request: Option<Request>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decision: Option<Decision>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolution: Option<Resolution>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snapshot: Option<Snapshot>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub activity: Option<Activity>,
}

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 200
        && Regex::new(r"^[A-Za-z0-9][A-Za-z0-9._:-]*$")
            .unwrap()
            .is_match(value)
}
fn parse_time(value: &str) -> Result<DateTime<Utc>> {
    if !(value.ends_with('Z') || Regex::new(r"[+-]\d\d:\d\d$").unwrap().is_match(value)) {
        return Err(ApprovalError::Validation(
            "timestamp requires an explicit offset".into(),
        ));
    }
    DateTime::parse_from_rfc3339(value)
        .map(|v| v.with_timezone(&Utc))
        .map_err(|_| ApprovalError::Validation("invalid RFC 3339 timestamp".into()))
}

/// Compute the RFC 8785 / SHA-256 binding for an action.
pub fn action_digest(action: &Action) -> Result<String> {
    let canonical =
        serde_jcs::to_vec(action).map_err(|e| ApprovalError::Validation(e.to_string()))?;
    Ok(format!("sha256:{:x}", Sha256::digest(canonical)))
}

/// Options for constructing a requested envelope.
pub struct CreateRequestOptions {
    pub action: Action,
    pub origin: Origin,
    pub risk: Risk,
    pub choices: Vec<Choice>,
    pub sequence: u64,
    pub stream: Option<String>,
    pub request_id: Option<String>,
    pub event_id: Option<String>,
    pub created_at: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
}

/// Build and validate an `approval.requested` envelope.
pub fn create_request(options: CreateRequestOptions) -> Result<Envelope> {
    let created = options.created_at.unwrap_or_else(Utc::now);
    let request = Request {
        id: options
            .request_id
            .unwrap_or_else(|| format!("apr_{}", Uuid::new_v4().simple())),
        created_at: created.to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true),
        expires_at: options
            .expires_at
            .map(|value| value.to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true)),
        status: "pending".into(),
        origin: options.origin,
        action_digest: action_digest(&options.action)?,
        action: options.action,
        risk: options.risk,
        choices: options.choices,
        extensions: None,
    };
    let envelope = Envelope {
        aais: "1.0".into(),
        event_type: "approval.requested".into(),
        id: options
            .event_id
            .unwrap_or_else(|| format!("evt_{}", Uuid::new_v4().simple())),
        occurred_at: request.created_at.clone(),
        sequence: options.sequence,
        stream: options.stream,
        extensions: None,
        request: Some(request),
        decision: None,
        resolution: None,
        snapshot: None,
        activity: None,
    };
    validate(&envelope)?;
    Ok(envelope)
}

/// Options for constructing a decision envelope.
pub struct CreateDecisionOptions {
    pub decision: String,
    pub scope: String,
    pub actor: Actor,
    pub sequence: u64,
    pub decision_id: Option<String>,
    pub event_id: Option<String>,
    pub decided_at: Option<DateTime<Utc>>,
    pub replacement_arguments: Option<Map<String, Value>>,
}

/// Build a decision bound to an `approval.requested` envelope.
pub fn create_decision(requested: &Envelope, options: CreateDecisionOptions) -> Result<Envelope> {
    validate(requested)?;
    if requested.event_type != "approval.requested" {
        return Err(ApprovalError::Validation(
            "create_decision requires approval.requested".into(),
        ));
    }
    let at = options.decided_at.unwrap_or_else(Utc::now);
    let request = requested.request.as_ref().unwrap();
    let decision = Decision {
        id: options
            .decision_id
            .unwrap_or_else(|| format!("dec_{}", Uuid::new_v4().simple())),
        request_id: request.id.clone(),
        action_digest: request.action_digest.clone(),
        decided_at: at.to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true),
        decision: options.decision,
        scope: options.scope,
        actor: options.actor,
        replacement_arguments: options.replacement_arguments,
        extensions: None,
    };
    let envelope = Envelope {
        aais: "1.0".into(),
        event_type: "approval.decided".into(),
        id: options
            .event_id
            .unwrap_or_else(|| format!("evt_{}", Uuid::new_v4().simple())),
        occurred_at: decision.decided_at.clone(),
        sequence: options.sequence,
        stream: requested.stream.clone(),
        extensions: None,
        request: None,
        decision: Some(decision),
        resolution: None,
        snapshot: None,
        activity: None,
    };
    validate(&envelope)?;
    Ok(envelope)
}

/// Parse and perform Core validation on one AAIS JSON envelope.
pub fn parse(data: &str) -> Result<Envelope> {
    let envelope: Envelope = serde_json::from_str(data)?;
    validate(&envelope)?;
    Ok(envelope)
}

/// Validate an AAIS envelope.
pub fn validate(e: &Envelope) -> Result<()> {
    if e.aais != "1.0" || !valid_id(&e.id) {
        return Err(ApprovalError::Validation(
            "invalid envelope version or id".into(),
        ));
    }
    parse_time(&e.occurred_at)?;
    let payloads = [
        e.request.is_some(),
        e.decision.is_some(),
        e.resolution.is_some(),
        e.snapshot.is_some(),
        e.activity.is_some(),
    ]
    .iter()
    .filter(|x| **x)
    .count();
    if payloads != 1 {
        return Err(ApprovalError::Validation(
            "exactly one payload is required".into(),
        ));
    }
    match e.event_type.as_str() {
        "approval.requested" => validate_request(
            e.request
                .as_ref()
                .ok_or_else(|| ApprovalError::Validation("request payload required".into()))?,
        ),
        "approval.decided" => validate_decision(
            e.decision
                .as_ref()
                .ok_or_else(|| ApprovalError::Validation("decision payload required".into()))?,
        ),
        "approval.resolved" => validate_resolution(
            e.resolution
                .as_ref()
                .ok_or_else(|| ApprovalError::Validation("resolution payload required".into()))?,
        ),
        "approval.snapshot" => {
            let snapshot = e
                .snapshot
                .as_ref()
                .ok_or_else(|| ApprovalError::Validation("snapshot payload required".into()))?;
            for r in &snapshot.pending {
                validate_request(r)?;
            }
            Ok(())
        }
        "approval.activity" => {
            let a = e
                .activity
                .as_ref()
                .ok_or_else(|| ApprovalError::Validation("activity payload required".into()))?;
            if !valid_id(&a.request_id) || a.message.is_empty() {
                Err(ApprovalError::Validation("invalid activity".into()))
            } else {
                Ok(())
            }
        }
        _ => Err(ApprovalError::Validation("unknown event type".into())),
    }
}

fn validate_request(r: &Request) -> Result<()> {
    if !valid_id(&r.id)
        || r.status != "pending"
        || !valid_id(&r.origin.harness)
        || !valid_id(&r.origin.session_id)
    {
        return Err(ApprovalError::Validation(
            "invalid request identity or origin".into(),
        ));
    }
    let created = parse_time(&r.created_at)?;
    if let Some(expires) = &r.expires_at {
        if parse_time(expires)? <= created {
            return Err(ApprovalError::Validation(
                "expires_at must be later than created_at".into(),
            ));
        }
    }
    if !valid_id(&r.action.kind) || !valid_id(&r.action.name) || r.action.summary.is_empty() {
        return Err(ApprovalError::Validation("invalid action".into()));
    }
    if r.action
        .presentation
        .as_ref()
        .is_some_and(|p| p.redacted && p.binding_hint.as_deref().unwrap_or("").is_empty())
    {
        return Err(ApprovalError::Validation(
            "redacted action requires binding_hint".into(),
        ));
    }
    if action_digest(&r.action)? != r.action_digest {
        return Err(ApprovalError::Validation(
            "action_digest does not match action".into(),
        ));
    }
    if !Regex::new(r"^sha256:[0-9a-f]{64}$")
        .unwrap()
        .is_match(&r.action_digest)
        || !["low", "medium", "high", "critical"].contains(&r.risk.level.as_str())
        || r.risk.reasons.is_empty()
        || r.choices.is_empty()
    {
        return Err(ApprovalError::Validation(
            "invalid digest, risk, or choices".into(),
        ));
    }
    let mut exit = false;
    for c in &r.choices {
        if !["approve", "deny", "cancel"].contains(&c.decision.as_str())
            || !["once", "session", "persistent"].contains(&c.scope.as_str())
            || c.label.is_empty()
        {
            return Err(ApprovalError::Validation("invalid choice".into()));
        }
        if c.decision != "approve" {
            exit = true;
            if c.scope != "once" || c.allow_edits {
                return Err(ApprovalError::Validation(
                    "deny/cancel choice invalid".into(),
                ));
            }
        }
        if c.scope != "once" && c.scope_constraints.as_ref().is_none_or(Map::is_empty) {
            return Err(ApprovalError::Validation(
                "broader scope requires constraints".into(),
            ));
        }
    }
    if !exit {
        return Err(ApprovalError::Validation(
            "at least one deny or cancel choice is required".into(),
        ));
    }
    Ok(())
}
fn validate_decision(d: &Decision) -> Result<()> {
    if !valid_id(&d.id)
        || !valid_id(&d.request_id)
        || !Regex::new(r"^sha256:[0-9a-f]{64}$")
            .unwrap()
            .is_match(&d.action_digest)
        || !["approve", "deny", "cancel"].contains(&d.decision.as_str())
        || !["once", "session", "persistent"].contains(&d.scope.as_str())
        || !valid_id(&d.actor.id)
        || !["human", "policy"].contains(&d.actor.actor_type.as_str())
    {
        return Err(ApprovalError::Validation("invalid decision".into()));
    }
    parse_time(&d.decided_at)?;
    if d.decision != "approve" && (d.scope != "once" || d.replacement_arguments.is_some()) {
        return Err(ApprovalError::Validation(
            "deny/cancel decision invalid".into(),
        ));
    }
    Ok(())
}
fn validate_resolution(r: &Resolution) -> Result<()> {
    if !valid_id(&r.id)
        || !valid_id(&r.request_id)
        || !Regex::new(r"^sha256:[0-9a-f]{64}$")
            .unwrap()
            .is_match(&r.action_digest)
        || ![
            "approved",
            "denied",
            "cancelled",
            "expired",
            "stale",
            "conflict",
            "invalid",
        ]
        .contains(&r.outcome.as_str())
        || r.message.is_empty()
    {
        return Err(ApprovalError::Validation("invalid resolution".into()));
    }
    parse_time(&r.resolved_at)?;
    Ok(())
}

/// Reference in-memory, replay-safe approval state machine.
#[derive(Default)]
pub struct ApprovalStore {
    pending: HashMap<String, Envelope>,
    resolutions: HashMap<String, Envelope>,
    fingerprints: HashMap<String, String>,
    pub last_sequence: u64,
}
impl ApprovalStore {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn add(&mut self, e: Envelope) -> Result<()> {
        validate(&e)?;
        if e.event_type != "approval.requested" {
            return Err(ApprovalError::Validation(
                "add requires approval.requested".into(),
            ));
        }
        let id = e.request.as_ref().unwrap().id.clone();
        if let Some(previous) = self.pending.get(&id) {
            if previous != &e {
                return Err(ApprovalError::Conflict(format!(
                    "request {id} already exists"
                )));
            }
            return Ok(());
        }
        self.last_sequence = self.last_sequence.max(e.sequence);
        self.pending.insert(id, e);
        Ok(())
    }
    pub fn decide(
        &mut self,
        e: Envelope,
        now: DateTime<Utc>,
        current_action: Option<&Action>,
    ) -> Result<Envelope> {
        validate(&e)?;
        if e.event_type != "approval.decided" {
            return Err(ApprovalError::Validation(
                "decide requires approval.decided".into(),
            ));
        }
        let d = e.decision.as_ref().unwrap();
        let fingerprint = format!(
            "sha256:{:x}",
            Sha256::digest(
                serde_jcs::to_vec(d).map_err(|x| ApprovalError::Validation(x.to_string()))?
            )
        );
        if let Some(previous) = self.resolutions.get(&d.request_id) {
            if self.fingerprints.get(&d.request_id) == Some(&fingerprint) {
                return Ok(previous.clone());
            }
            return Err(ApprovalError::Conflict("request already resolved".into()));
        }
        let requested = self
            .pending
            .get(&d.request_id)
            .ok_or_else(|| ApprovalError::Validation("unknown pending request".into()))?;
        let r = requested.request.as_ref().unwrap();
        let (mut outcome, mut message) = match d.decision.as_str() {
            "approve" => ("approved", "Approval accepted."),
            "deny" => ("denied", "Action denied."),
            _ => ("cancelled", "Approval cancelled."),
        };
        if r.expires_at
            .as_ref()
            .is_some_and(|x| parse_time(x).is_ok_and(|t| now >= t))
        {
            outcome = "expired";
            message = "Approval request expired.";
        } else if d.action_digest != r.action_digest
            || current_action.is_some_and(|a| action_digest(a).is_ok_and(|x| x != r.action_digest))
        {
            outcome = "stale";
            message = "The decision does not match the current action.";
        } else if let Some(choice) = r
            .choices
            .iter()
            .find(|c| c.decision == d.decision && c.scope == d.scope)
        {
            if d.replacement_arguments.is_some() && !choice.allow_edits {
                outcome = "invalid";
                message = "This choice does not allow edits.";
            }
        } else {
            outcome = "invalid";
            message = "The selected decision and scope were not offered.";
        }
        self.last_sequence = (self.last_sequence + 1).max(e.sequence);
        let at = now.to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true);
        let resolution = Resolution {
            id: format!("res_{}", d.id),
            request_id: d.request_id.clone(),
            decision_id: Some(d.id.clone()),
            action_digest: r.action_digest.clone(),
            resolved_at: at.clone(),
            outcome: outcome.into(),
            message: message.into(),
            effective_scope: matches!(outcome, "approved" | "denied").then(|| d.scope.clone()),
            extensions: None,
        };
        let result = Envelope {
            aais: "1.0".into(),
            event_type: "approval.resolved".into(),
            id: format!("evt_res_{}", d.id),
            occurred_at: at,
            sequence: self.last_sequence,
            stream: requested.stream.clone(),
            extensions: None,
            request: None,
            decision: None,
            resolution: Some(resolution),
            snapshot: None,
            activity: None,
        };
        validate(&result)?;
        self.pending.remove(&d.request_id);
        self.resolutions
            .insert(d.request_id.clone(), result.clone());
        self.fingerprints.insert(d.request_id.clone(), fingerprint);
        Ok(result)
    }
    pub fn snapshot(&self, stream: Option<String>, now: DateTime<Utc>) -> Envelope {
        Envelope {
            aais: "1.0".into(),
            event_type: "approval.snapshot".into(),
            id: format!("evt_{}", Uuid::new_v4().simple()),
            occurred_at: now.to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true),
            sequence: self.last_sequence,
            stream,
            extensions: None,
            request: None,
            decision: None,
            resolution: None,
            snapshot: Some(Snapshot {
                as_of_sequence: self.last_sequence,
                pending: self
                    .pending
                    .values()
                    .filter(|e| {
                        e.request
                            .as_ref()
                            .unwrap()
                            .expires_at
                            .as_ref()
                            .is_none_or(|value| {
                                parse_time(value).is_ok_and(|expires| now < expires)
                            })
                    })
                    .map(|e| e.request.clone().unwrap())
                    .collect(),
            }),
            activity: None,
        }
    }
    pub fn from_snapshot(e: &Envelope) -> Result<Self> {
        validate(e)?;
        if e.event_type != "approval.snapshot" {
            return Err(ApprovalError::Validation(
                "from_snapshot requires approval.snapshot".into(),
            ));
        }
        let mut store = Self::new();
        store.last_sequence = e.snapshot.as_ref().unwrap().as_of_sequence;
        for request in &e.snapshot.as_ref().unwrap().pending {
            let wrapper = Envelope {
                aais: "1.0".into(),
                event_type: "approval.requested".into(),
                id: format!("restore_{}", request.id),
                occurred_at: request.created_at.clone(),
                sequence: store.last_sequence,
                stream: e.stream.clone(),
                extensions: None,
                request: Some(request.clone()),
                decision: None,
                resolution: None,
                snapshot: None,
                activity: None,
            };
            store.add(wrapper)?;
        }
        Ok(store)
    }
}
