use agent_approval_interchange::{
    Actor, ApprovalError, ApprovalStore, CreateDecisionOptions, CreateRequestOptions,
    action_digest, create_decision, create_request, parse,
};
use chrono::{TimeZone, Utc};
use std::fs;

fn fixture(name: &str) -> agent_approval_interchange::Envelope {
    parse(&fs::read_to_string(format!("../examples/{name}")).unwrap()).unwrap()
}

#[test]
fn shared_digest_and_validation() {
    let request = fixture("shell-approval.json");
    assert_eq!(
        action_digest(&request.request.unwrap().action).unwrap(),
        "sha256:157f438a55ce7db6aa61c8515f0b48ce2851b9bad6c5b67bb3eb34ff353fd9d8"
    );
    fixture("approve-once.json");
}
#[test]
fn approval_replay_conflict_and_snapshot() {
    let mut store = ApprovalStore::new();
    store.add(fixture("shell-approval.json")).unwrap();
    let decision = fixture("approve-once.json");
    let at = Utc.with_ymd_and_hms(2026, 8, 30, 18, 1, 0).unwrap();
    let first = store.decide(decision.clone(), at, None).unwrap();
    assert_eq!(first.resolution.as_ref().unwrap().outcome, "approved");
    assert_eq!(store.decide(decision.clone(), at, None).unwrap(), first);
    let mut changed = decision;
    let body = changed.decision.as_mut().unwrap();
    body.id = "dec_other".into();
    body.decision = "deny".into();
    assert!(matches!(
        store.decide(changed, at, None),
        Err(ApprovalError::Conflict(_))
    ));
}
#[test]
fn expiry_and_unoffered_scope() {
    let mut expired = ApprovalStore::new();
    expired.add(fixture("shell-approval.json")).unwrap();
    let at = Utc.with_ymd_and_hms(2026, 8, 30, 19, 0, 0).unwrap();
    assert_eq!(
        expired
            .decide(fixture("approve-once.json"), at, None)
            .unwrap()
            .resolution
            .unwrap()
            .outcome,
        "expired"
    );
    let mut store = ApprovalStore::new();
    store.add(fixture("shell-approval.json")).unwrap();
    let mut decision = fixture("approve-once.json");
    decision.decision.as_mut().unwrap().scope = "persistent".into();
    let at = Utc.with_ymd_and_hms(2026, 8, 30, 18, 1, 0).unwrap();
    assert_eq!(
        store
            .decide(decision, at, None)
            .unwrap()
            .resolution
            .unwrap()
            .outcome,
        "invalid"
    );
}
#[test]
fn snapshot_round_trip() {
    let mut store = ApprovalStore::new();
    store.add(fixture("shell-approval.json")).unwrap();
    let at = Utc.with_ymd_and_hms(2026, 8, 30, 18, 1, 0).unwrap();
    let snapshot = store.snapshot(Some("session_s1".into()), at);
    let restored = ApprovalStore::from_snapshot(&snapshot).unwrap();
    assert_eq!(
        restored.snapshot(None, at).snapshot.unwrap().pending.len(),
        1
    );
}

#[test]
fn builders_are_valid() {
    let source = fixture("shell-approval.json").request.unwrap();
    let at = Utc.with_ymd_and_hms(2026, 8, 30, 18, 0, 0).unwrap();
    let request = create_request(CreateRequestOptions {
        action: source.action,
        origin: source.origin,
        risk: source.risk,
        choices: source.choices,
        sequence: 1,
        stream: Some("session_s1".into()),
        request_id: None,
        event_id: None,
        created_at: Some(at),
        expires_at: Some(at + chrono::Duration::minutes(10)),
    })
    .unwrap();
    create_decision(
        &request,
        CreateDecisionOptions {
            decision: "approve".into(),
            scope: "once".into(),
            actor: Actor {
                id: "alex".into(),
                actor_type: "human".into(),
                display_name: None,
                authenticated_by: None,
            },
            sequence: 2,
            stream: Some("presenter_alex".into()),
            decision_id: None,
            event_id: None,
            decided_at: Some(at + chrono::Duration::minutes(1)),
        },
    )
    .unwrap();
}
