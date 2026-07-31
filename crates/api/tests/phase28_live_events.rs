#![allow(
    let_underscore_drop,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_panics_doc,
    clippy::print_stderr,
    clippy::too_many_lines,
    clippy::let_underscore_untyped
)]
//! Phase 28 acceptance: the project change feed now covers epics and comments,
//! not just issues, so an open detail view can stay live for every kind of
//! change rather than only issue field edits.

mod common;

use common::{TestApp, delete_bearer, post_json_bearer, req};
use serde_json::{Value, json};

const STRONG_PW: &str = "7xK!pq2$mz9Wbe#aQ";

async fn owner_with_project(app: &TestApp, tag: &str) -> (String, String) {
    let _ = app
        .register(&format!("{tag}@example.com"), tag, STRONG_PW)
        .await;
    let token = app
        .login(&format!("{tag}@example.com"), STRONG_PW)
        .await
        .access_token()
        .unwrap();
    let project = app
        .send(post_json_bearer(
            "/api/v1/projects",
            &token,
            &json!({ "name": "Live" }),
        ))
        .await;
    assert_eq!(project.status, 201, "{:?}", project.json);
    (token, project.json["id"].as_str().unwrap().to_owned())
}

/// Drains everything currently buffered on the feed and returns the payloads.
fn drain(
    rx: &mut tokio::sync::broadcast::Receiver<intellipilot_api::events::ProjectEvent>,
) -> Vec<Value> {
    let mut out = Vec::new();
    while let Ok(ev) = rx.try_recv() {
        if let Ok(v) = serde_json::from_str::<Value>(ev.as_str()) {
            out.push(v);
        }
    }
    out
}

fn find<'a>(events: &'a [Value], name: &str) -> Option<&'a Value> {
    events.iter().find(|e| e["event"] == name)
}

#[tokio::test]
async fn epic_create_and_update_publish_events() {
    require_db!();
    let app = TestApp::spawn().await;
    let (token, pid) = owner_with_project(&app, "liveepic").await;
    let project_uuid = uuid::Uuid::parse_str(&pid).unwrap();
    let mut rx = app.events.subscribe(project_uuid);

    let created = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/epics"),
            &token,
            &json!({ "subject": "Live epic" }),
        ))
        .await;
    assert_eq!(created.status, 201, "{:?}", created.json);
    let epic_id = created.json["id"].as_str().unwrap().to_owned();

    let events = drain(&mut rx);
    let ev = find(&events, "epic.created").expect("epic.created not published");
    assert_eq!(ev["epic"]["id"], Value::String(epic_id.clone()));
    assert_eq!(ev["project_id"], Value::String(pid.clone()));
    assert!(
        ev["actor_id"].is_string(),
        "actor_id lets clients suppress self-echo: {ev:?}"
    );

    let etag = created.header("etag").unwrap().to_owned();
    let updated = app
        .send(req(
            "PATCH",
            &format!("/api/v1/projects/{pid}/epics/{epic_id}"),
            Some(&token),
            &[("if-match", &etag)],
            Some(&json!({ "subject": "Renamed" })),
        ))
        .await;
    assert_eq!(updated.status, 200, "{:?}", updated.json);

    let events = drain(&mut rx);
    let ev = find(&events, "epic.updated").expect("epic.updated not published");
    assert_eq!(ev["epic"]["subject"], Value::String("Renamed".to_owned()));
    // The full entity travels with the event so subscribers need no re-fetch.
    assert!(ev["epic"]["version"].is_number());
}

#[tokio::test]
async fn epic_delete_publishes_event() {
    require_db!();
    let app = TestApp::spawn().await;
    let (token, pid) = owner_with_project(&app, "liveepicdel").await;
    let project_uuid = uuid::Uuid::parse_str(&pid).unwrap();

    let created = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/epics"),
            &token,
            &json!({ "subject": "Doomed" }),
        ))
        .await;
    let epic_id = created.json["id"].as_str().unwrap().to_owned();
    let etag = created.header("etag").unwrap().to_owned();

    let mut rx = app.events.subscribe(project_uuid);
    let deleted = app
        .send(req(
            "DELETE",
            &format!("/api/v1/projects/{pid}/epics/{epic_id}"),
            Some(&token),
            &[("if-match", &etag)],
            None,
        ))
        .await;
    assert_eq!(deleted.status, 204, "{:?}", deleted.json);

    let events = drain(&mut rx);
    let ev = find(&events, "epic.deleted").expect("epic.deleted not published");
    assert_eq!(ev["epic_id"], Value::String(epic_id));
}

#[tokio::test]
async fn comment_lifecycle_publishes_events() {
    require_db!();
    let app = TestApp::spawn().await;
    let (token, pid) = owner_with_project(&app, "livecomment").await;
    let project_uuid = uuid::Uuid::parse_str(&pid).unwrap();

    let issue = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/issues"),
            &token,
            &json!({ "subject": "Has comments" }),
        ))
        .await;
    assert_eq!(issue.status, 201, "{:?}", issue.json);
    let issue_id = issue.json["id"].as_str().unwrap().to_owned();

    let mut rx = app.events.subscribe(project_uuid);

    let created = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/issues/{issue_id}/comments"),
            &token,
            &json!({ "body": "first" }),
        ))
        .await;
    assert_eq!(created.status, 201, "{:?}", created.json);
    let comment_id = created.json["id"].as_str().unwrap().to_owned();

    let events = drain(&mut rx);
    let ev = find(&events, "comment.created").expect("comment.created");
    // Subscribers filter by target so an open issue only reacts to its own
    // thread; the ids must therefore be on the payload.
    assert_eq!(ev["target_id"], Value::String(issue_id.clone()));
    assert_eq!(ev["target_type"], Value::String("issue".to_owned()));
    assert_eq!(ev["comment_id"], Value::String(comment_id.clone()));

    let edited = app
        .send(req(
            "PATCH",
            &format!("/api/v1/projects/{pid}/issues/{issue_id}/comments/{comment_id}"),
            Some(&token),
            &[],
            Some(&json!({ "body": "edited" })),
        ))
        .await;
    assert_eq!(edited.status, 200, "{:?}", edited.json);
    let events = drain(&mut rx);
    let ev = find(&events, "comment.updated").expect("comment.updated");
    assert_eq!(ev["target_id"], Value::String(issue_id.clone()));

    let removed = app
        .send(delete_bearer(
            &format!("/api/v1/projects/{pid}/issues/{issue_id}/comments/{comment_id}"),
            &token,
        ))
        .await;
    assert_eq!(removed.status, 204, "{:?}", removed.json);
    let events = drain(&mut rx);
    let ev = find(&events, "comment.deleted").expect("comment.deleted");
    assert_eq!(ev["comment_id"], Value::String(comment_id));
}

#[tokio::test]
async fn events_do_not_leak_across_projects() {
    require_db!();
    let app = TestApp::spawn().await;
    let (token, pid) = owner_with_project(&app, "liveiso1").await;
    let (_t2, other) = owner_with_project(&app, "liveiso2").await;
    let other_uuid = uuid::Uuid::parse_str(&other).unwrap();

    // Subscribe to the OTHER project, then change this one.
    let mut rx = app.events.subscribe(other_uuid);
    let created = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/epics"),
            &token,
            &json!({ "subject": "Elsewhere" }),
        ))
        .await;
    assert_eq!(created.status, 201, "{:?}", created.json);

    assert!(
        drain(&mut rx).is_empty(),
        "a project's feed must not carry another project's changes"
    );
}
