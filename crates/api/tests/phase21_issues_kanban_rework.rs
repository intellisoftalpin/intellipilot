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
//! Phase 21 acceptance: issues & kanban rework — the "new" status flag and
//! default-on-create, multi-customer issues, key-based issue resolution, and
//! per-user kanban board views.

mod common;

use common::{TestApp, delete_bearer, get_with_bearer, post_json_bearer, req};
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
            &json!({ "name": "Rework" }),
        ))
        .await;
    assert_eq!(project.status, 201, "{:?}", project.json);
    (token, project.json["id"].as_str().unwrap().to_owned())
}

async fn statuses(app: &TestApp, token: &str, pid: &str) -> Vec<Value> {
    let resp = app
        .send(get_with_bearer(
            &format!("/api/v1/projects/{pid}/taxonomy/issue_status"),
            token,
        ))
        .await;
    resp.json["items"].as_array().unwrap().clone()
}

async fn create_issue(app: &TestApp, token: &str, pid: &str, body: &Value) -> common::TestResponse {
    app.send(post_json_bearer(
        &format!("/api/v1/projects/{pid}/issues"),
        token,
        body,
    ))
    .await
}

async fn create_customer(app: &TestApp, token: &str, pid: &str, name: &str) -> String {
    let r = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/customers"),
            token,
            &json!({ "name": name }),
        ))
        .await;
    assert_eq!(r.status, 201, "{:?}", r.json);
    r.json["id"].as_str().unwrap().to_owned()
}

// ---------------------------------------------------------------------------
// "new" status flag: exactly one per project, default landing on create.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn new_status_is_unique_and_defaults_on_create() {
    require_db!();
    let app = TestApp::spawn().await;
    let (token, pid) = owner_with_project(&app, "newstatus").await;

    // Exactly one seeded status is the "new" one, and it is "New".
    let items = statuses(&app, &token, &pid).await;
    let flagged: Vec<&Value> = items
        .iter()
        .filter(|i| i["is_new"].as_bool() == Some(true))
        .collect();
    assert_eq!(flagged.len(), 1, "exactly one new status");
    assert_eq!(flagged[0]["name"], "New");
    let new_id = flagged[0]["id"].as_str().unwrap().to_owned();

    // An issue created without a status lands in the new status.
    let created = create_issue(&app, &token, &pid, &json!({ "subject": "auto" })).await;
    assert_eq!(created.status, 201, "{:?}", created.json);
    assert_eq!(created.json["status_id"], new_id);

    // Flag a different status as "new" → the flag moves (still exactly one).
    let triage = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/taxonomy/issue_status"),
            &token,
            &json!({ "name": "Triage", "slug": "triage", "is_new": true }),
        ))
        .await;
    assert_eq!(triage.status, 201, "{:?}", triage.json);
    let triage_id = triage.json["id"].as_str().unwrap().to_owned();
    assert_eq!(triage.json["is_new"], true);

    let items = statuses(&app, &token, &pid).await;
    let flagged: Vec<&Value> = items
        .iter()
        .filter(|i| i["is_new"].as_bool() == Some(true))
        .collect();
    assert_eq!(flagged.len(), 1, "still exactly one new status");
    assert_eq!(flagged[0]["id"], triage_id);

    // New issues now default into Triage.
    let created = create_issue(&app, &token, &pid, &json!({ "subject": "auto2" })).await;
    assert_eq!(created.json["status_id"], triage_id);
}

// ---------------------------------------------------------------------------
// multi-customer issues
// ---------------------------------------------------------------------------

#[tokio::test]
async fn issue_supports_multiple_customers() {
    require_db!();
    let app = TestApp::spawn().await;
    let (token, pid) = owner_with_project(&app, "multicust").await;
    let a = create_customer(&app, &token, &pid, "Acme").await;
    let b = create_customer(&app, &token, &pid, "Globex").await;

    let created = create_issue(
        &app,
        &token,
        &pid,
        &json!({ "subject": "served", "customer_ids": [a, b] }),
    )
    .await;
    assert_eq!(created.status, 201, "{:?}", created.json);
    let got: Vec<&str> = created.json["customer_ids"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert_eq!(got.len(), 2);
    assert!(got.contains(&a.as_str()) && got.contains(&b.as_str()));
    let id = created.json["id"].as_str().unwrap().to_owned();
    let etag = created.header("etag").unwrap().to_owned();

    // Replace with a single customer.
    let upd = app
        .send(req(
            "PATCH",
            &format!("/api/v1/projects/{pid}/issues/{id}"),
            Some(&token),
            &[("if-match", &etag)],
            Some(&json!({ "customer_ids": [a] })),
        ))
        .await;
    assert_eq!(upd.status, 200, "{:?}", upd.json);
    assert_eq!(upd.json["customer_ids"].as_array().unwrap().len(), 1);
    assert_eq!(upd.json["customer_ids"][0], a);

    // Clear all customers.
    let etag2 = upd.header("etag").unwrap().to_owned();
    let cleared = app
        .send(req(
            "PATCH",
            &format!("/api/v1/projects/{pid}/issues/{id}"),
            Some(&token),
            &[("if-match", &etag2)],
            Some(&json!({ "customer_ids": [] })),
        ))
        .await;
    assert_eq!(cleared.status, 200, "{:?}", cleared.json);
    assert!(cleared.json["customer_ids"].as_array().unwrap().is_empty());
}

// ---------------------------------------------------------------------------
// key-based issue resolution
// ---------------------------------------------------------------------------

#[tokio::test]
async fn resolve_issue_by_ref() {
    require_db!();
    let app = TestApp::spawn().await;
    let (token, pid) = owner_with_project(&app, "byref").await;

    let created = create_issue(&app, &token, &pid, &json!({ "subject": "deep link" })).await;
    let id = created.json["id"].as_str().unwrap().to_owned();
    let reference = created.json["ref"].as_i64().unwrap();

    let got = app
        .send(get_with_bearer(
            &format!("/api/v1/projects/{pid}/issues/by-ref/{reference}"),
            &token,
        ))
        .await;
    assert_eq!(got.status, 200, "{:?}", got.json);
    assert_eq!(got.json["id"], id);

    // Unknown ref → 404.
    let missing = app
        .send(get_with_bearer(
            &format!("/api/v1/projects/{pid}/issues/by-ref/999999"),
            &token,
        ))
        .await;
    assert_eq!(missing.status, 404);

    // An epic sharing the same ref number does NOT shadow the issue lookup
    // (epics number independently).
    let epic = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/epics"),
            &token,
            &json!({ "subject": "an epic" }),
        ))
        .await;
    assert_eq!(epic.status, 201, "{:?}", epic.json);
    let epic_ref = epic.json["ref"].as_i64().unwrap();
    let still_issue = app
        .send(get_with_bearer(
            &format!("/api/v1/projects/{pid}/issues/by-ref/{epic_ref}"),
            &token,
        ))
        .await;
    // epic_ref == 1 == the issue's ref; by-ref must return the ISSUE.
    if epic_ref == reference {
        assert_eq!(still_issue.status, 200);
        assert_eq!(still_issue.json["id"], id);
    }
}

// ---------------------------------------------------------------------------
// per-user kanban board views
// ---------------------------------------------------------------------------

#[tokio::test]
async fn board_views_crud_last_used_and_isolation() {
    require_db!();
    let app = TestApp::spawn().await;
    let (token, pid) = owner_with_project(&app, "boards").await;

    // Empty to start.
    let empty = app
        .send(get_with_bearer(
            &format!("/api/v1/projects/{pid}/board-views"),
            &token,
        ))
        .await;
    assert_eq!(empty.json["views"].as_array().unwrap().len(), 0);

    // Create a saved view.
    let cfg = json!({ "hidden": ["x"], "order": ["a", "b"], "group": "component" });
    let created = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/board-views"),
            &token,
            &json!({ "name": "My board", "config": cfg }),
        ))
        .await;
    assert_eq!(created.status, 201, "{:?}", created.json);
    let view_id = created.json["id"].as_str().unwrap().to_owned();
    assert_eq!(created.json["config"]["group"], "component");

    // Update it.
    let upd = app
        .send(req(
            "PUT",
            &format!("/api/v1/projects/{pid}/board-views/{view_id}"),
            Some(&token),
            &[],
            Some(&json!({ "name": "Renamed", "config": { "group": "assignee" } })),
        ))
        .await;
    assert_eq!(upd.status, 200, "{:?}", upd.json);
    assert_eq!(upd.json["name"], "Renamed");
    assert_eq!(upd.json["config"]["group"], "assignee");

    // last-used round trip.
    let put_last = app
        .send(req(
            "PUT",
            &format!("/api/v1/projects/{pid}/board-views/last-used"),
            Some(&token),
            &[],
            Some(&json!({ "group": "epic", "search": "foo" })),
        ))
        .await;
    assert_eq!(put_last.status, 204);
    let last = app
        .send(get_with_bearer(
            &format!("/api/v1/projects/{pid}/board-views/last-used"),
            &token,
        ))
        .await;
    assert_eq!(last.json["config"]["group"], "epic");

    // A second project member sees none of the owner's views (per-user).
    let _ = app.register("other@x", "otheruser", STRONG_PW).await;
    let other = app
        .login("other@x", STRONG_PW)
        .await
        .access_token()
        .unwrap();
    let me = app.send(get_with_bearer("/api/v1/me", &other)).await;
    let oid = me.json["id"].as_str().unwrap().to_owned();
    let add = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/members"),
            &token,
            &json!({ "user_id": oid, "role": "stakeholder" }),
        ))
        .await;
    assert_eq!(add.status, 201, "{:?}", add.json);
    let other_views = app
        .send(get_with_bearer(
            &format!("/api/v1/projects/{pid}/board-views"),
            &other,
        ))
        .await;
    assert_eq!(other_views.json["views"].as_array().unwrap().len(), 0);

    // Delete the owner's view.
    let del = app
        .send(delete_bearer(
            &format!("/api/v1/projects/{pid}/board-views/{view_id}"),
            &token,
        ))
        .await;
    assert_eq!(del.status, 204);
}
