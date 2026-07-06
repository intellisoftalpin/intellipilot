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
//! Phase 22 acceptance: server-side filtering + pagination of the issues list.

mod common;

use common::{TestApp, get_with_bearer, post_json_bearer};
use serde_json::{Value, json};

const STRONG_PW: &str = "7xK!pq2$mz9Wbe#aQ";

async fn owner_with_project(app: &TestApp, tag: &str) -> (String, String, String) {
    let _ = app
        .register(&format!("{tag}@example.com"), tag, STRONG_PW)
        .await;
    let token = app
        .login(&format!("{tag}@example.com"), STRONG_PW)
        .await
        .access_token()
        .unwrap();
    let me = app.send(get_with_bearer("/api/v1/me", &token)).await;
    let uid = me.json["id"].as_str().unwrap().to_owned();
    let project = app
        .send(post_json_bearer(
            "/api/v1/projects",
            &token,
            &json!({ "name": "Paging" }),
        ))
        .await;
    assert_eq!(project.status, 201, "{:?}", project.json);
    (token, project.json["id"].as_str().unwrap().to_owned(), uid)
}

async fn tax_id(app: &TestApp, token: &str, pid: &str, kind: &str, name: &str) -> String {
    let resp = app
        .send(get_with_bearer(
            &format!("/api/v1/projects/{pid}/taxonomy/{kind}"),
            token,
        ))
        .await;
    resp.json["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["name"] == name)
        .unwrap_or_else(|| panic!("taxonomy {kind}/{name} not found"))["id"]
        .as_str()
        .unwrap()
        .to_owned()
}

async fn create(app: &TestApp, token: &str, pid: &str, body: &Value) -> Value {
    let r = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/issues"),
            token,
            body,
        ))
        .await;
    assert_eq!(r.status, 201, "{:?}", r.json);
    r.json
}

async fn list(app: &TestApp, token: &str, pid: &str, query: &str) -> common::TestResponse {
    app.send(get_with_bearer(
        &format!("/api/v1/projects/{pid}/issues{query}"),
        token,
    ))
    .await
}

#[tokio::test]
async fn pagination_envelope_and_offsets() {
    require_db!();
    let app = TestApp::spawn().await;
    let (token, pid, _uid) = owner_with_project(&app, "pgnate").await;
    for i in 0..5 {
        let _ = create(
            &app,
            &token,
            &pid,
            &json!({ "subject": format!("Issue {i}") }),
        )
        .await;
    }

    // First page of 2.
    let p0 = list(&app, &token, &pid, "?limit=2&offset=0").await;
    assert_eq!(p0.status, 200, "{:?}", p0.json);
    assert_eq!(p0.json["issues"].as_array().unwrap().len(), 2);
    assert_eq!(p0.json["total"], 5);
    assert_eq!(p0.json["limit"], 2);
    assert_eq!(p0.json["offset"], 0);

    // Last (partial) page.
    let p2 = list(&app, &token, &pid, "?limit=2&offset=4").await;
    assert_eq!(p2.json["issues"].as_array().unwrap().len(), 1);
    assert_eq!(p2.json["total"], 5);

    // Past the end → empty page, total still reported.
    let p3 = list(&app, &token, &pid, "?limit=2&offset=10").await;
    assert_eq!(p3.json["issues"].as_array().unwrap().len(), 0);
    assert_eq!(p3.json["total"], 5);

    // No limit → unbounded (board / all-issues path) still returns everything.
    let all = list(&app, &token, &pid, "").await;
    assert_eq!(all.json["issues"].as_array().unwrap().len(), 5);
    assert_eq!(all.json["total"], 5);

    // limit is clamped to 200.
    let clamped = list(&app, &token, &pid, "?limit=99999").await;
    assert_eq!(clamped.json["limit"], 200);
}

#[tokio::test]
async fn server_side_filters() {
    require_db!();
    let app = TestApp::spawn().await;
    let (token, pid, uid) = owner_with_project(&app, "filters").await;
    let bug = tax_id(&app, &token, &pid, "issue_type", "Bug").await;
    let story = tax_id(&app, &token, &pid, "issue_type", "Story").await;

    // A: bug, assigned to self, subject "Alpha login".
    let _a = create(
        &app,
        &token,
        &pid,
        &json!({ "subject": "Alpha login", "type_id": bug, "assigned_to": uid }),
    )
    .await;
    // B: story, unassigned, subject "Beta logout", overdue.
    let _b = create(
        &app,
        &token,
        &pid,
        &json!({ "subject": "Beta logout", "type_id": story, "due_date": "2020-01-01" }),
    )
    .await;
    // C: story, unassigned, subject "Gamma", future due date.
    let _c = create(
        &app,
        &token,
        &pid,
        &json!({ "subject": "Gamma", "type_id": story, "due_date": "2999-01-01" }),
    )
    .await;

    // Filter by type.
    let bugs = list(&app, &token, &pid, &format!("?type={bug}")).await;
    assert_eq!(bugs.json["total"], 1);
    assert_eq!(bugs.json["issues"][0]["subject"], "Alpha login");

    // Assignee = self vs unassigned.
    let mine = list(&app, &token, &pid, &format!("?assignee={uid}")).await;
    assert_eq!(mine.json["total"], 1);
    assert_eq!(mine.json["issues"][0]["subject"], "Alpha login");
    let unassigned = list(&app, &token, &pid, "?assignee=none").await;
    assert_eq!(unassigned.json["total"], 2);

    // Text search (subject / description / ref).
    let search = list(&app, &token, &pid, "?search=logout").await;
    assert_eq!(search.json["total"], 1);
    assert_eq!(search.json["issues"][0]["subject"], "Beta logout");

    // Overdue: only B (past due + open). C is in the future.
    let overdue = list(&app, &token, &pid, "?overdue=true").await;
    assert_eq!(overdue.json["total"], 1);
    assert_eq!(overdue.json["issues"][0]["subject"], "Beta logout");

    // Filters compose with pagination.
    let stories = list(
        &app,
        &token,
        &pid,
        &format!("?type={story}&limit=1&offset=0"),
    )
    .await;
    assert_eq!(stories.json["total"], 2);
    assert_eq!(stories.json["issues"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn server_side_filter_by_qa_assignee() {
    require_db!();
    let app = TestApp::spawn().await;
    let (token, pid, uid) = owner_with_project(&app, "qafilter").await;

    // One issue with a QA assignee, one without.
    let _with_qa = create(
        &app,
        &token,
        &pid,
        &json!({ "subject": "Needs testing", "qa_assignee_id": uid }),
    )
    .await;
    let _no_qa = create(&app, &token, &pid, &json!({ "subject": "No QA yet" })).await;

    // qa_assignee = self → only the QA-assigned issue.
    let mine = list(&app, &token, &pid, &format!("?qa_assignee={uid}")).await;
    assert_eq!(mine.json["total"], 1, "{:?}", mine.json);
    assert_eq!(mine.json["issues"][0]["subject"], "Needs testing");

    // qa_assignee = none → only the issue without a QA assignee.
    let none = list(&app, &token, &pid, "?qa_assignee=none").await;
    assert_eq!(none.json["total"], 1, "{:?}", none.json);
    assert_eq!(none.json["issues"][0]["subject"], "No QA yet");
}
