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
//! Phase 24 acceptance: multi-level issue hierarchy with cycle rejection, the
//! `involved` and `release` issue-list filters, and work-log date editing.

mod common;

use common::{TestApp, get_with_bearer, patch_json_bearer, post_json_bearer, req};
use serde_json::{Value, json};

const STRONG_PW: &str = "7xK!pq2$mz9Wbe#aQ";

/// Register + login, returning (token, user_id).
async fn user(app: &TestApp, email: &str, username: &str) -> (String, String) {
    let _ = app.register(email, username, STRONG_PW).await;
    let token = app.login(email, STRONG_PW).await.access_token().unwrap();
    let me = app.send(get_with_bearer("/api/v1/me", &token)).await;
    let id = me.json["id"].as_str().unwrap().to_owned();
    (token, id)
}

/// Owner with a fresh project. Returns (token, owner_id, project_id).
async fn owner_project(app: &TestApp) -> (String, String, String) {
    let (token, uid) = user(app, "owner@x", "owneruser").await;
    let p = app
        .send(post_json_bearer(
            "/api/v1/projects",
            &token,
            &json!({ "name": "P24" }),
        ))
        .await;
    assert_eq!(p.status, 201, "{:?}", p.json);
    (token, uid, p.json["id"].as_str().unwrap().to_owned())
}

async fn add_member(app: &TestApp, owner: &str, pid: &str, user_id: &str, role: &str) {
    let r = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/members"),
            owner,
            &json!({ "user_id": user_id, "role": role }),
        ))
        .await;
    assert_eq!(r.status, 201, "add member: {:?}", r.json);
}

/// Create an issue from an arbitrary JSON body, returning (id, etag).
async fn issue(app: &TestApp, token: &str, pid: &str, body: &Value) -> (String, String) {
    let r = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/issues"),
            token,
            body,
        ))
        .await;
    assert_eq!(r.status, 201, "create issue: {:?}", r.json);
    (
        r.json["id"].as_str().unwrap().to_owned(),
        r.header("etag").unwrap().to_owned(),
    )
}

/// PATCH an issue with If-Match, returning the response.
async fn patch_issue(
    app: &TestApp,
    token: &str,
    pid: &str,
    id: &str,
    etag: &str,
    body: &Value,
) -> common::TestResponse {
    app.send(req(
        "PATCH",
        &format!("/api/v1/projects/{pid}/issues/{id}"),
        Some(token),
        &[("if-match", etag)],
        Some(body),
    ))
    .await
}

/// Ids of the issues returned by a filtered list call.
async fn list_ids(app: &TestApp, token: &str, pid: &str, query: &str) -> Vec<String> {
    let r = app
        .send(get_with_bearer(
            &format!("/api/v1/projects/{pid}/issues?{query}"),
            token,
        ))
        .await;
    assert_eq!(r.status, 200, "{:?}", r.json);
    r.json["issues"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["id"].as_str().unwrap().to_owned())
        .collect()
}

// ---------------------------------------------------------------------------
// multi-level hierarchy + cycle rejection
// ---------------------------------------------------------------------------

#[tokio::test]
async fn multi_level_parent_allowed_but_cycles_rejected() {
    require_db!();
    let app = TestApp::spawn().await;
    let (token, _uid, pid) = owner_project(&app).await;

    let (a, _ea) = issue(&app, &token, &pid, &json!({ "subject": "A" })).await;
    let (b, eb) = issue(&app, &token, &pid, &json!({ "subject": "B" })).await;
    let (c, ec) = issue(&app, &token, &pid, &json!({ "subject": "C" })).await;

    // B under A, then C under B: a two-level chain is allowed.
    let r = patch_issue(&app, &token, &pid, &b, &eb, &json!({ "parent_id": a })).await;
    assert_eq!(r.status, 200, "B->A: {:?}", r.json);
    let r = patch_issue(&app, &token, &pid, &c, &ec, &json!({ "parent_id": b })).await;
    assert_eq!(r.status, 200, "C->B (multi-level): {:?}", r.json);

    // A under C closes a cycle A->B->C->A and must be rejected.
    let ea = app
        .send(get_with_bearer(
            &format!("/api/v1/projects/{pid}/issues/{a}"),
            &token,
        ))
        .await
        .header("etag")
        .unwrap()
        .to_owned();
    let r = patch_issue(&app, &token, &pid, &a, &ea, &json!({ "parent_id": c })).await;
    assert_eq!(r.status, 422, "cycle rejected: {:?}", r.json);
    assert_eq!(r.json["code"], "invalid_association");

    // Direct self-parenting stays rejected too.
    let r = patch_issue(&app, &token, &pid, &a, &ea, &json!({ "parent_id": a })).await;
    assert_eq!(r.status, 422, "self-parent rejected: {:?}", r.json);
}

// ---------------------------------------------------------------------------
// involved filter: assignee OR qa OR reviewer, never reporter
// ---------------------------------------------------------------------------

#[tokio::test]
async fn involved_filter_matches_assignee_qa_or_reviewer() {
    require_db!();
    let app = TestApp::spawn().await;
    let (owner, oid, pid) = owner_project(&app).await;
    let (_dev, did) = user(&app, "dev@x", "devuser").await;
    add_member(&app, &owner, &pid, &did, "dev").await;

    let (i1, _) = issue(
        &app,
        &owner,
        &pid,
        &json!({ "subject": "assigned", "assigned_to": did }),
    )
    .await;
    let (i2, _) = issue(
        &app,
        &owner,
        &pid,
        &json!({ "subject": "qa", "qa_assignee_id": did }),
    )
    .await;
    let (i3, _) = issue(
        &app,
        &owner,
        &pid,
        &json!({ "subject": "review", "reviewer_id": did }),
    )
    .await;
    let (i4, _) = issue(
        &app,
        &owner,
        &pid,
        &json!({ "subject": "owner's", "assigned_to": oid }),
    )
    .await;
    let (i5, _) = issue(&app, &owner, &pid, &json!({ "subject": "nobody" })).await;

    // The dev shows up via any of the three roles.
    let ids = list_ids(&app, &owner, &pid, &format!("involved={did}")).await;
    assert_eq!(ids.len(), 3, "dev involved in exactly 3 issues");
    for id in [&i1, &i2, &i3] {
        assert!(ids.contains(id), "missing {id}");
    }

    // The reporter role alone does not count as involved: the owner reported
    // all five but is only involved in the one assigned to them.
    let ids = list_ids(&app, &owner, &pid, &format!("involved={oid}")).await;
    assert_eq!(ids, vec![i4.clone()], "reporter-only issues excluded");

    // `none` matches issues with no assignee, QA, or reviewer at all.
    let ids = list_ids(&app, &owner, &pid, "involved=none").await;
    assert_eq!(ids, vec![i5.clone()], "only the untouched issue");
}

// ---------------------------------------------------------------------------
// release filter
// ---------------------------------------------------------------------------

#[tokio::test]
async fn release_filter_narrows_issue_list() {
    require_db!();
    let app = TestApp::spawn().await;
    let (token, _uid, pid) = owner_project(&app).await;

    // Two releases with one version each.
    let mut versions = Vec::new();
    let mut releases = Vec::new();
    for name in ["Spring", "Autumn"] {
        let r = app
            .send(post_json_bearer(
                &format!("/api/v1/projects/{pid}/releases"),
                &token,
                &json!({ "name": name }),
            ))
            .await;
        assert_eq!(r.status, 201, "{:?}", r.json);
        let rid = r.json["id"].as_str().unwrap().to_owned();
        let v = app
            .send(post_json_bearer(
                &format!("/api/v1/projects/{pid}/releases/{rid}/versions"),
                &token,
                &json!({ "version": "1.0" }),
            ))
            .await;
        assert_eq!(v.status, 201, "{:?}", v.json);
        versions.push(v.json["id"].as_str().unwrap().to_owned());
        releases.push(rid);
    }

    let (i1, _) = issue(
        &app,
        &token,
        &pid,
        &json!({ "subject": "in spring", "release_version_id": versions[0] }),
    )
    .await;
    let (i2, _) = issue(
        &app,
        &token,
        &pid,
        &json!({ "subject": "in autumn", "release_version_id": versions[1] }),
    )
    .await;
    let (i3, _) = issue(&app, &token, &pid, &json!({ "subject": "unplanned" })).await;

    let ids = list_ids(&app, &token, &pid, &format!("release={}", releases[0])).await;
    assert_eq!(ids, vec![i1.clone()], "spring release only");

    let ids = list_ids(&app, &token, &pid, &format!("release={}", releases[1])).await;
    assert_eq!(ids, vec![i2.clone()], "autumn release only");

    let ids = list_ids(&app, &token, &pid, "release=none").await;
    assert_eq!(ids, vec![i3.clone()], "issues without a fix version");

    // Combines with the component filter (empty intersection here).
    let comp = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/components"),
            &token,
            &json!({ "name": "backend" }),
        ))
        .await;
    assert_eq!(comp.status, 201, "{:?}", comp.json);
    let cid = comp.json["id"].as_str().unwrap().to_owned();
    let ids = list_ids(
        &app,
        &token,
        &pid,
        &format!("component={cid}&release={}", releases[0]),
    )
    .await;
    assert!(ids.is_empty(), "no spring issues in the backend component");
}

// ---------------------------------------------------------------------------
// work-log date editing
// ---------------------------------------------------------------------------

#[tokio::test]
async fn work_log_date_is_editable() {
    require_db!();
    let app = TestApp::spawn().await;
    let (token, uid, pid) = owner_project(&app).await;
    let (issue_id, _) = issue(
        &app,
        &token,
        &pid,
        &json!({ "subject": "T", "assigned_to": uid }),
    )
    .await;

    let logged = app
        .send(post_json_bearer(
            "/api/v1/me/time-entries",
            &token,
            &json!({ "issue_id": issue_id, "date": "2020-03-04", "minutes": 60 }),
        ))
        .await;
    assert_eq!(logged.status, 201, "{:?}", logged.json);
    let entry_id = logged.json["id"].as_str().unwrap().to_owned();

    // Move the entry to another day, keeping minutes.
    let upd = app
        .send(patch_json_bearer(
            &format!("/api/v1/me/time-entries/{entry_id}"),
            &token,
            &json!({ "minutes": 60, "date": "2020-03-10", "version": 1 }),
        ))
        .await;
    assert_eq!(upd.status, 200, "{:?}", upd.json);
    assert_eq!(upd.json["entry_date"], "2020-03-10");
    assert_eq!(upd.json["version"], 2);

    // Omitting the date leaves it unchanged.
    let upd = app
        .send(patch_json_bearer(
            &format!("/api/v1/me/time-entries/{entry_id}"),
            &token,
            &json!({ "minutes": 90, "version": 2 }),
        ))
        .await;
    assert_eq!(upd.status, 200, "{:?}", upd.json);
    assert_eq!(upd.json["entry_date"], "2020-03-10");

    // Garbage dates are rejected.
    let bad = app
        .send(patch_json_bearer(
            &format!("/api/v1/me/time-entries/{entry_id}"),
            &token,
            &json!({ "minutes": 90, "date": "2020-13-99", "version": 3 }),
        ))
        .await;
    assert_eq!(bad.status, 422, "{:?}", bad.json);
}

#[tokio::test]
async fn work_log_date_move_respects_period_locks() {
    require_db!();
    let app = TestApp::spawn().await;
    let (owner, _oid, pid) = owner_project(&app).await;
    let (dev, did) = user(&app, "dev@x", "devuser").await;
    add_member(&app, &owner, &pid, &did, "dev").await;
    let (issue_id, _) = issue(
        &app,
        &owner,
        &pid,
        &json!({ "subject": "T", "assigned_to": did }),
    )
    .await;

    let logged = app
        .send(post_json_bearer(
            "/api/v1/me/time-entries",
            &dev,
            &json!({ "issue_id": issue_id, "date": "2020-05-05", "minutes": 60 }),
        ))
        .await;
    assert_eq!(logged.status, 201, "{:?}", logged.json);
    let entry_id = logged.json["id"].as_str().unwrap().to_owned();

    // Owner locks June 2020.
    let lock = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/time/locks"),
            &owner,
            &json!({ "year": 2020, "month": 6 }),
        ))
        .await;
    assert_eq!(lock.status, 201, "{:?}", lock.json);

    // The dev cannot move their May entry into the locked June.
    let blocked = app
        .send(patch_json_bearer(
            &format!("/api/v1/me/time-entries/{entry_id}"),
            &dev,
            &json!({ "minutes": 60, "date": "2020-06-02", "version": 1 }),
        ))
        .await;
    assert_eq!(blocked.status, 409, "{:?}", blocked.json);
    assert_eq!(blocked.json["code"], "period_locked");

    // A manager may move it via the admin endpoint (locks don't bind them).
    let moved = app
        .send(patch_json_bearer(
            &format!("/api/v1/projects/{pid}/time-entries/{entry_id}"),
            &owner,
            &json!({ "minutes": 60, "date": "2020-06-02", "version": 1 }),
        ))
        .await;
    assert_eq!(moved.status, 200, "{:?}", moved.json);
    assert_eq!(moved.json["entry_date"], "2020-06-02");
}
