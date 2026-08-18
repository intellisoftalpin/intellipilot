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
//! Phase 6 acceptance: milestones (CRUD, complete/reopen, epics, board, stats).
//!
//! Since V019 a milestone is composed of epics and *only* of epics: an issue's
//! milestone is derived from its epic by database trigger and cannot be set
//! from the API. Most fixtures here therefore go issue → epic → milestone.

mod common;

use common::{TestApp, get_with_bearer, post_bearer, post_json_bearer, req};
use serde_json::{Value, json};

const STRONG_PW: &str = "7xK!pq2$mz9Wbe#aQ";

async fn fresh_user(app: &TestApp, email: &str, username: &str) -> String {
    let _ = app.register(email, username, STRONG_PW).await;
    app.login(email, STRONG_PW)
        .await
        .access_token()
        .expect("access token")
}

async fn owner_project(app: &TestApp) -> (String, String) {
    let token = fresh_user(app, "ms@example.com", "msuser").await;
    let p = app
        .send(post_json_bearer(
            "/api/v1/projects",
            &token,
            &json!({ "name": "MS" }),
        ))
        .await;
    assert_eq!(p.status, 201, "{:?}", p.json);
    (token, p.json["id"].as_str().unwrap().to_owned())
}

/// Create a custom role with exactly `permissions`, invite a fresh user into
/// it, and return that user's access token.
async fn member_with_role(
    app: &TestApp,
    owner: &str,
    pid: &str,
    role_slug: &str,
    permissions: &[&str],
    email: &str,
    username: &str,
) -> String {
    let role = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/roles"),
            owner,
            &json!({ "name": role_slug, "slug": role_slug, "permissions": permissions }),
        ))
        .await;
    assert_eq!(role.status, 201, "create role: {:?}", role.json);
    let invite = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/invitations"),
            owner,
            &json!({ "email": email, "role": role_slug }),
        ))
        .await;
    let itoken = invite.json["invite_token"].as_str().unwrap().to_owned();
    let member = fresh_user(app, email, username).await;
    let accept = app
        .send(post_json_bearer(
            "/api/v1/invitations/accept",
            &member,
            &json!({ "token": itoken }),
        ))
        .await;
    assert_eq!(accept.status, 200, "accept invite: {:?}", accept.json);
    member
}

/// Find a taxonomy item id by display name within a kind.
async fn tax_id(app: &TestApp, token: &str, pid: &str, kind: &str, name: &str) -> String {
    let list = app
        .send(get_with_bearer(
            &format!("/api/v1/projects/{pid}/taxonomy/{kind}"),
            token,
        ))
        .await;
    list.json["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["name"] == name)
        .unwrap_or_else(|| panic!("taxonomy {kind} '{name}' not found"))["id"]
        .as_str()
        .unwrap()
        .to_owned()
}

async fn milestone(app: &TestApp, token: &str, pid: &str, body: &Value) -> Value {
    let m = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/milestones"),
            token,
            body,
        ))
        .await;
    assert_eq!(m.status, 201, "create milestone: {:?}", m.json);
    m.json
}

async fn epic(app: &TestApp, token: &str, pid: &str, subject: &str, mid: Option<&str>) -> String {
    let body = mid.map_or_else(
        || json!({ "subject": subject }),
        |m| json!({ "subject": subject, "milestone_id": m }),
    );
    let e = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/epics"),
            token,
            &body,
        ))
        .await;
    assert_eq!(e.status, 201, "create epic: {:?}", e.json);
    e.json["id"].as_str().unwrap().to_owned()
}

async fn issue(app: &TestApp, token: &str, pid: &str, body: &Value) -> Value {
    let i = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/issues"),
            token,
            body,
        ))
        .await;
    assert_eq!(i.status, 201, "create issue: {:?}", i.json);
    i.json
}

/// PATCH a milestone with the `If-Match` its current ETag demands.
async fn patch_milestone(
    app: &TestApp,
    token: &str,
    pid: &str,
    mid: &str,
    body: &Value,
) -> common::TestResponse {
    let current = app
        .send(get_with_bearer(
            &format!("/api/v1/projects/{pid}/milestones/{mid}"),
            token,
        ))
        .await;
    let tag = current.header("etag").unwrap().to_owned();
    app.send(req(
        "PATCH",
        &format!("/api/v1/projects/{pid}/milestones/{mid}"),
        Some(token),
        &[("if-match", tag.as_str())],
        Some(body),
    ))
    .await
}

// ---------------------------------------------------------------------------
// CRUD
// ---------------------------------------------------------------------------

#[tokio::test]
async fn milestone_crud() {
    require_db!();
    let app = TestApp::spawn().await;
    let (token, pid) = owner_project(&app).await;

    let created = milestone(
        &app,
        &token,
        &pid,
        &json!({
            "name": "Sprint 1",
            "description": "First push",
            "start_date": "2026-05-01",
            "end_date": "2026-05-14",
            "business_release_date": "2026-05-20",
        }),
    )
    .await;
    assert_eq!(created["slug"], "sprint-1");
    assert_eq!(created["start_date"], "2026-05-01");
    assert_eq!(created["description"], "First push");
    assert_eq!(created["business_release_date"], "2026-05-20");
    assert_eq!(created["closed"], false);
    let id = created["id"].as_str().unwrap().to_owned();

    let list = app
        .send(get_with_bearer(
            &format!("/api/v1/projects/{pid}/milestones"),
            &token,
        ))
        .await;
    assert_eq!(list.json["milestones"].as_array().unwrap().len(), 1);

    let patched = patch_milestone(
        &app,
        &token,
        &pid,
        &id,
        &json!({ "name": "Sprint One", "description": "Renamed" }),
    )
    .await;
    assert_eq!(patched.status, 200, "{:?}", patched.json);
    assert_eq!(patched.json["name"], "Sprint One");
    assert_eq!(patched.json["description"], "Renamed");

    let del = app
        .send(req(
            "DELETE",
            &format!("/api/v1/projects/{pid}/milestones/{id}"),
            Some(&token),
            &[],
            None,
        ))
        .await;
    assert_eq!(del.status, 204);
    let gone = app
        .send(get_with_bearer(
            &format!("/api/v1/projects/{pid}/milestones/{id}"),
            &token,
        ))
        .await;
    assert_eq!(gone.status, 404);
}

#[tokio::test]
async fn invalid_dates_rejected() {
    require_db!();
    let app = TestApp::spawn().await;
    let (token, pid) = owner_project(&app).await;
    let resp = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/milestones"),
            &token,
            &json!({ "name": "Bad", "start_date": "2026-05-14", "end_date": "2026-05-01" }),
        ))
        .await;
    assert_eq!(resp.status, 422);
    assert_eq!(resp.json["code"], "invalid_dates");
}

#[tokio::test]
async fn patch_requires_if_match_and_detects_conflict() {
    require_db!();
    let app = TestApp::spawn().await;
    let (token, pid) = owner_project(&app).await;
    let m = milestone(&app, &token, &pid, &json!({ "name": "Guarded" })).await;
    let mid = m["id"].as_str().unwrap().to_owned();

    // No If-Match at all.
    let bare = app
        .send(req(
            "PATCH",
            &format!("/api/v1/projects/{pid}/milestones/{mid}"),
            Some(&token),
            &[],
            Some(&json!({ "name": "Nope" })),
        ))
        .await;
    assert_eq!(bare.status, 428, "{:?}", bare.json);

    // A stale ETag: capture one, let someone else save, then try to use it.
    let stale = app
        .send(get_with_bearer(
            &format!("/api/v1/projects/{pid}/milestones/{mid}"),
            &token,
        ))
        .await
        .header("etag")
        .unwrap()
        .to_owned();
    let first = patch_milestone(&app, &token, &pid, &mid, &json!({ "name": "First" })).await;
    assert_eq!(first.status, 200);

    let conflict = app
        .send(req(
            "PATCH",
            &format!("/api/v1/projects/{pid}/milestones/{mid}"),
            Some(&token),
            &[("if-match", stale.as_str())],
            Some(&json!({ "name": "Second" })),
        ))
        .await;
    assert_eq!(conflict.status, 412, "{:?}", conflict.json);
}

#[tokio::test]
async fn dates_can_be_cleared() {
    require_db!();
    let app = TestApp::spawn().await;
    let (token, pid) = owner_project(&app).await;
    let m = milestone(
        &app,
        &token,
        &pid,
        &json!({ "name": "Clearable", "start_date": "2026-05-01", "end_date": "2026-05-14" }),
    )
    .await;
    let mid = m["id"].as_str().unwrap().to_owned();

    // Absent field leaves the date alone...
    let untouched = patch_milestone(&app, &token, &pid, &mid, &json!({ "name": "Same" })).await;
    assert_eq!(untouched.json["start_date"], "2026-05-01");

    // ...explicit null clears it.
    let cleared = patch_milestone(&app, &token, &pid, &mid, &json!({ "start_date": null })).await;
    assert_eq!(cleared.status, 200, "{:?}", cleared.json);
    assert!(cleared.json["start_date"].is_null());
    assert_eq!(cleared.json["end_date"], "2026-05-14");
}

// ---------------------------------------------------------------------------
// business release date
// ---------------------------------------------------------------------------

#[tokio::test]
async fn business_release_needs_an_end_date_after_it() {
    require_db!();
    let app = TestApp::spawn().await;
    let (token, pid) = owner_project(&app).await;

    // No end date at all.
    let orphan = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/milestones"),
            &token,
            &json!({ "name": "Orphan", "business_release_date": "2026-06-01" }),
        ))
        .await;
    assert_eq!(orphan.status, 422, "{:?}", orphan.json);
    assert_eq!(orphan.json["code"], "invalid_dates");

    // Same day as the end date is not "after" it.
    let same_day = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/milestones"),
            &token,
            &json!({
                "name": "SameDay",
                "end_date": "2026-05-14",
                "business_release_date": "2026-05-14",
            }),
        ))
        .await;
    assert_eq!(same_day.status, 422, "{:?}", same_day.json);
}

#[tokio::test]
async fn clearing_end_date_clears_business_release() {
    require_db!();
    let app = TestApp::spawn().await;
    let (token, pid) = owner_project(&app).await;
    let m = milestone(
        &app,
        &token,
        &pid,
        &json!({
            "name": "Tail",
            "end_date": "2026-05-14",
            "business_release_date": "2026-05-20",
        }),
    )
    .await;
    let mid = m["id"].as_str().unwrap().to_owned();

    let cleared = patch_milestone(&app, &token, &pid, &mid, &json!({ "end_date": null })).await;
    assert_eq!(cleared.status, 200, "{:?}", cleared.json);
    assert!(cleared.json["end_date"].is_null());
    assert!(
        cleared.json["business_release_date"].is_null(),
        "business release must not outlive the technical one: {:?}",
        cleared.json
    );
}

#[tokio::test]
async fn business_release_is_hidden_without_permission() {
    require_db!();
    let app = TestApp::spawn().await;
    let (owner, pid) = owner_project(&app).await;
    let m = milestone(
        &app,
        &owner,
        &pid,
        &json!({
            "name": "Commercial",
            "end_date": "2026-05-14",
            "business_release_date": "2026-05-20",
        }),
    )
    .await;
    let mid = m["id"].as_str().unwrap().to_owned();

    // A plain viewer: milestone.view but no business-release permission.
    let viewer = member_with_role(
        &app,
        &owner,
        &pid,
        "viewer",
        &["project.view", "milestone.view", "milestone.modify"],
        "viewer@example.com",
        "viewerms",
    )
    .await;

    for uri in [
        format!("/api/v1/projects/{pid}/milestones/{mid}"),
        format!("/api/v1/projects/{pid}/milestones"),
    ] {
        let resp = app.send(get_with_bearer(&uri, &viewer)).await;
        assert_eq!(resp.status, 200, "{:?}", resp.json);
        let body = resp.json.to_string();
        assert!(
            !body.contains("business_release_date"),
            "business release leaked to a plain viewer via {uri}: {body}"
        );
        assert!(
            !body.contains("2026-05-20"),
            "business release value leaked via {uri}: {body}"
        );
    }

    // The owner (admin) still sees it.
    let owner_view = app
        .send(get_with_bearer(
            &format!("/api/v1/projects/{pid}/milestones/{mid}"),
            &owner,
        ))
        .await;
    assert_eq!(owner_view.json["business_release_date"], "2026-05-20");

    // And cannot be set by someone without the modify permission.
    let denied = patch_milestone(
        &app,
        &viewer,
        &pid,
        &mid,
        &json!({ "business_release_date": "2026-06-01" }),
    )
    .await;
    assert_eq!(denied.status, 403, "{:?}", denied.json);
}

// ---------------------------------------------------------------------------
// epic-derived membership
// ---------------------------------------------------------------------------

#[tokio::test]
async fn issue_milestone_cannot_be_set_directly() {
    require_db!();
    let app = TestApp::spawn().await;
    let (token, pid) = owner_project(&app).await;
    let m = milestone(&app, &token, &pid, &json!({ "name": "Sprint" })).await;
    let mid = m["id"].as_str().unwrap().to_owned();

    let created = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/issues"),
            &token,
            &json!({ "subject": "Direct", "milestone_id": mid }),
        ))
        .await;
    assert_eq!(created.status, 422, "{:?}", created.json);
    assert_eq!(created.json["code"], "milestone_via_epic_only");

    // ... and the same on PATCH.
    let i = issue(&app, &token, &pid, &json!({ "subject": "Plain" })).await;
    let iid = i["id"].as_str().unwrap().to_owned();
    let tag = app
        .send(get_with_bearer(
            &format!("/api/v1/projects/{pid}/issues/{iid}"),
            &token,
        ))
        .await
        .header("etag")
        .unwrap()
        .to_owned();
    let patched = app
        .send(req(
            "PATCH",
            &format!("/api/v1/projects/{pid}/issues/{iid}"),
            Some(&token),
            &[("if-match", tag.as_str())],
            Some(&json!({ "milestone_id": mid })),
        ))
        .await;
    assert_eq!(patched.status, 422, "{:?}", patched.json);
    assert_eq!(patched.json["code"], "milestone_via_epic_only");
}

#[tokio::test]
async fn issue_milestone_follows_its_epic() {
    require_db!();
    let app = TestApp::spawn().await;
    let (token, pid) = owner_project(&app).await;
    let a = milestone(&app, &token, &pid, &json!({ "name": "A" })).await;
    let b = milestone(&app, &token, &pid, &json!({ "name": "B" })).await;
    let (aid, bid) = (
        a["id"].as_str().unwrap().to_owned(),
        b["id"].as_str().unwrap().to_owned(),
    );
    let eid = epic(&app, &token, &pid, "E", Some(&aid)).await;

    // An issue created under the epic inherits the epic's milestone.
    let i = issue(
        &app,
        &token,
        &pid,
        &json!({ "subject": "Inheriting", "epic_id": eid }),
    )
    .await;
    assert_eq!(i["milestone_id"], aid);
    let iid = i["id"].as_str().unwrap().to_owned();

    // Moving the epic carries its issues along.
    let e_now = app
        .send(get_with_bearer(
            &format!("/api/v1/projects/{pid}/epics/{eid}"),
            &token,
        ))
        .await;
    let etag = e_now.header("etag").unwrap().to_owned();
    let moved = app
        .send(req(
            "PATCH",
            &format!("/api/v1/projects/{pid}/epics/{eid}"),
            Some(&token),
            &[("if-match", etag.as_str())],
            Some(&json!({ "milestone_id": bid })),
        ))
        .await;
    assert_eq!(moved.status, 200, "{:?}", moved.json);

    let after = app
        .send(get_with_bearer(
            &format!("/api/v1/projects/{pid}/issues/{iid}"),
            &token,
        ))
        .await;
    assert_eq!(after.json["milestone_id"], bid, "{:?}", after.json);

    // Detaching the epic from every milestone clears the issue too.
    let put = app
        .send(req(
            "PUT",
            &format!("/api/v1/projects/{pid}/milestones/{bid}/epics"),
            Some(&token),
            &[],
            Some(&json!({ "epic_ids": [] })),
        ))
        .await;
    assert_eq!(put.status, 204, "{:?}", put.json);
    let detached = app
        .send(get_with_bearer(
            &format!("/api/v1/projects/{pid}/issues/{iid}"),
            &token,
        ))
        .await;
    assert!(
        detached.json["milestone_id"].is_null(),
        "{:?}",
        detached.json
    );
}

#[tokio::test]
async fn cross_project_milestone_is_422() {
    require_db!();
    let app = TestApp::spawn().await;
    let (token, pid_a) = owner_project(&app).await;
    let pb = app
        .send(post_json_bearer(
            "/api/v1/projects",
            &token,
            &json!({ "name": "Other" }),
        ))
        .await;
    let pid_b = pb.json["id"].as_str().unwrap().to_owned();
    let mb = milestone(&app, &token, &pid_b, &json!({ "name": "S" })).await;
    let mb_id = mb["id"].as_str().unwrap();

    let e = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid_a}/epics"),
            &token,
            &json!({ "subject": "X", "milestone_id": mb_id }),
        ))
        .await;
    assert_eq!(e.status, 422, "{:?}", e.json);
}

// ---------------------------------------------------------------------------
// completion
// ---------------------------------------------------------------------------

#[tokio::test]
async fn completing_a_milestone_blocks_new_epics_and_reopening_unblocks() {
    require_db!();
    let app = TestApp::spawn().await;
    let (token, pid) = owner_project(&app).await;
    let m = milestone(&app, &token, &pid, &json!({ "name": "Sprint" })).await;
    let mid = m["id"].as_str().unwrap().to_owned();

    // An epic can join while the milestone is in progress.
    let _first = epic(&app, &token, &pid, "InTime", Some(&mid)).await;

    let closed = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/milestones/{mid}/close"),
            &token,
            &json!({}),
        ))
        .await;
    assert_eq!(closed.status, 200, "{:?}", closed.json);
    assert_eq!(closed.json["closed"], true);
    assert!(closed.json["closed_at"].is_string(), "closed_at stamped");

    // A new epic may not.
    let blocked = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/epics"),
            &token,
            &json!({ "subject": "TooLate", "milestone_id": mid }),
        ))
        .await;
    assert_eq!(blocked.status, 409, "{:?}", blocked.json);
    assert_eq!(blocked.json["code"], "milestone_closed");

    // Nor via the bulk epics endpoint.
    let late = epic(&app, &token, &pid, "Late", None).await;
    let bulk = app
        .send(req(
            "PUT",
            &format!("/api/v1/projects/{pid}/milestones/{mid}/epics"),
            Some(&token),
            &[],
            Some(&json!({ "epic_ids": [late] })),
        ))
        .await;
    assert_eq!(bulk.status, 409, "{:?}", bulk.json);

    // Reopening restores normal service and clears the completion stamp.
    let reopened = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/milestones/{mid}/reopen"),
            &token,
            &json!({}),
        ))
        .await;
    assert_eq!(reopened.status, 200, "{:?}", reopened.json);
    assert_eq!(reopened.json["closed"], false);
    assert!(reopened.json["closed_at"].is_null());

    let allowed = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/epics"),
            &token,
            &json!({ "subject": "NowFine", "milestone_id": mid }),
        ))
        .await;
    assert_eq!(allowed.status, 201, "{:?}", allowed.json);
}

// ---------------------------------------------------------------------------
// delete guard
// ---------------------------------------------------------------------------

#[tokio::test]
async fn milestone_with_epics_cannot_be_deleted() {
    require_db!();
    let app = TestApp::spawn().await;
    let (token, pid) = owner_project(&app).await;
    let m = milestone(&app, &token, &pid, &json!({ "name": "Full" })).await;
    let mid = m["id"].as_str().unwrap().to_owned();
    let eid = epic(&app, &token, &pid, "Occupant", Some(&mid)).await;

    let refused = app
        .send(req(
            "DELETE",
            &format!("/api/v1/projects/{pid}/milestones/{mid}"),
            Some(&token),
            &[],
            None,
        ))
        .await;
    assert_eq!(refused.status, 409, "{:?}", refused.json);
    assert_eq!(refused.json["code"], "milestone_has_epics");

    // Emptying it makes the milestone deletable.
    let put = app
        .send(req(
            "PUT",
            &format!("/api/v1/projects/{pid}/milestones/{mid}/epics"),
            Some(&token),
            &[],
            Some(&json!({ "epic_ids": [] })),
        ))
        .await;
    assert_eq!(put.status, 204);
    let _ = eid;

    let deleted = app
        .send(req(
            "DELETE",
            &format!("/api/v1/projects/{pid}/milestones/{mid}"),
            Some(&token),
            &[],
            None,
        ))
        .await;
    assert_eq!(deleted.status, 204, "{:?}", deleted.json);
}

// ---------------------------------------------------------------------------
// epics listing, stats, board
// ---------------------------------------------------------------------------

#[tokio::test]
async fn milestone_epics_carry_readiness_counts() {
    require_db!();
    let app = TestApp::spawn().await;
    let (token, pid) = owner_project(&app).await;
    let m = milestone(&app, &token, &pid, &json!({ "name": "Sprint" })).await;
    let mid = m["id"].as_str().unwrap().to_owned();
    let eid = epic(&app, &token, &pid, "Ring", Some(&mid)).await;
    let st_done = tax_id(&app, &token, &pid, "issue_status", "Done").await;
    let st_new = tax_id(&app, &token, &pid, "issue_status", "New").await;

    let _ = issue(
        &app,
        &token,
        &pid,
        &json!({ "subject": "done", "epic_id": eid, "status_id": st_done }),
    )
    .await;
    let _ = issue(
        &app,
        &token,
        &pid,
        &json!({ "subject": "open", "epic_id": eid, "status_id": st_new }),
    )
    .await;

    let epics = app
        .send(get_with_bearer(
            &format!("/api/v1/projects/{pid}/milestones/{mid}/epics"),
            &token,
        ))
        .await;
    assert_eq!(epics.status, 200, "{:?}", epics.json);
    let items = epics.json["epics"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["id"], eid);
    assert_eq!(items[0]["task_total"], 2);
    assert_eq!(items[0]["task_closed"], 1);
}

#[tokio::test]
async fn milestone_stats_from_fixture() {
    require_db!();
    let app = TestApp::spawn().await;
    let (token, pid) = owner_project(&app).await;
    let m = milestone(&app, &token, &pid, &json!({ "name": "Sprint" })).await;
    let mid = m["id"].as_str().unwrap().to_owned();
    let eid = epic(&app, &token, &pid, "Scope", Some(&mid)).await;

    // Sizes carry an ordinal `value`: XL=5, M=3.
    let p5 = tax_id(&app, &token, &pid, "size", "XL").await;
    let p3 = tax_id(&app, &token, &pid, "size", "M").await;
    let st_done = tax_id(&app, &token, &pid, "issue_status", "Done").await; // closed
    let st_new = tax_id(&app, &token, &pid, "issue_status", "New").await; // open

    let _ = issue(
        &app,
        &token,
        &pid,
        &json!({ "subject": "I1", "epic_id": eid, "size_id": p5, "status_id": st_done }),
    )
    .await;
    let _ = issue(
        &app,
        &token,
        &pid,
        &json!({ "subject": "I2", "epic_id": eid, "size_id": p3, "status_id": st_new }),
    )
    .await;

    let stats = app
        .send(get_with_bearer(
            &format!("/api/v1/projects/{pid}/milestones/{mid}/stats"),
            &token,
        ))
        .await;
    assert_eq!(stats.status, 200, "{:?}", stats.json);
    assert_eq!(stats.json["total_points"], 8.0);
    assert_eq!(stats.json["completed_points"], 5.0);
    assert_eq!(stats.json["total_tasks"], 2);
    assert_eq!(stats.json["completed_tasks"], 1);
}

#[tokio::test]
async fn milestone_board_shape() {
    require_db!();
    let app = TestApp::spawn().await;
    let (token, pid) = owner_project(&app).await;
    let m = milestone(&app, &token, &pid, &json!({ "name": "Sprint" })).await;
    let mid = m["id"].as_str().unwrap().to_owned();
    let eid = epic(&app, &token, &pid, "Board", Some(&mid)).await;
    let st_new = tax_id(&app, &token, &pid, "issue_status", "New").await;

    // A top-level issue in the sprint (via its epic), plus one sub-task.
    let parent = issue(
        &app,
        &token,
        &pid,
        &json!({ "subject": "Card", "epic_id": eid, "status_id": st_new }),
    )
    .await;
    let parent_id = parent["id"].as_str().unwrap().to_owned();
    let _ = issue(
        &app,
        &token,
        &pid,
        &json!({ "subject": "Sub", "parent_id": parent_id }),
    )
    .await;

    let board = app
        .send(get_with_bearer(
            &format!("/api/v1/projects/{pid}/milestones/{mid}/board"),
            &token,
        ))
        .await;
    assert_eq!(board.status, 200, "{:?}", board.json);

    // Schema snapshot: column status slugs + the subjects/sub-task-counts placed
    // in each. Derived to avoid non-deterministic UUIDs.
    let columns = board.json["columns"].as_array().unwrap();
    let shape: Vec<Value> = columns
        .iter()
        .map(|c| {
            let status_slug = c["status"].get("slug").and_then(Value::as_str).map(str::to_owned);
            let cards: Vec<Value> = c["issues"]
                .as_array()
                .unwrap()
                .iter()
                .map(|u| json!({ "subject": u["subject"], "subtasks": u["subtasks"].as_array().unwrap().len() }))
                .collect();
            json!({ "status": status_slug, "issues": cards })
        })
        .collect();
    insta::assert_json_snapshot!(shape);
}

/// The planned end date is the commitment; the actual end date is what
/// happened. The gap between them is the slip the gantt draws.
#[tokio::test]
async fn actual_end_date_is_separate_from_the_planned_one() {
    require_db!();
    let app = TestApp::spawn().await;
    let (token, pid) = owner_project(&app).await;

    let created = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/milestones"),
            &token,
            &json!({
                "name": "Ship",
                "start_date": "2026-05-01",
                "end_date": "2026-05-20"
            }),
        ))
        .await;
    assert_eq!(created.status, 201, "{:?}", created.json);
    // Absent until recorded, so "not known" and "on time" stay distinct.
    assert!(created.json["actual_end_date"].is_null());
    let id = created.json["id"].as_str().unwrap().to_owned();
    let url = format!("/api/v1/projects/{pid}/milestones/{id}");

    let slipped = app
        .send(req(
            "PATCH",
            &url,
            Some(&token),
            &[("if-match", &format!("\"{id}:1\""))],
            Some(&json!({ "actual_end_date": "2026-05-27" })),
        ))
        .await;
    assert_eq!(slipped.status, 200, "{:?}", slipped.json);
    assert_eq!(slipped.json["end_date"], "2026-05-20");
    assert_eq!(slipped.json["actual_end_date"], "2026-05-27");

    // Finishing early is just as recordable as finishing late.
    let early = app
        .send(req(
            "PATCH",
            &url,
            Some(&token),
            &[("if-match", &format!("\"{id}:2\""))],
            Some(&json!({ "actual_end_date": "2026-05-15" })),
        ))
        .await;
    assert_eq!(early.status, 200, "{:?}", early.json);
    assert_eq!(early.json["actual_end_date"], "2026-05-15");

    // And it can be cleared again.
    let cleared = app
        .send(req(
            "PATCH",
            &url,
            Some(&token),
            &[("if-match", &format!("\"{id}:3\""))],
            Some(&json!({ "actual_end_date": null })),
        ))
        .await;
    assert_eq!(cleared.status, 200, "{:?}", cleared.json);
    assert!(cleared.json["actual_end_date"].is_null());
}

/// The commercial date trails whichever technical release really happened, so
/// a slipped milestone cannot announce a business release before it finished.
#[tokio::test]
async fn business_release_follows_the_actual_end_when_there_is_one() {
    require_db!();
    let app = TestApp::spawn().await;
    let (token, pid) = owner_project(&app).await;

    let created = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/milestones"),
            &token,
            &json!({
                "name": "Ship",
                "start_date": "2026-05-01",
                "end_date": "2026-05-20",
                "business_release_date": "2026-05-25"
            }),
        ))
        .await;
    assert_eq!(created.status, 201, "{:?}", created.json);
    let id = created.json["id"].as_str().unwrap().to_owned();
    let url = format!("/api/v1/projects/{pid}/milestones/{id}");

    // Slipping past the business release would make it announce a release
    // that had not happened yet.
    let contradictory = app
        .send(req(
            "PATCH",
            &url,
            Some(&token),
            &[("if-match", &format!("\"{id}:1\""))],
            Some(&json!({ "actual_end_date": "2026-05-28" })),
        ))
        .await;
    assert_eq!(contradictory.status, 422, "{:?}", contradictory.json);

    // A slip that still lands before it is fine.
    let ok = app
        .send(req(
            "PATCH",
            &url,
            Some(&token),
            &[("if-match", &format!("\"{id}:1\""))],
            Some(&json!({ "actual_end_date": "2026-05-22" })),
        ))
        .await;
    assert_eq!(ok.status, 200, "{:?}", ok.json);
    assert_eq!(ok.json["business_release_date"], "2026-05-25");
}

/// Completing records what actually happened without asking, using the plan as
/// the best available answer. An already-recorded date is never overwritten.
#[tokio::test]
async fn completing_records_the_actual_end_from_the_plan() {
    require_db!();
    let app = TestApp::spawn().await;
    let (token, pid) = owner_project(&app).await;

    let planned = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/milestones"),
            &token,
            &json!({ "name": "A", "end_date": "2026-06-30" }),
        ))
        .await;
    let a = planned.json["id"].as_str().unwrap().to_owned();
    let closed = app
        .send(post_bearer(
            &format!("/api/v1/projects/{pid}/milestones/{a}/close"),
            &token,
        ))
        .await;
    assert_eq!(closed.status, 200, "{:?}", closed.json);
    assert_eq!(closed.json["actual_end_date"], "2026-06-30");

    // Already recorded → left exactly as it is.
    let recorded = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/milestones"),
            &token,
            &json!({
                "name": "B",
                "end_date": "2026-06-30",
                "actual_end_date": "2026-07-04"
            }),
        ))
        .await;
    let b = recorded.json["id"].as_str().unwrap().to_owned();
    let closed_b = app
        .send(post_bearer(
            &format!("/api/v1/projects/{pid}/milestones/{b}/close"),
            &token,
        ))
        .await;
    assert_eq!(closed_b.json["actual_end_date"], "2026-07-04");

    // No plan to copy from → nothing invented.
    let undated = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/milestones"),
            &token,
            &json!({ "name": "C" }),
        ))
        .await;
    let c = undated.json["id"].as_str().unwrap().to_owned();
    let closed_c = app
        .send(post_bearer(
            &format!("/api/v1/projects/{pid}/milestones/{c}/close"),
            &token,
        ))
        .await;
    assert!(closed_c.json["actual_end_date"].is_null());
}
