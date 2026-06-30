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
// multiple boards (personal + shared) + per-column board data
// ---------------------------------------------------------------------------

#[tokio::test]
async fn boards_crud_default_and_permissions() {
    require_db!();
    let app = TestApp::spawn().await;
    let (token, pid) = owner_with_project(&app, "boards").await;

    // A new project ships with one seeded SHARED default board.
    let list0 = app
        .send(get_with_bearer(
            &format!("/api/v1/projects/{pid}/boards"),
            &token,
        ))
        .await;
    let boards0 = list0.json["boards"].as_array().unwrap();
    assert_eq!(boards0.len(), 1);
    assert_eq!(boards0[0]["visibility"], "shared");
    assert_eq!(boards0[0]["name"], "Board");

    // Create a PERSONAL board (shared omitted → personal).
    let personal = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/boards"),
            &token,
            &json!({ "name": "My WIP", "color": "#ff8a84", "config": { "group": "assignee" } }),
        ))
        .await;
    assert_eq!(personal.status, 201, "{:?}", personal.json);
    assert_eq!(personal.json["visibility"], "personal");
    let bid = personal.json["id"].as_str().unwrap().to_owned();

    // Create a SHARED board (owner is admin → holds board.shared.create).
    let shared = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/boards"),
            &token,
            &json!({ "name": "Team", "shared": true }),
        ))
        .await;
    assert_eq!(shared.status, 201, "{:?}", shared.json);
    assert_eq!(shared.json["visibility"], "shared");

    // Update + last-opened round trip.
    let upd = app
        .send(req(
            "PUT",
            &format!("/api/v1/projects/{pid}/boards/{bid}"),
            Some(&token),
            &[],
            Some(&json!({ "name": "My WIP 2", "color": "#669900", "config": { "group": "epic" } })),
        ))
        .await;
    assert_eq!(upd.status, 200, "{:?}", upd.json);
    assert_eq!(upd.json["name"], "My WIP 2");
    assert_eq!(upd.json["config"]["group"], "epic");

    let setlast = app
        .send(req(
            "PUT",
            &format!("/api/v1/projects/{pid}/boards/{bid}/last-opened"),
            Some(&token),
            &[],
            None,
        ))
        .await;
    assert_eq!(setlast.status, 204);
    let getlast = app
        .send(get_with_bearer(
            &format!("/api/v1/projects/{pid}/boards/last-opened"),
            &token,
        ))
        .await;
    assert_eq!(getlast.json["board_id"], bid);

    // A stakeholder (view-only) member: sees shared boards, NOT the owner's
    // personal one; may create personal but NOT shared.
    let _ = app.register("sh@x", "shuser", STRONG_PW).await;
    let sh = app.login("sh@x", STRONG_PW).await.access_token().unwrap();
    let me = app.send(get_with_bearer("/api/v1/me", &sh)).await;
    let sid = me.json["id"].as_str().unwrap().to_owned();
    let addm = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/members"),
            &token,
            &json!({ "user_id": sid, "role": "stakeholder" }),
        ))
        .await;
    assert_eq!(addm.status, 201, "{:?}", addm.json);

    let sh_list = app
        .send(get_with_bearer(
            &format!("/api/v1/projects/{pid}/boards"),
            &sh,
        ))
        .await;
    let names: Vec<&str> = sh_list.json["boards"]
        .as_array()
        .unwrap()
        .iter()
        .map(|b| b["name"].as_str().unwrap())
        .collect();
    assert!(
        names.contains(&"Board") && names.contains(&"Team"),
        "sees shared boards"
    );
    assert!(
        !names.contains(&"My WIP 2"),
        "does not see owner's personal board"
    );

    let sh_personal = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/boards"),
            &sh,
            &json!({ "name": "Mine" }),
        ))
        .await;
    assert_eq!(sh_personal.status, 201, "{:?}", sh_personal.json);
    let sh_shared = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/boards"),
            &sh,
            &json!({ "name": "Nope", "shared": true }),
        ))
        .await;
    assert_eq!(
        sh_shared.status, 403,
        "stakeholder may not create shared boards"
    );

    // The owner's personal board is invisible to the stakeholder (404 on write).
    let sh_upd = app
        .send(req(
            "PUT",
            &format!("/api/v1/projects/{pid}/boards/{bid}"),
            Some(&sh),
            &[],
            Some(&json!({ "name": "hax" })),
        ))
        .await;
    assert_eq!(sh_upd.status, 404);

    // Owner deletes their personal board.
    let del = app
        .send(delete_bearer(
            &format!("/api/v1/projects/{pid}/boards/{bid}"),
            &token,
        ))
        .await;
    assert_eq!(del.status, 204);
}

#[tokio::test]
async fn board_data_columns_and_lanes() {
    require_db!();
    let app = TestApp::spawn().await;
    let (token, pid) = owner_with_project(&app, "bdata").await;
    let st = statuses(&app, &token, &pid).await;
    let new_id = st.iter().find(|s| s["name"] == "New").unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let done_id = st.iter().find(|s| s["name"] == "Done").unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();

    // Two issues land in New (default), one explicitly in Done.
    let _ = create_issue(&app, &token, &pid, &json!({ "subject": "A" })).await;
    let _ = create_issue(&app, &token, &pid, &json!({ "subject": "B" })).await;
    let _ = create_issue(
        &app,
        &token,
        &pid,
        &json!({ "subject": "C", "status_id": done_id }),
    )
    .await;

    // Flat board data: per-column counts + cards.
    let bd = app
        .send(get_with_bearer(
            &format!("/api/v1/projects/{pid}/board"),
            &token,
        ))
        .await;
    assert_eq!(bd.status, 200, "{:?}", bd.json);
    assert!(bd.json["group"].is_null());
    let cols = bd.json["columns"].as_array().unwrap();
    let new_col = cols.iter().find(|c| c["status_id"] == new_id).unwrap();
    assert_eq!(new_col["total"], 2);
    assert_eq!(new_col["cards"].as_array().unwrap().len(), 2);
    let done_col = cols.iter().find(|c| c["status_id"] == done_id).unwrap();
    assert_eq!(done_col["total"], 1);

    // column_limit caps the cards but not the total.
    let capped = app
        .send(get_with_bearer(
            &format!("/api/v1/projects/{pid}/board?column_limit=1"),
            &token,
        ))
        .await;
    let new_capped = capped.json["columns"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["status_id"] == new_id)
        .unwrap()
        .clone();
    assert_eq!(new_capped["total"], 2);
    assert_eq!(new_capped["cards"].as_array().unwrap().len(), 1);

    // Swimlanes: group by assignee → lanes envelope.
    let grouped = app
        .send(get_with_bearer(
            &format!("/api/v1/projects/{pid}/board?group=assignee"),
            &token,
        ))
        .await;
    assert_eq!(grouped.json["group"], "assignee");
    assert!(grouped.json["lanes"].is_array());
    // Everything is unassigned → a single "none" lane.
    let lanes = grouped.json["lanes"].as_array().unwrap();
    assert_eq!(lanes.len(), 1);
    assert_eq!(lanes[0]["key"], "none");
    assert_eq!(lanes[0]["total"], 3);
}
