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
//! Phase 14 acceptance: new issue fields (size/category/customer/dates/
//! resolution/fix-version), per-project customers, relationships, watchers.

mod common;

use common::{TestApp, delete_bearer, get_with_bearer, patch_json_bearer, post_json_bearer};
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
            &json!({ "name": "Meta" }),
        ))
        .await;
    assert_eq!(project.status, 201, "{:?}", project.json);
    (token, project.json["id"].as_str().unwrap().to_owned())
}

/// Look up a taxonomy item id by kind + display name.
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

async fn create_issue(app: &TestApp, token: &str, pid: &str, body: &Value) -> common::TestResponse {
    app.send(post_json_bearer(
        &format!("/api/v1/projects/{pid}/issues"),
        token,
        body,
    ))
    .await
}

#[tokio::test]
async fn customers_crud_and_perms() {
    require_db!();
    let app = TestApp::spawn().await;
    let (token, pid) = owner_with_project(&app, "custowner").await;

    let created = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/customers"),
            &token,
            &json!({
                "name": "Acme", "company_name": "Acme Inc",
                "contact_email": "ops@acme.test", "phone": "+1 555"
            }),
        ))
        .await;
    assert_eq!(created.status, 201, "{:?}", created.json);
    assert_eq!(created.json["name"], "Acme");
    let cid = created.json["id"].as_str().unwrap().to_owned();

    // Duplicate name → 409.
    let dup = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/customers"),
            &token,
            &json!({ "name": "Acme" }),
        ))
        .await;
    assert_eq!(dup.status, 409);

    // Invalid email → 422.
    let bad = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/customers"),
            &token,
            &json!({ "name": "Bad", "contact_email": "not-an-email" }),
        ))
        .await;
    assert_eq!(bad.status, 422);

    // Update.
    let upd = app
        .send(patch_json_bearer(
            &format!("/api/v1/projects/{pid}/customers/{cid}"),
            &token,
            &json!({ "phone": "+44 20" }),
        ))
        .await;
    assert_eq!(upd.status, 200, "{:?}", upd.json);
    assert_eq!(upd.json["phone"], "+44 20");
    assert_eq!(upd.json["name"], "Acme");

    // List + delete.
    let list = app
        .send(get_with_bearer(
            &format!("/api/v1/projects/{pid}/customers"),
            &token,
        ))
        .await;
    assert_eq!(list.json["customers"].as_array().unwrap().len(), 1);
    let del = app
        .send(delete_bearer(
            &format!("/api/v1/projects/{pid}/customers/{cid}"),
            &token,
        ))
        .await;
    assert_eq!(del.status, 204);
}

#[tokio::test]
async fn issue_new_fields_round_trip_and_resolution() {
    require_db!();
    let app = TestApp::spawn().await;
    let (token, pid) = owner_with_project(&app, "fields").await;
    let size_m = tax_id(&app, &token, &pid, "size", "M").await;
    let st_new = tax_id(&app, &token, &pid, "issue_status", "New").await;
    let st_done = tax_id(&app, &token, &pid, "issue_status", "Done").await;
    let cust = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/customers"),
            &token,
            &json!({ "name": "Globex" }),
        ))
        .await;
    let cust_id = cust.json["id"].as_str().unwrap().to_owned();

    let created = create_issue(
        &app,
        &token,
        &pid,
        &json!({
            "subject": "Feature X",
            "size_id": size_m,
            "category": "customer_request",
            "customer_id": cust_id,
            "start_date": "2026-06-01",
            "due_date": "2026-06-30",
            "status_id": st_new,
            "release_text": "PSBP 1.1 (manual)"
        }),
    )
    .await;
    assert_eq!(created.status, 201, "{:?}", created.json);
    assert_eq!(created.json["size_id"], size_m);
    assert_eq!(created.json["category"], "customer_request");
    assert_eq!(created.json["customer_id"], cust_id);
    assert_eq!(created.json["start_date"], "2026-06-01");
    assert_eq!(created.json["due_date"], "2026-06-30");
    assert_eq!(created.json["release_text"], "PSBP 1.1 (manual)");
    assert!(created.json["resolved_at"].is_null());
    let id = created.json["id"].as_str().unwrap().to_owned();
    let etag = created.header("etag").unwrap().to_owned();

    // Move to a closed status + set resolution → resolved_at populated.
    let resolved = app
        .send(common::req(
            "PATCH",
            &format!("/api/v1/projects/{pid}/issues/{id}"),
            Some(&token),
            &[("if-match", &etag)],
            Some(&json!({ "status_id": st_done, "resolution": "fixed" })),
        ))
        .await;
    assert_eq!(resolved.status, 200, "{:?}", resolved.json);
    assert_eq!(resolved.json["resolution"], "fixed");
    assert!(
        !resolved.json["resolved_at"].is_null(),
        "resolved_at set on close"
    );

    // Reopen → resolved_at cleared.
    let etag2 = resolved.header("etag").unwrap().to_owned();
    let reopened = app
        .send(common::req(
            "PATCH",
            &format!("/api/v1/projects/{pid}/issues/{id}"),
            Some(&token),
            &[("if-match", &etag2)],
            Some(&json!({ "status_id": st_new })),
        ))
        .await;
    assert_eq!(reopened.status, 200, "{:?}", reopened.json);
    assert!(
        reopened.json["resolved_at"].is_null(),
        "resolved_at cleared on reopen"
    );
}

#[tokio::test]
async fn invalid_category_and_customer_and_fix_version() {
    require_db!();
    let app = TestApp::spawn().await;
    let (token, pid) = owner_with_project(&app, "validate").await;

    // Bad enum value is rejected (deserialize/validation).
    let bad_cat = create_issue(
        &app,
        &token,
        &pid,
        &json!({ "subject": "x", "category": "made_up" }),
    )
    .await;
    assert!(
        matches!(bad_cat.status, 400 | 422),
        "got {}",
        bad_cat.status
    );

    // Unknown customer → 422.
    let bad_cust = create_issue(
        &app,
        &token,
        &pid,
        &json!({ "subject": "x", "customer_id": uuid::Uuid::now_v7() }),
    )
    .await;
    assert_eq!(bad_cust.status, 422, "{:?}", bad_cust.json);

    // Both fix-version forms → 422.
    let both = create_issue(
        &app,
        &token,
        &pid,
        &json!({
            "subject": "x",
            "release_version_id": uuid::Uuid::now_v7(),
            "release_text": "1.0"
        }),
    )
    .await;
    assert_eq!(both.status, 422, "{:?}", both.json);
}

#[tokio::test]
async fn issue_relationships() {
    require_db!();
    let app = TestApp::spawn().await;
    let (token, pid) = owner_with_project(&app, "links").await;
    let a = create_issue(&app, &token, &pid, &json!({ "subject": "A" })).await;
    let b = create_issue(&app, &token, &pid, &json!({ "subject": "B" })).await;
    let aid = a.json["id"].as_str().unwrap().to_owned();
    let bid = b.json["id"].as_str().unwrap().to_owned();

    // A blocks B.
    let link = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/issues/{aid}/links"),
            &token,
            &json!({ "target_issue_id": bid, "link_type": "blocks" }),
        ))
        .await;
    assert_eq!(link.status, 201, "{:?}", link.json);
    let link_id = link.json["id"].as_str().unwrap().to_owned();

    // Outgoing on A, incoming on B.
    let a_links = app
        .send(get_with_bearer(
            &format!("/api/v1/projects/{pid}/issues/{aid}/links"),
            &token,
        ))
        .await;
    assert_eq!(a_links.json["links"][0]["direction"], "outgoing");
    let b_links = app
        .send(get_with_bearer(
            &format!("/api/v1/projects/{pid}/issues/{bid}/links"),
            &token,
        ))
        .await;
    assert_eq!(b_links.json["links"][0]["direction"], "incoming");

    // Self-link → 422.
    let self_link = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/issues/{aid}/links"),
            &token,
            &json!({ "target_issue_id": aid, "link_type": "relates" }),
        ))
        .await;
    assert_eq!(self_link.status, 422);

    // Duplicate → 409.
    let dup = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/issues/{aid}/links"),
            &token,
            &json!({ "target_issue_id": bid, "link_type": "blocks" }),
        ))
        .await;
    assert_eq!(dup.status, 409);

    // Delete.
    let del = app
        .send(delete_bearer(
            &format!("/api/v1/projects/{pid}/issues/{aid}/links/{link_id}"),
            &token,
        ))
        .await;
    assert_eq!(del.status, 204);
}

#[tokio::test]
async fn issue_watchers() {
    require_db!();
    let app = TestApp::spawn().await;
    let (token, pid) = owner_with_project(&app, "watch").await;
    let issue = create_issue(&app, &token, &pid, &json!({ "subject": "W" })).await;
    let id = issue.json["id"].as_str().unwrap().to_owned();

    // Watch as self.
    let add = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/issues/{id}/watchers"),
            &token,
            &json!({}),
        ))
        .await;
    assert_eq!(add.status, 204);

    let list = app
        .send(get_with_bearer(
            &format!("/api/v1/projects/{pid}/issues/{id}/watchers"),
            &token,
        ))
        .await;
    let watchers = list.json["watchers"].as_array().unwrap();
    assert_eq!(watchers.len(), 1);
    let me = watchers[0].as_str().unwrap().to_owned();

    let del = app
        .send(delete_bearer(
            &format!("/api/v1/projects/{pid}/issues/{id}/watchers/{me}"),
            &token,
        ))
        .await;
    assert_eq!(del.status, 204);
}
