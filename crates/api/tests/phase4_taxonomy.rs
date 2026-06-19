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
//! Phase 4 acceptance: per-project taxonomy CRUD + ordering.

mod common;

use common::{TestApp, delete_bearer, get_with_bearer, patch_json_bearer, post_json_bearer};
use serde_json::{Value, json};

const STRONG_PW: &str = "7xK!pq2$mz9Wbe#aQ";

async fn owner_with_project(app: &TestApp) -> (String, String) {
    let _ = app.register("tax@example.com", "taxuser", STRONG_PW).await;
    let token = app
        .login("tax@example.com", STRONG_PW)
        .await
        .access_token()
        .unwrap();
    let project = app
        .send(post_json_bearer(
            "/api/v1/projects",
            &token,
            &json!({ "name": "Taxo" }),
        ))
        .await;
    assert_eq!(project.status, 201, "{:?}", project.json);
    (token, project.json["id"].as_str().unwrap().to_owned())
}

fn names(items: &Value) -> Vec<String> {
    items["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["name"].as_str().unwrap().to_owned())
        .collect()
}

#[tokio::test]
async fn defaults_are_seeded_on_project_creation() {
    require_db!();
    let app = TestApp::spawn().await;
    let (token, pid) = owner_with_project(&app).await;

    let us = app
        .send(get_with_bearer(
            &format!("/api/v1/projects/{pid}/taxonomy/issue_status"),
            &token,
        ))
        .await;
    assert_eq!(us.status, 200);
    assert_eq!(us.json["items"].as_array().unwrap().len(), 6);

    let prio = app
        .send(get_with_bearer(
            &format!("/api/v1/projects/{pid}/taxonomy/priority"),
            &token,
        ))
        .await;
    assert_eq!(prio.json["items"].as_array().unwrap().len(), 5);

    let sizes = app
        .send(get_with_bearer(
            &format!("/api/v1/projects/{pid}/taxonomy/size"),
            &token,
        ))
        .await;
    assert_eq!(sizes.json["items"].as_array().unwrap().len(), 6);
    // A status carries is_closed; a size carries its ordinal value.
    assert!(us.json["items"][0].get("is_closed").is_some());
    assert!(sizes.json["items"][1].get("value").is_some());
}

#[tokio::test]
async fn unknown_kind_is_404() {
    require_db!();
    let app = TestApp::spawn().await;
    let (token, pid) = owner_with_project(&app).await;
    let resp = app
        .send(get_with_bearer(
            &format!("/api/v1/projects/{pid}/taxonomy/bogus"),
            &token,
        ))
        .await;
    assert_eq!(resp.status, 404);
}

#[tokio::test]
async fn crud_lifecycle() {
    require_db!();
    let app = TestApp::spawn().await;
    let (token, pid) = owner_with_project(&app).await;
    let base = format!("/api/v1/projects/{pid}/taxonomy/priority");

    // Create.
    let created = app
        .send(post_json_bearer(
            &base,
            &token,
            &json!({ "name": "Urgent", "slug": "urgent", "color": "#ff0000" }),
        ))
        .await;
    assert_eq!(created.status, 201, "{:?}", created.json);
    let id = created.json["id"].as_str().unwrap().to_owned();
    assert_eq!(created.json["name"], "Urgent");

    // Duplicate slug → 409.
    let dup = app
        .send(post_json_bearer(
            &base,
            &token,
            &json!({ "name": "Urgent2", "slug": "urgent" }),
        ))
        .await;
    assert_eq!(dup.status, 409);

    // Update.
    let updated = app
        .send(patch_json_bearer(
            &format!("{base}/{id}"),
            &token,
            &json!({ "name": "Very Urgent" }),
        ))
        .await;
    assert_eq!(updated.status, 200);
    assert_eq!(updated.json["name"], "Very Urgent");

    // Delete.
    let deleted = app
        .send(delete_bearer(&format!("{base}/{id}"), &token))
        .await;
    assert_eq!(deleted.status, 204);

    // Gone.
    let after = app
        .send(patch_json_bearer(
            &format!("{base}/{id}"),
            &token,
            &json!({ "name": "x" }),
        ))
        .await;
    assert_eq!(after.status, 404);
}

#[tokio::test]
async fn reorder_moves_item_to_front() {
    require_db!();
    let app = TestApp::spawn().await;
    let (token, pid) = owner_with_project(&app).await;
    let base = format!("/api/v1/projects/{pid}/taxonomy/priority");

    let before = app.send(get_with_bearer(&base, &token)).await;
    let items = before.json["items"].as_array().unwrap();
    assert_eq!(
        names(&before.json),
        vec!["Low", "Medium", "High", "Critical", "Blocker"]
    );
    let high_id = items[2]["id"].as_str().unwrap().to_owned();

    // Move "High" to the front (before "Low").
    let mv = app
        .send(post_json_bearer(
            &format!("{base}/{high_id}/move"),
            &token,
            &json!({ "after_id": items[0]["id"] }),
        ))
        .await;
    assert_eq!(mv.status, 204, "{:?}", mv.json);

    let after = app.send(get_with_bearer(&base, &token)).await;
    assert_eq!(
        names(&after.json),
        vec!["High", "Low", "Medium", "Critical", "Blocker"]
    );
}

#[tokio::test]
async fn taxonomy_requires_modify_permission() {
    require_db!();
    let app = TestApp::spawn().await;
    let (owner, pid) = owner_with_project(&app).await;
    let base = format!("/api/v1/projects/{pid}/taxonomy/priority");

    // Invite a dev (no project.modify).
    let invite = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/invitations"),
            &owner,
            &json!({ "email": "tax-dev@example.com", "role": "dev" }),
        ))
        .await;
    let itoken = invite.json["invite_token"].as_str().unwrap().to_owned();
    let _ = app
        .register("tax-dev@example.com", "taxdev", STRONG_PW)
        .await;
    let dev = app
        .login("tax-dev@example.com", STRONG_PW)
        .await
        .access_token()
        .unwrap();
    let _ = app
        .send(post_json_bearer(
            "/api/v1/invitations/accept",
            &dev,
            &json!({ "token": itoken }),
        ))
        .await;

    // Dev can view taxonomy...
    let view = app.send(get_with_bearer(&base, &dev)).await;
    assert_eq!(view.status, 200);

    // ...but cannot create one.
    let create = app
        .send(post_json_bearer(
            &base,
            &dev,
            &json!({ "name": "Nope", "slug": "nope" }),
        ))
        .await;
    assert_eq!(create.status, 403);
}
