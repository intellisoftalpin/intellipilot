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
//! Acceptance: the project-configuration entities (taxonomy, labels,
//! components, repositories, customers, releases) are gated by their own
//! create/modify/delete permissions instead of the coarse `project.modify`.

mod common;

use common::{TestApp, delete_bearer, get_with_bearer, post_json_bearer};
use serde_json::json;

const STRONG_PW: &str = "7xK!pq2$mz9Wbe#aQ";

/// Register + log a fresh user in, returning their access token.
async fn fresh_user(app: &TestApp, email: &str, username: &str) -> String {
    let _ = app.register(email, username, STRONG_PW).await;
    app.login(email, STRONG_PW)
        .await
        .access_token()
        .expect("access token")
}

/// Owner (admin) with a brand-new project; returns (owner_token, project_id).
async fn owner_with_project(app: &TestApp) -> (String, String) {
    let owner = fresh_user(app, "cfg-owner@example.com", "cfgowner").await;
    let project = app
        .send(post_json_bearer(
            "/api/v1/projects",
            &owner,
            &json!({ "name": "Config" }),
        ))
        .await;
    assert_eq!(project.status, 201, "{:?}", project.json);
    (owner, project.json["id"].as_str().unwrap().to_owned())
}

/// Create a custom role with the given permission wire strings, then invite a
/// new user into it and return that user's access token.
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
            &json!({
                "name": role_slug,
                "slug": role_slug,
                "permissions": permissions,
            }),
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

/// POST a minimal create request for each config entity; returns the status.
async fn try_create_all(
    app: &TestApp,
    token: &str,
    pid: &str,
    tag: &str,
) -> Vec<(&'static str, u16)> {
    let mut out = Vec::new();
    let tax = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/taxonomy/priority"),
            token,
            &json!({ "name": format!("P-{tag}"), "slug": format!("p-{tag}") }),
        ))
        .await;
    out.push(("taxonomy", tax.status));
    let label = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/labels"),
            token,
            &json!({ "name": format!("L-{tag}") }),
        ))
        .await;
    out.push(("label", label.status));
    let comp = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/components"),
            token,
            &json!({ "name": format!("C-{tag}") }),
        ))
        .await;
    out.push(("component", comp.status));
    let cust = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/customers"),
            token,
            &json!({ "name": format!("Cust-{tag}") }),
        ))
        .await;
    out.push(("customer", cust.status));
    let rel = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/releases"),
            token,
            &json!({ "name": format!("R-{tag}") }),
        ))
        .await;
    out.push(("release", rel.status));
    out
}

#[tokio::test]
async fn fine_grained_create_permissions_grant_access_without_project_modify() {
    require_db!();
    let app = TestApp::spawn().await;
    let (owner, pid) = owner_with_project(&app).await;

    // A role holding ONLY the per-entity create permissions (and view) — but
    // NOT project.modify — can create every config entity.
    let editor = member_with_role(
        &app,
        &owner,
        &pid,
        "config_editor",
        &[
            "project.view",
            "taxonomy.create",
            "label.create",
            "component.create",
            "customer.create",
            "release.create",
        ],
        "cfg-editor@example.com",
        "cfgeditor",
    )
    .await;

    for (entity, status) in try_create_all(&app, &editor, &pid, "ok").await {
        assert_eq!(status, 201, "{entity} create should be allowed");
    }
}

#[tokio::test]
async fn project_modify_no_longer_grants_config_edit() {
    require_db!();
    let app = TestApp::spawn().await;
    let (owner, pid) = owner_with_project(&app).await;

    // A role with project.modify but none of the new config permissions can no
    // longer create config entities — proving the split from the coarse gate.
    let modifier = member_with_role(
        &app,
        &owner,
        &pid,
        "modifier_only",
        &["project.view", "project.modify"],
        "cfg-modifier@example.com",
        "cfgmodifier",
    )
    .await;

    for (entity, status) in try_create_all(&app, &modifier, &pid, "no").await {
        assert_eq!(status, 403, "{entity} create should be forbidden");
    }
}

#[tokio::test]
async fn create_permission_does_not_grant_delete() {
    require_db!();
    let app = TestApp::spawn().await;
    let (owner, pid) = owner_with_project(&app).await;
    let base = format!("/api/v1/projects/{pid}/taxonomy/priority");

    // Role can create taxonomy but not delete it.
    let creator = member_with_role(
        &app,
        &owner,
        &pid,
        "tax_creator",
        &["project.view", "taxonomy.create"],
        "cfg-creator@example.com",
        "cfgcreator",
    )
    .await;

    let created = app
        .send(post_json_bearer(
            &base,
            &creator,
            &json!({ "name": "Spicy", "slug": "spicy" }),
        ))
        .await;
    assert_eq!(created.status, 201, "{:?}", created.json);
    let id = created.json["id"].as_str().unwrap().to_owned();

    // The same role cannot delete it (lacks taxonomy.delete).
    let del = app
        .send(delete_bearer(&format!("{base}/{id}"), &creator))
        .await;
    assert_eq!(del.status, 403, "delete should require taxonomy.delete");

    // The owner (admin) still can.
    let owner_del = app
        .send(delete_bearer(&format!("{base}/{id}"), &owner))
        .await;
    assert_eq!(owner_del.status, 204);
}

#[tokio::test]
async fn default_developer_cannot_edit_config_entities() {
    require_db!();
    let app = TestApp::spawn().await;
    let (owner, pid) = owner_with_project(&app).await;

    // The built-in developer role does not get any config permissions by
    // default; it can view but not create.
    let invite = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/invitations"),
            &owner,
            &json!({ "email": "cfg-dev@example.com", "role": "dev" }),
        ))
        .await;
    let itoken = invite.json["invite_token"].as_str().unwrap().to_owned();
    let dev = fresh_user(&app, "cfg-dev@example.com", "cfgdev").await;
    let _ = app
        .send(post_json_bearer(
            "/api/v1/invitations/accept",
            &dev,
            &json!({ "token": itoken }),
        ))
        .await;

    // Can read labels...
    let view = app
        .send(get_with_bearer(
            &format!("/api/v1/projects/{pid}/labels"),
            &dev,
        ))
        .await;
    assert_eq!(view.status, 200);

    // ...but every create is forbidden.
    for (entity, status) in try_create_all(&app, &dev, &pid, "dev").await {
        assert_eq!(status, 403, "{entity} create should be forbidden for dev");
    }
}

#[tokio::test]
async fn product_owner_can_edit_config_entities() {
    require_db!();
    let app = TestApp::spawn().await;
    let (owner, pid) = owner_with_project(&app).await;

    // The built-in product_owner role gets all config permissions, preserving
    // the prior behavior (it formerly relied on project.modify).
    let invite = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/invitations"),
            &owner,
            &json!({ "email": "cfg-po@example.com", "role": "product_owner" }),
        ))
        .await;
    let itoken = invite.json["invite_token"].as_str().unwrap().to_owned();
    let po = fresh_user(&app, "cfg-po@example.com", "cfgpo").await;
    let _ = app
        .send(post_json_bearer(
            "/api/v1/invitations/accept",
            &po,
            &json!({ "token": itoken }),
        ))
        .await;

    for (entity, status) in try_create_all(&app, &po, &pid, "po").await {
        assert_eq!(status, 201, "{entity} create should be allowed for PO");
    }
}
