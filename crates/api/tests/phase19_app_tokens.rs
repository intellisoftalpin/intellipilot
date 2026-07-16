//! Phase 19 — app tokens (machine API access) + the INTELLIBOT actor (V004).
//!
//! Covers: one-time secret on create + masked listing; project-scoped +
//! permission-scoped authorisation; INTELLIBOT attribution on writes;
//! revoked/expired/garbage rejection; app tokens barred from user-only and
//! admin endpoints; non-superadmins barred from token management; edit/revoke
//! effects; INTELLIBOT hidden from the user directory and unable to log in.
#![cfg(test)]
#![allow(
    let_underscore_drop,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_panics_doc,
    clippy::print_stderr,
    clippy::too_many_lines,
    clippy::string_slice,
    clippy::let_underscore_untyped
)]

mod common;

use common::{TestApp, get_with_bearer, patch_json_bearer, post_bearer, post_json_bearer};
use serde_json::{Value, json};

const PW: &str = "correct horse battery staple";
const INTELLIBOT_ID: &str = "b0700000-0000-7000-8000-000000000000";

async fn promote_to_superadmin(app: &TestApp, email: &str) {
    let client = app.db.pool.get().await.unwrap();
    client
        .execute(
            "UPDATE users SET is_superadmin = true WHERE email = $1",
            &[&email.trim().to_lowercase()],
        )
        .await
        .unwrap();
}

/// Register + login a user, returning their access token.
async fn user(app: &TestApp, email: &str, username: &str) -> String {
    let r = app.register(email, username, PW).await;
    assert_eq!(r.status, 201, "register: {:?}", r.json);
    app.login(email, PW).await.access_token().expect("token")
}

/// A superadmin access token.
async fn admin(app: &TestApp) -> String {
    user(app, "admin@x", "adminuser").await;
    promote_to_superadmin(app, "admin@x").await;
    // The superadmin flag is read per request, so the original token would work
    // too; re-login just to mirror real usage.
    app.login("admin@x", PW)
        .await
        .access_token()
        .expect("token")
}

async fn create_project(app: &TestApp, token: &str, name: &str, visibility: &str) -> String {
    let r = app
        .send(post_json_bearer(
            "/api/v1/projects",
            token,
            &json!({ "name": name, "visibility": visibility }),
        ))
        .await;
    assert_eq!(r.status, 201, "create project: {:?}", r.json);
    r.json["id"].as_str().unwrap().to_owned()
}

/// Create an app token; returns the full creation response JSON.
async fn create_token(app: &TestApp, admin_token: &str, body: &Value) -> common::TestResponse {
    app.send(post_json_bearer(
        "/api/v1/admin/app-tokens",
        admin_token,
        body,
    ))
    .await
}

// ---------------------------------------------------------------------------

#[tokio::test]
async fn create_returns_secret_once_and_list_is_masked() {
    require_db!();
    let app = TestApp::spawn().await;
    let admin = admin(&app).await;
    let pid = create_project(&app, &admin, "P", "private").await;

    let r = create_token(
        &app,
        &admin,
        &json!({
            "name": "CI bot",
            "permissions": ["issue.view", "issue.create"],
            "project_ids": [pid],
        }),
    )
    .await;
    assert_eq!(r.status, 201, "{:?}", r.json);
    let secret = r.json["secret"].as_str().unwrap();
    assert!(secret.starts_with("ipat_"), "secret prefix: {secret}");
    assert_eq!(r.json["token"]["name"], "CI bot");
    assert_eq!(r.json["token"]["last4"], secret[secret.len() - 4..]);
    let perms: Vec<&str> = r.json["token"]["permissions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert!(perms.contains(&"issue.create") && perms.contains(&"issue.view"));

    // Listing never exposes the secret, only the masked hints.
    let list = app
        .send(get_with_bearer("/api/v1/admin/app-tokens", &admin))
        .await;
    assert_eq!(list.status, 200, "{:?}", list.json);
    let items = list.json.as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert!(items[0].get("secret").is_none(), "secret must not leak");
    assert_eq!(items[0]["last4"], secret[secret.len() - 4..]);
    assert!(items[0]["prefix"].as_str().unwrap().starts_with("ipat_"));
}

#[tokio::test]
async fn app_token_acts_in_scope_and_is_attributed_to_intellibot() {
    require_db!();
    let app = TestApp::spawn().await;
    let admin = admin(&app).await;
    let pid = create_project(&app, &admin, "P", "private").await;

    let r = create_token(
        &app,
        &admin,
        &json!({
            "name": "writer",
            "permissions": ["issue.view", "issue.create", "comment.create"],
            "project_ids": [pid],
        }),
    )
    .await;
    let secret = r.json["secret"].as_str().unwrap().to_owned();

    // Create an issue with the token.
    let issue = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/issues"),
            &secret,
            &json!({ "subject": "from the bot" }),
        ))
        .await;
    assert_eq!(issue.status, 201, "{:?}", issue.json);
    assert_eq!(
        issue.json["owner_id"], INTELLIBOT_ID,
        "issue must be owned by INTELLIBOT"
    );
    let issue_id = issue.json["id"].as_str().unwrap().to_owned();

    // Comment with the token → authored by INTELLIBOT.
    let comment = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/issues/{issue_id}/comments"),
            &secret,
            &json!({ "body": "beep boop" }),
        ))
        .await;
    assert_eq!(comment.status, 201, "{:?}", comment.json);
    assert_eq!(comment.json["author_id"], INTELLIBOT_ID);
}

#[tokio::test]
async fn app_token_lists_only_its_scoped_projects() {
    require_db!();
    let app = TestApp::spawn().await;
    let admin = admin(&app).await;
    let in_scope = create_project(&app, &admin, "InScope", "private").await;
    let _out_of_scope = create_project(&app, &admin, "OutOfScope", "private").await;

    let r = create_token(
        &app,
        &admin,
        &json!({ "name": "lister", "permissions": ["issue.view"], "project_ids": [in_scope] }),
    )
    .await;
    let secret = r.json["secret"].as_str().unwrap().to_owned();

    let list = app.send(get_with_bearer("/api/v1/projects", &secret)).await;
    assert_eq!(list.status, 200, "{:?}", list.json);
    let projects = list.json["projects"].as_array().unwrap();
    assert_eq!(projects.len(), 1);
    assert_eq!(projects[0]["id"], in_scope);
}

#[tokio::test]
async fn app_token_denied_without_permission() {
    require_db!();
    let app = TestApp::spawn().await;
    let admin = admin(&app).await;
    let pid = create_project(&app, &admin, "P", "private").await;

    // View-only token.
    let r = create_token(
        &app,
        &admin,
        &json!({ "name": "reader", "permissions": ["issue.view"], "project_ids": [pid] }),
    )
    .await;
    let secret = r.json["secret"].as_str().unwrap().to_owned();

    // Can read…
    let list = app
        .send(get_with_bearer(
            &format!("/api/v1/projects/{pid}/issues"),
            &secret,
        ))
        .await;
    assert_eq!(list.status, 200, "{:?}", list.json);
    // …but cannot create.
    let create = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/issues"),
            &secret,
            &json!({ "subject": "nope" }),
        ))
        .await;
    assert_eq!(create.status, 403, "{:?}", create.json);
}

#[tokio::test]
async fn app_token_denied_outside_project_scope() {
    require_db!();
    let app = TestApp::spawn().await;
    let admin = admin(&app).await;
    let scoped = create_project(&app, &admin, "A", "private").await;
    // An internal project the token is NOT scoped to: existence isn't hidden,
    // so we get a clean 403 (rather than the 404 a private project would give).
    let other = create_project(&app, &admin, "B", "internal").await;

    let r = create_token(
        &app,
        &admin,
        &json!({
            "name": "scoped",
            "permissions": ["issue.view", "issue.create"],
            "project_ids": [scoped],
        }),
    )
    .await;
    let secret = r.json["secret"].as_str().unwrap().to_owned();

    let in_scope = app
        .send(get_with_bearer(
            &format!("/api/v1/projects/{scoped}/issues"),
            &secret,
        ))
        .await;
    assert_eq!(in_scope.status, 200, "in scope: {:?}", in_scope.json);

    let out = app
        .send(get_with_bearer(
            &format!("/api/v1/projects/{other}/issues"),
            &secret,
        ))
        .await;
    assert_eq!(out.status, 403, "out of scope: {:?}", out.json);
}

#[tokio::test]
async fn revoked_and_expired_and_garbage_tokens_are_unauthorized() {
    require_db!();
    let app = TestApp::spawn().await;
    let admin = admin(&app).await;
    let pid = create_project(&app, &admin, "P", "private").await;

    // Garbage.
    let bad = app
        .send(get_with_bearer(
            &format!("/api/v1/projects/{pid}/issues"),
            "ipat_not_a_real_token",
        ))
        .await;
    assert_eq!(bad.status, 401);

    // Expired.
    let exp = create_token(
        &app,
        &admin,
        &json!({
            "name": "expired",
            "permissions": ["issue.view"],
            "project_ids": [pid],
            "expires_at": "2020-01-01T00:00:00Z",
        }),
    )
    .await;
    let exp_secret = exp.json["secret"].as_str().unwrap().to_owned();
    let r = app
        .send(get_with_bearer(
            &format!("/api/v1/projects/{pid}/issues"),
            &exp_secret,
        ))
        .await;
    assert_eq!(r.status, 401, "expired token: {:?}", r.json);

    // Revoked.
    let live = create_token(
        &app,
        &admin,
        &json!({ "name": "live", "permissions": ["issue.view"], "project_ids": [pid] }),
    )
    .await;
    let live_secret = live.json["secret"].as_str().unwrap().to_owned();
    let token_id = live.json["token"]["id"].as_str().unwrap().to_owned();
    // Works before revoke.
    let before = app
        .send(get_with_bearer(
            &format!("/api/v1/projects/{pid}/issues"),
            &live_secret,
        ))
        .await;
    assert_eq!(before.status, 200);
    // Revoke.
    let rev = app
        .send(post_bearer(
            &format!("/api/v1/admin/app-tokens/{token_id}/revoke"),
            &admin,
        ))
        .await;
    assert_eq!(rev.status, 204);
    // Dead after revoke.
    let after = app
        .send(get_with_bearer(
            &format!("/api/v1/projects/{pid}/issues"),
            &live_secret,
        ))
        .await;
    assert_eq!(after.status, 401, "revoked token: {:?}", after.json);
}

#[tokio::test]
async fn app_token_barred_from_user_and_admin_endpoints() {
    require_db!();
    let app = TestApp::spawn().await;
    let admin = admin(&app).await;
    let pid = create_project(&app, &admin, "P", "private").await;
    let r = create_token(
        &app,
        &admin,
        &json!({ "name": "t", "permissions": ["issue.view"], "project_ids": [pid] }),
    )
    .await;
    let secret = r.json["secret"].as_str().unwrap().to_owned();

    // User-only endpoint.
    let me = app.send(get_with_bearer("/api/v1/me", &secret)).await;
    assert_eq!(me.status, 401, "/me with app token: {:?}", me.json);

    // Admin endpoint (app tokens are not superadmins, and aren't even users).
    let admin_list = app
        .send(get_with_bearer("/api/v1/admin/app-tokens", &secret))
        .await;
    assert_eq!(
        admin_list.status, 401,
        "admin with app token: {:?}",
        admin_list.json
    );
}

#[tokio::test]
async fn non_superadmin_cannot_manage_tokens() {
    require_db!();
    let app = TestApp::spawn().await;
    let admin = admin(&app).await;
    let pid = create_project(&app, &admin, "P", "private").await;
    let plain = user(&app, "bob@x", "bobuser").await;

    let create = create_token(
        &app,
        &plain,
        &json!({ "name": "t", "permissions": ["issue.view"], "project_ids": [pid] }),
    )
    .await;
    assert_eq!(create.status, 403, "{:?}", create.json);

    let list = app
        .send(get_with_bearer("/api/v1/admin/app-tokens", &plain))
        .await;
    assert_eq!(list.status, 403);
}

#[tokio::test]
async fn update_changes_permissions_and_scope() {
    require_db!();
    let app = TestApp::spawn().await;
    let admin = admin(&app).await;
    let a = create_project(&app, &admin, "A", "private").await;
    let b = create_project(&app, &admin, "B", "private").await;

    let r = create_token(
        &app,
        &admin,
        &json!({ "name": "t", "permissions": ["issue.view"], "project_ids": [a] }),
    )
    .await;
    let secret = r.json["secret"].as_str().unwrap().to_owned();
    let id = r.json["token"]["id"].as_str().unwrap().to_owned();

    // Initially cannot create in A and cannot see B.
    let c1 = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{a}/issues"),
            &secret,
            &json!({ "subject": "x" }),
        ))
        .await;
    assert_eq!(c1.status, 403);

    // Grant issue.create and add project B.
    let upd = app
        .send(patch_json_bearer(
            &format!("/api/v1/admin/app-tokens/{id}"),
            &admin,
            &json!({ "permissions": ["issue.view", "issue.create"], "project_ids": [a, b] }),
        ))
        .await;
    assert_eq!(upd.status, 200, "{:?}", upd.json);

    // Now creation works in both A and B.
    for p in [&a, &b] {
        let c = app
            .send(post_json_bearer(
                &format!("/api/v1/projects/{p}/issues"),
                &secret,
                &json!({ "subject": "ok" }),
            ))
            .await;
        assert_eq!(c.status, 201, "create in {p}: {:?}", c.json);
    }
}

#[tokio::test]
async fn create_rejects_unknown_project() {
    require_db!();
    let app = TestApp::spawn().await;
    let admin = admin(&app).await;
    let r = create_token(
        &app,
        &admin,
        &json!({
            "name": "t",
            "permissions": ["issue.view"],
            "project_ids": ["00000000-0000-0000-0000-000000000000"],
        }),
    )
    .await;
    assert_eq!(r.status, 422, "{:?}", r.json);
}

#[tokio::test]
async fn intellibot_is_hidden_and_cannot_log_in() {
    require_db!();
    let app = TestApp::spawn().await;
    let admin = admin(&app).await;

    // Not present in the admin user directory.
    let users = app
        .send(get_with_bearer("/api/v1/admin/users", &admin))
        .await;
    assert_eq!(users.status, 200, "{:?}", users.json);
    let names: Vec<&str> = users.json["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|u| u["username"].as_str().unwrap_or(""))
        .collect();
    assert!(
        !names.contains(&"INTELLIBOT"),
        "INTELLIBOT must be hidden from the user list: {names:?}"
    );

    // Cannot authenticate (no password, auth_source='system').
    let login = app.login("intellibot@system.local", PW).await;
    assert_ne!(
        login.status, 200,
        "INTELLIBOT must not log in: {:?}",
        login.json
    );
}

#[tokio::test]
async fn revoke_unknown_token_is_404() {
    require_db!();
    let app = TestApp::spawn().await;
    let admin = admin(&app).await;
    let r = app
        .send(post_bearer(
            "/api/v1/admin/app-tokens/00000000-0000-7000-8000-000000000000/revoke",
            &admin,
        ))
        .await;
    assert_eq!(r.status, 404, "{:?}", r.json);

    // Delete route is not exposed; revoke is the lifecycle op. Sanity: GET of a
    // missing token is 404 too.
    let g = app
        .send(get_with_bearer(
            "/api/v1/admin/app-tokens/00000000-0000-7000-8000-000000000001",
            &admin,
        ))
        .await;
    assert_eq!(g.status, 404);
}
