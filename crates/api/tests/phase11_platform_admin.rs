//! Phase 11 — platform-admin + invite-only registration (V011).
//!
//! Covers:
//!   * Register gate (open=false → 403; open=true → 201; invitation flow).
//!   * Invitation token reuse / expired / email-mismatch errors.
//!   * Admin endpoints: list, create, patch, delete, reset-password, invitations,
//!     settings.
//!   * Last-superadmin guard on demote / deactivate / delete.
//!   * `must_change_password` flag plumbing.
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
    clippy::let_underscore_untyped
)]

mod common;

use axum::body::Body;
use axum::http::Request;
use common::{TestApp, get_with_bearer, json_post, req};
use serde_json::{Value, json};

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

/// Promote the user with the given email to superadmin via the DB. The HTTP
/// API has no "promote yourself" path — production uses the env-driven
/// bootstrap step in `main.rs` instead.
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

/// Flip the open-registration toggle directly via the DB (skipping the auth-
/// gated admin endpoint). Used to set up tests that exercise the open path.
async fn set_open_registration(app: &TestApp, value: bool) {
    let client = app.db.pool.get().await.unwrap();
    client
        .execute(
            "UPDATE platform_settings SET open_registration = $1 WHERE id = 1",
            &[&value],
        )
        .await
        .unwrap();
}

async fn register_and_login(app: &TestApp, email: &str, username: &str) -> String {
    let r = app
        .register(email, username, "correct horse battery staple")
        .await;
    assert_eq!(r.status, 201, "register: {:?}", r.json);
    let l = app.login(email, "correct horse battery staple").await;
    assert_eq!(l.status, 200, "login: {:?}", l.json);
    l.access_token().expect("access token")
}

fn delete_req(uri: &str, token: &str) -> Request<Body> {
    req("DELETE", uri, Some(token), &[], None)
}

fn patch_req(uri: &str, token: &str, body: &Value) -> Request<Body> {
    req("PATCH", uri, Some(token), &[], Some(body))
}

fn post_req(uri: &str, token: &str, body: &Value) -> Request<Body> {
    req("POST", uri, Some(token), &[], Some(body))
}

fn post_no_body(uri: &str, token: &str) -> Request<Body> {
    req("POST", uri, Some(token), &[], None)
}

// ---------------------------------------------------------------------------
// register gating
// ---------------------------------------------------------------------------

#[tokio::test]
async fn register_open_succeeds() {
    let app = TestApp::spawn().await;
    set_open_registration(&app, true).await;
    let r = app
        .register("user@x", "user", "correct horse battery staple")
        .await;
    assert_eq!(r.status, 201, "{:?}", r.json);
    // must_change_password is false on open-registration accounts.
    assert_eq!(r.json["must_change_password"], Value::Bool(false));
    assert_eq!(r.json["is_superadmin"], Value::Bool(false));
}

#[tokio::test]
async fn register_closed_without_token_is_forbidden() {
    let app = TestApp::spawn().await;
    // default platform_settings.open_registration = false
    let r = app
        .register("user@x", "user", "correct horse battery staple")
        .await;
    assert_eq!(r.status, 403);
    assert_eq!(r.json["type"], "registration_closed");
}

#[tokio::test]
async fn invitation_flow_end_to_end() {
    let app = TestApp::spawn().await;
    // Bootstrap a superadmin out-of-band.
    set_open_registration(&app, true).await;
    let r = app
        .register("admin@x", "admin", "correct horse battery staple")
        .await;
    assert_eq!(r.status, 201);
    promote_to_superadmin(&app, "admin@x").await;
    set_open_registration(&app, false).await;
    let admin_token = app
        .login("admin@x", "correct horse battery staple")
        .await
        .access_token()
        .unwrap();

    // Admin issues an invitation for 'new@x'.
    let r = app
        .send(post_req(
            "/api/v1/admin/invitations",
            &admin_token,
            &json!({ "email": "new@x", "role": "user" }),
        ))
        .await;
    assert_eq!(r.status, 201, "{:?}", r.json);
    let token = r.json["invite_token"].as_str().unwrap().to_owned();

    // Wrong email → 403 invitation_email_mismatch.
    let r = app
        .send(json_post(
            "/api/v1/auth/register",
            &json!({
                "email": "stranger@x",
                "username": "stranger",
                "password": "correct horse battery staple",
                "invitation_token": token,
            }),
        ))
        .await;
    assert_eq!(r.status, 403);
    assert_eq!(r.json["type"], "invitation_email_mismatch");

    // Correct email → 201.
    let r = app
        .send(json_post(
            "/api/v1/auth/register",
            &json!({
                "email": "new@x",
                "username": "new",
                "password": "correct horse battery staple",
                "invitation_token": token,
            }),
        ))
        .await;
    assert_eq!(r.status, 201);
    assert_eq!(r.json["is_superadmin"], Value::Bool(false));

    // Token reuse → 410.
    let r = app
        .send(json_post(
            "/api/v1/auth/register",
            &json!({
                "email": "new2@x",
                "username": "new2",
                "password": "correct horse battery staple",
                "invitation_token": token,
            }),
        ))
        .await;
    assert_eq!(r.status, 410);
    assert_eq!(r.json["type"], "invitation_consumed");
}

#[tokio::test]
async fn invitation_with_superadmin_role_propagates() {
    let app = TestApp::spawn().await;
    set_open_registration(&app, true).await;
    let r = app
        .register("admin@x", "admin", "correct horse battery staple")
        .await;
    assert_eq!(r.status, 201);
    promote_to_superadmin(&app, "admin@x").await;
    set_open_registration(&app, false).await;
    let admin_token = app
        .login("admin@x", "correct horse battery staple")
        .await
        .access_token()
        .unwrap();

    let r = app
        .send(post_req(
            "/api/v1/admin/invitations",
            &admin_token,
            &json!({ "email": "co-admin@x", "role": "superadmin" }),
        ))
        .await;
    let token = r.json["invite_token"].as_str().unwrap().to_owned();

    let r = app
        .send(json_post(
            "/api/v1/auth/register",
            &json!({
                "email": "co-admin@x",
                "username": "coadmin",
                "password": "correct horse battery staple",
                "invitation_token": token,
            }),
        ))
        .await;
    assert_eq!(r.status, 201);
    assert_eq!(r.json["is_superadmin"], Value::Bool(true));
}

// ---------------------------------------------------------------------------
// admin endpoints: authz
// ---------------------------------------------------------------------------

#[tokio::test]
async fn non_admin_cannot_reach_admin_routes() {
    let app = TestApp::spawn().await;
    set_open_registration(&app, true).await;
    let token = register_and_login(&app, "joe@x", "joe").await;
    let r = app
        .send(get_with_bearer("/api/v1/admin/users", &token))
        .await;
    assert_eq!(r.status, 403);
}

#[tokio::test]
async fn unauthenticated_admin_routes_are_unauthorized() {
    let app = TestApp::spawn().await;
    let r = app.send(common::get("/api/v1/admin/users")).await;
    assert_eq!(r.status, 401);
}

// ---------------------------------------------------------------------------
// admin: users + last-admin guard
// ---------------------------------------------------------------------------

#[tokio::test]
async fn admin_create_user_sets_must_change_password() {
    let app = TestApp::spawn().await;
    set_open_registration(&app, true).await;
    let r = app
        .register("admin@x", "admin", "correct horse battery staple")
        .await;
    assert_eq!(r.status, 201);
    promote_to_superadmin(&app, "admin@x").await;
    set_open_registration(&app, false).await;
    let admin_token = app
        .login("admin@x", "correct horse battery staple")
        .await
        .access_token()
        .unwrap();

    // No password supplied → server-generated, returned once.
    let r = app
        .send(post_req(
            "/api/v1/admin/users",
            &admin_token,
            &json!({
                "email": "alice@x",
                "username": "alice",
                "full_name": "Alice",
            }),
        ))
        .await;
    assert_eq!(r.status, 201, "{:?}", r.json);
    let generated = r.json["generated_password"].as_str().unwrap();
    assert_eq!(generated.len(), 24);
    assert_eq!(r.json["user"]["must_change_password"], Value::Bool(true));

    // New user can login with the temp password.
    let l = app.login("alice@x", generated).await;
    assert_eq!(l.status, 200);

    // /me reflects must_change_password=true.
    let me = app
        .send(get_with_bearer("/api/v1/me", &l.access_token().unwrap()))
        .await;
    assert_eq!(me.status, 200);
    assert_eq!(me.json["must_change_password"], Value::Bool(true));
}

#[tokio::test]
async fn last_superadmin_cannot_be_demoted() {
    let app = TestApp::spawn().await;
    set_open_registration(&app, true).await;
    let r = app
        .register("admin@x", "admin", "correct horse battery staple")
        .await;
    assert_eq!(r.status, 201);
    promote_to_superadmin(&app, "admin@x").await;
    let admin_token = app
        .login("admin@x", "correct horse battery staple")
        .await
        .access_token()
        .unwrap();

    // Get my own id.
    let me = app.send(get_with_bearer("/api/v1/me", &admin_token)).await;
    let my_id = me.json["id"].as_str().unwrap().to_owned();

    let r = app
        .send(patch_req(
            &format!("/api/v1/admin/users/{my_id}"),
            &admin_token,
            &json!({ "is_superadmin": false }),
        ))
        .await;
    assert_eq!(r.status, 409);
    assert_eq!(r.json["type"], "last_superadmin");
}

#[tokio::test]
async fn last_superadmin_cannot_be_deleted() {
    let app = TestApp::spawn().await;
    set_open_registration(&app, true).await;
    let r = app
        .register("admin@x", "admin", "correct horse battery staple")
        .await;
    assert_eq!(r.status, 201);
    promote_to_superadmin(&app, "admin@x").await;
    let admin_token = app
        .login("admin@x", "correct horse battery staple")
        .await
        .access_token()
        .unwrap();

    let me = app.send(get_with_bearer("/api/v1/me", &admin_token)).await;
    let my_id = me.json["id"].as_str().unwrap().to_owned();

    let r = app
        .send(delete_req(
            &format!("/api/v1/admin/users/{my_id}"),
            &admin_token,
        ))
        .await;
    assert_eq!(r.status, 409);
    assert_eq!(r.json["type"], "last_superadmin");
}

#[tokio::test]
async fn second_admin_can_demote_first() {
    let app = TestApp::spawn().await;
    set_open_registration(&app, true).await;
    let r1 = app
        .register("admin1@x", "admin1", "correct horse battery staple")
        .await;
    assert_eq!(r1.status, 201);
    promote_to_superadmin(&app, "admin1@x").await;
    let r2 = app
        .register("admin2@x", "admin2", "correct horse battery staple")
        .await;
    assert_eq!(r2.status, 201);
    promote_to_superadmin(&app, "admin2@x").await;
    let t1 = app
        .login("admin1@x", "correct horse battery staple")
        .await
        .access_token()
        .unwrap();
    let t2 = app
        .login("admin2@x", "correct horse battery staple")
        .await
        .access_token()
        .unwrap();

    // admin1 finds admin2's id by listing users
    let list = app
        .send(get_with_bearer("/api/v1/admin/users?limit=200", &t1))
        .await;
    assert_eq!(list.status, 200);
    let id2 = list.json["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|u| u["email"] == "admin2@x")
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();

    // admin1 demotes admin2 (still leaves admin1) — should succeed.
    let r = app
        .send(patch_req(
            &format!("/api/v1/admin/users/{id2}"),
            &t1,
            &json!({ "is_superadmin": false }),
        ))
        .await;
    assert_eq!(r.status, 200);
    assert_eq!(r.json["is_superadmin"], Value::Bool(false));

    // admin2's admin routes now 403.
    let r = app.send(get_with_bearer("/api/v1/admin/users", &t2)).await;
    assert_eq!(r.status, 403);
}

// ---------------------------------------------------------------------------
// admin: settings + invitations list/revoke
// ---------------------------------------------------------------------------

#[tokio::test]
async fn settings_get_and_patch_round_trip() {
    let app = TestApp::spawn().await;
    set_open_registration(&app, true).await;
    let r = app
        .register("admin@x", "admin", "correct horse battery staple")
        .await;
    assert_eq!(r.status, 201);
    promote_to_superadmin(&app, "admin@x").await;
    let admin_token = app
        .login("admin@x", "correct horse battery staple")
        .await
        .access_token()
        .unwrap();

    let g = app
        .send(get_with_bearer("/api/v1/admin/settings", &admin_token))
        .await;
    assert_eq!(g.status, 200);
    assert_eq!(g.json["open_registration"], Value::Bool(true));

    let p = app
        .send(patch_req(
            "/api/v1/admin/settings",
            &admin_token,
            &json!({ "open_registration": false }),
        ))
        .await;
    assert_eq!(p.status, 200);
    assert_eq!(p.json["open_registration"], Value::Bool(false));

    // Anonymous register is now closed.
    let r = app
        .register("bob@x", "bob", "correct horse battery staple")
        .await;
    assert_eq!(r.status, 403);
}

#[tokio::test]
async fn revoke_invitation_blocks_reuse() {
    let app = TestApp::spawn().await;
    set_open_registration(&app, true).await;
    let r = app
        .register("admin@x", "admin", "correct horse battery staple")
        .await;
    assert_eq!(r.status, 201);
    promote_to_superadmin(&app, "admin@x").await;
    set_open_registration(&app, false).await;
    let admin_token = app
        .login("admin@x", "correct horse battery staple")
        .await
        .access_token()
        .unwrap();

    let r = app
        .send(post_req(
            "/api/v1/admin/invitations",
            &admin_token,
            &json!({ "email": "invitee@x", "role": "user" }),
        ))
        .await;
    let inv_id = r.json["invitation_id"].as_str().unwrap().to_owned();
    let token = r.json["invite_token"].as_str().unwrap().to_owned();

    // Revoke.
    let r = app
        .send(delete_req(
            &format!("/api/v1/admin/invitations/{inv_id}"),
            &admin_token,
        ))
        .await;
    assert_eq!(r.status, 204);

    // Token now 410.
    let r = app
        .send(json_post(
            "/api/v1/auth/register",
            &json!({
                "email": "invitee@x",
                "username": "invitee",
                "password": "correct horse battery staple",
                "invitation_token": token,
            }),
        ))
        .await;
    assert_eq!(r.status, 410);
}

#[tokio::test]
async fn reset_password_returns_token_in_dev() {
    let app = TestApp::spawn().await;
    set_open_registration(&app, true).await;
    let r = app
        .register("admin@x", "admin", "correct horse battery staple")
        .await;
    assert_eq!(r.status, 201);
    promote_to_superadmin(&app, "admin@x").await;
    let admin_token = app
        .login("admin@x", "correct horse battery staple")
        .await
        .access_token()
        .unwrap();
    let ru = app
        .register("user@x", "user", "correct horse battery staple")
        .await;
    assert_eq!(ru.status, 201);

    let list = app
        .send(get_with_bearer(
            "/api/v1/admin/users?limit=200",
            &admin_token,
        ))
        .await;
    let uid = list.json["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|u| u["email"] == "user@x")
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();

    let r = app
        .send(post_no_body(
            &format!("/api/v1/admin/users/{uid}/reset-password"),
            &admin_token,
        ))
        .await;
    assert_eq!(r.status, 201);
    // Dev mailer is NoopMailer → reset_token surfaced.
    assert!(r.json["reset_token"].as_str().is_some());
}
