//! Phase 39 — a superadmin reads every project and manages its members, but
//! otherwise writes only as a member.
//!
//! Covers:
//!   * Non-member superadmin: every read works, every write outside member
//!     management is 403.
//!   * Non-member superadmin manages members: add, invite, change role,
//!     remove; the last-admin guard still holds.
//!   * `POST /projects/{id}/join`: superadmin adds himself with a chosen role;
//!     refused for non-superadmins, members, and unknown roles.
//!   * Superadmin member with a limited role: role decides writes, reads stay
//!     unrestricted.
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

use common::{TestApp, get_with_bearer, patch_json_bearer, post_json_bearer};
use serde_json::json;

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

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

async fn register_and_login(app: &TestApp, email: &str, username: &str) -> String {
    let r = app
        .register(email, username, "correct horse battery staple")
        .await;
    assert_eq!(r.status, 201, "register: {:?}", r.json);
    let l = app.login(email, "correct horse battery staple").await;
    assert_eq!(l.status, 200, "login: {:?}", l.json);
    l.access_token().expect("access token")
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

async fn user_id(app: &TestApp, token: &str) -> String {
    let r = app.send(get_with_bearer("/api/v1/me", token)).await;
    assert_eq!(r.status, 200, "{:?}", r.json);
    r.json["id"].as_str().unwrap().to_owned()
}

/// Owner, an outsider who is promoted to superadmin, and the owner's private
/// project.
async fn setup(app: &TestApp) -> (String, String, String) {
    let owner = register_and_login(app, "owner@example.com", "owner").await;
    let pid = create_project(app, &owner, "Alpha", "private").await;
    let sa = register_and_login(app, "sa@example.com", "superadmin").await;
    promote_to_superadmin(app, "sa@example.com").await;
    (owner, sa, pid)
}

// ---------------------------------------------------------------------------
// non-member superadmin
// ---------------------------------------------------------------------------

#[tokio::test]
async fn non_member_superadmin_reads_but_cannot_write_outside_members() {
    require_db!();
    let app = TestApp::spawn().await;
    let (owner, sa, pid) = setup(&app).await;

    // Reads — including ones no default role below admin holds together.
    for path in [
        "",
        "/members",
        "/roles",
        "/issues",
        "/meetings?from=2026-01-01&to=2026-12-31",
    ] {
        let r = app
            .send(get_with_bearer(
                &format!("/api/v1/projects/{pid}{path}"),
                &sa,
            ))
            .await;
        assert_eq!(r.status, 200, "GET {path}: {:?}", r.json);
    }

    // Writes.
    let r = app
        .send(patch_json_bearer(
            &format!("/api/v1/projects/{pid}"),
            &sa,
            &json!({ "name": "Hijacked" }),
        ))
        .await;
    assert_eq!(r.status, 403, "modify project: {:?}", r.json);

    let r = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/issues"),
            &sa,
            &json!({ "subject": "Not allowed" }),
        ))
        .await;
    assert_eq!(r.status, 403, "create issue: {:?}", r.json);

    let r = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/roles"),
            &sa,
            &json!({ "slug": "extra", "name": "Extra", "permissions": [] }),
        ))
        .await;
    assert_eq!(r.status, 403, "create role: {:?}", r.json);

    let r = app
        .send(common::delete_bearer(
            &format!("/api/v1/projects/{pid}"),
            &sa,
        ))
        .await;
    assert_eq!(r.status, 403, "delete project: {:?}", r.json);

    // The owner still sees an untouched project.
    let r = app
        .send(get_with_bearer(&format!("/api/v1/projects/{pid}"), &owner))
        .await;
    assert_eq!(r.json["name"], "Alpha");
}

// ---------------------------------------------------------------------------
// member management without membership
// ---------------------------------------------------------------------------

#[tokio::test]
async fn non_member_superadmin_manages_members() {
    require_db!();
    let app = TestApp::spawn().await;
    let (owner, sa, pid) = setup(&app).await;
    let alice = register_and_login(&app, "alice@example.com", "alice").await;
    let alice_id = user_id(&app, &alice).await;
    let owner_id = user_id(&app, &owner).await;
    let members = format!("/api/v1/projects/{pid}/members");

    let r = app
        .send(post_json_bearer(
            &members,
            &sa,
            &json!({ "user_id": alice_id, "role": "dev" }),
        ))
        .await;
    assert_eq!(r.status, 201, "add member: {:?}", r.json);

    let r = app
        .send(patch_json_bearer(
            &format!("{members}/{alice_id}"),
            &sa,
            &json!({ "role": "product_owner" }),
        ))
        .await;
    assert_eq!(r.status, 204, "change role: {:?}", r.json);

    let r = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/invitations"),
            &sa,
            &json!({ "email": "bob@example.com", "role": "dev" }),
        ))
        .await;
    assert_eq!(r.status, 201, "invite: {:?}", r.json);

    // The owner is the only admin: neither demoted nor removed.
    let r = app
        .send(patch_json_bearer(
            &format!("{members}/{owner_id}"),
            &sa,
            &json!({ "role": "dev" }),
        ))
        .await;
    assert_eq!(r.status, 409, "demote last admin: {:?}", r.json);
    let r = app
        .send(common::delete_bearer(&format!("{members}/{owner_id}"), &sa))
        .await;
    assert_eq!(r.status, 409, "remove last admin: {:?}", r.json);

    let r = app
        .send(common::delete_bearer(&format!("{members}/{alice_id}"), &sa))
        .await;
    assert_eq!(r.status, 204, "remove member: {:?}", r.json);

    // Managing members did not make him one.
    let sa_id = user_id(&app, &sa).await;
    let r = app.send(get_with_bearer(&members, &owner)).await;
    assert!(
        r.json["members"]
            .as_array()
            .unwrap()
            .iter()
            .all(|m| m["user_id"] != sa_id.as_str()),
        "{:?}",
        r.json
    );
}

// ---------------------------------------------------------------------------
// join
// ---------------------------------------------------------------------------

#[tokio::test]
async fn superadmin_joins_with_chosen_role_and_can_then_write() {
    require_db!();
    let app = TestApp::spawn().await;
    let (_owner, sa, pid) = setup(&app).await;
    let join = format!("/api/v1/projects/{pid}/join");

    let r = app
        .send(post_json_bearer(&join, &sa, &json!({ "role": "nope" })))
        .await;
    assert_eq!(r.status, 422, "{:?}", r.json);
    assert_eq!(r.json["code"], "unknown_role");

    let r = app
        .send(post_json_bearer(&join, &sa, &json!({ "role": "admin" })))
        .await;
    assert_eq!(r.status, 201, "{:?}", r.json);
    assert_eq!(r.json["role"], "admin");

    let sa_id = user_id(&app, &sa).await;
    let r = app
        .send(get_with_bearer(
            &format!("/api/v1/projects/{pid}/members"),
            &sa,
        ))
        .await;
    let me = r.json["members"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["user_id"] == sa_id.as_str())
        .expect("superadmin listed as member");
    assert_eq!(me["role_slug"], "admin");

    let r = app
        .send(patch_json_bearer(
            &format!("/api/v1/projects/{pid}"),
            &sa,
            &json!({ "name": "Renamed" }),
        ))
        .await;
    assert_eq!(r.status, 200, "member admin modifies: {:?}", r.json);

    // A second join is a conflict.
    let r = app
        .send(post_json_bearer(&join, &sa, &json!({ "role": "dev" })))
        .await;
    assert_eq!(r.status, 409, "{:?}", r.json);
}

#[tokio::test]
async fn join_is_superadmin_only() {
    require_db!();
    let app = TestApp::spawn().await;
    let owner = register_and_login(&app, "owner@example.com", "owner").await;
    let private = create_project(&app, &owner, "Private", "private").await;
    let internal = create_project(&app, &owner, "Internal", "internal").await;
    let plain = register_and_login(&app, "plain@example.com", "plain").await;
    let body = json!({ "role": "admin" });

    // A private project stays hidden from an outsider.
    let r = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{private}/join"),
            &plain,
            &body,
        ))
        .await;
    assert_eq!(r.status, 404, "{:?}", r.json);

    // A visible one refuses him.
    let r = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{internal}/join"),
            &plain,
            &body,
        ))
        .await;
    assert_eq!(r.status, 403, "{:?}", r.json);

    // The owner — a member, not a superadmin — is refused as well.
    let r = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{internal}/join"),
            &owner,
            &body,
        ))
        .await;
    assert_eq!(r.status, 403, "{:?}", r.json);
}

// ---------------------------------------------------------------------------
// superadmin member with a limited role
// ---------------------------------------------------------------------------

#[tokio::test]
async fn superadmin_member_writes_by_role_and_reads_everything() {
    require_db!();
    let app = TestApp::spawn().await;
    let (_owner, sa, pid) = setup(&app).await;

    let r = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/join"),
            &sa,
            &json!({ "role": "stakeholder" }),
        ))
        .await;
    assert_eq!(r.status, 201, "{:?}", r.json);

    // Stakeholders hold no `meeting.view`; the superadmin still reads them.
    let r = app
        .send(get_with_bearer(
            &format!("/api/v1/projects/{pid}/meetings?from=2026-01-01&to=2026-12-31"),
            &sa,
        ))
        .await;
    assert_eq!(r.status, 200, "{:?}", r.json);

    // Writes follow the stakeholder role.
    let r = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/issues"),
            &sa,
            &json!({ "subject": "Stakeholders do not create issues" }),
        ))
        .await;
    assert_eq!(r.status, 403, "{:?}", r.json);
    let r = app
        .send(patch_json_bearer(
            &format!("/api/v1/projects/{pid}"),
            &sa,
            &json!({ "name": "Renamed" }),
        ))
        .await;
    assert_eq!(r.status, 403, "{:?}", r.json);
}
