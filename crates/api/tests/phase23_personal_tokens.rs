//! Phase 23 — personal app tokens (V015) + the cross-project work feed.
//!
//! Covers: one-time secret on create + masked reads; one-token-per-user (409);
//! the token authenticating as its owner on `/me` and project routes with
//! correct attribution; reset invalidating the old secret (and re-enabling);
//! disable/enable/delete lifecycle; garbage rejection; admin `ipat_` tokens
//! still barred from `/me`; and `/api/v1/me/issues` role filters (assignee /
//! reporter / reviewer / qa / mentioned) including the private-project guard
//! on mentions.
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

use common::{TestApp, delete_bearer, get_with_bearer, post_bearer, post_json_bearer};
use serde_json::{Value, json};

const PW: &str = "correct horse battery staple";

/// Register + login a user, returning their access token.
async fn user(app: &TestApp, email: &str, username: &str) -> String {
    let r = app.register(email, username, PW).await;
    assert_eq!(r.status, 201, "register: {:?}", r.json);
    app.login(email, PW).await.access_token().expect("token")
}

async fn user_id(app: &TestApp, access: &str) -> String {
    let me = app.send(get_with_bearer("/api/v1/me", access)).await;
    assert_eq!(me.status, 200, "{:?}", me.json);
    me.json["id"].as_str().unwrap().to_owned()
}

/// Mint the caller's personal token, returning the raw secret.
async fn mint(app: &TestApp, access: &str) -> String {
    let r = app.send(post_bearer("/api/v1/me/app-token", access)).await;
    assert_eq!(r.status, 201, "mint: {:?}", r.json);
    r.json["secret"].as_str().unwrap().to_owned()
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

async fn create_issue(app: &TestApp, token: &str, pid: &str, body: &Value) -> Value {
    let r = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/issues"),
            token,
            body,
        ))
        .await;
    assert_eq!(r.status, 201, "create issue: {:?}", r.json);
    r.json
}

/// Fetch `/api/v1/me/issues` for a role and return the subjects, newest first.
async fn my_issue_subjects(app: &TestApp, token: &str, role: &str) -> Vec<String> {
    let r = app
        .send(get_with_bearer(
            &format!("/api/v1/me/issues?role={role}"),
            token,
        ))
        .await;
    assert_eq!(r.status, 200, "me/issues {role}: {:?}", r.json);
    r.json["issues"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["subject"].as_str().unwrap().to_owned())
        .collect()
}

// ---------------------------------------------------------------------------

#[tokio::test]
async fn create_returns_secret_once_get_is_masked_and_second_create_conflicts() {
    require_db!();
    let app = TestApp::spawn().await;
    let access = user(&app, "pat1@x", "patone").await;

    // No token yet.
    let none = app
        .send(get_with_bearer("/api/v1/me/app-token", &access))
        .await;
    assert_eq!(none.status, 404);

    let r = app.send(post_bearer("/api/v1/me/app-token", &access)).await;
    assert_eq!(r.status, 201, "{:?}", r.json);
    let secret = r.json["secret"].as_str().unwrap();
    assert!(secret.starts_with("ippt_"), "secret prefix: {secret}");
    assert_eq!(r.json["token"]["last4"], secret[secret.len() - 4..]);
    assert!(r.json["token"]["disabled_at"].is_null());

    // Reads never expose the secret, only the masked hints.
    let got = app
        .send(get_with_bearer("/api/v1/me/app-token", &access))
        .await;
    assert_eq!(got.status, 200, "{:?}", got.json);
    assert!(got.json.get("secret").is_none(), "secret must not leak");
    assert!(got.json["prefix"].as_str().unwrap().starts_with("ippt_"));
    assert_eq!(got.json["last4"], secret[secret.len() - 4..]);

    // Only one token per user.
    let again = app.send(post_bearer("/api/v1/me/app-token", &access)).await;
    assert_eq!(again.status, 409, "{:?}", again.json);
}

#[tokio::test]
async fn personal_token_acts_as_its_owner() {
    require_db!();
    let app = TestApp::spawn().await;
    let access = user(&app, "pat2@x", "pattwo").await;
    let uid = user_id(&app, &access).await;
    let pid = create_project(&app, &access, "P", "private").await;
    let secret = mint(&app, &access).await;

    // /me works and resolves to the owner.
    let me = app.send(get_with_bearer("/api/v1/me", &secret)).await;
    assert_eq!(me.status, 200, "{:?}", me.json);
    assert_eq!(me.json["id"], uid.as_str());
    assert_eq!(me.json["username"], "pattwo");

    // Project routes work with the owner's permissions, and writes are
    // attributed to the owner (not INTELLIBOT).
    let issue = create_issue(&app, &secret, &pid, &json!({ "subject": "Via token" })).await;
    assert_eq!(issue["owner_id"], uid.as_str());

    // last_used_at is stamped.
    let got = app
        .send(get_with_bearer("/api/v1/me/app-token", &access))
        .await;
    assert!(!got.json["last_used_at"].is_null(), "{:?}", got.json);
}

#[tokio::test]
async fn reset_rotates_the_secret() {
    require_db!();
    let app = TestApp::spawn().await;
    let access = user(&app, "pat3@x", "patthree").await;
    let old = mint(&app, &access).await;

    let r = app
        .send(post_bearer("/api/v1/me/app-token/reset", &access))
        .await;
    assert_eq!(r.status, 200, "{:?}", r.json);
    let new = r.json["secret"].as_str().unwrap().to_owned();
    assert_ne!(old, new);

    let stale = app.send(get_with_bearer("/api/v1/me", &old)).await;
    assert_eq!(stale.status, 401, "old secret must die: {:?}", stale.json);
    let fresh = app.send(get_with_bearer("/api/v1/me", &new)).await;
    assert_eq!(fresh.status, 200, "{:?}", fresh.json);
}

#[tokio::test]
async fn disable_enable_delete_lifecycle() {
    require_db!();
    let app = TestApp::spawn().await;
    let access = user(&app, "pat4@x", "patfour").await;
    let secret = mint(&app, &access).await;

    // Disable → the bearer is rejected, but the token row survives.
    let d = app
        .send(post_bearer("/api/v1/me/app-token/disable", &access))
        .await;
    assert_eq!(d.status, 204);
    let rejected = app.send(get_with_bearer("/api/v1/me", &secret)).await;
    assert_eq!(rejected.status, 401);
    let got = app
        .send(get_with_bearer("/api/v1/me/app-token", &access))
        .await;
    assert!(!got.json["disabled_at"].is_null(), "{:?}", got.json);

    // Disable is idempotent.
    let d2 = app
        .send(post_bearer("/api/v1/me/app-token/disable", &access))
        .await;
    assert_eq!(d2.status, 204);

    // Enable → works again, same secret.
    let e = app
        .send(post_bearer("/api/v1/me/app-token/enable", &access))
        .await;
    assert_eq!(e.status, 204);
    let ok = app.send(get_with_bearer("/api/v1/me", &secret)).await;
    assert_eq!(ok.status, 200);

    // Delete → gone for good.
    let del = app
        .send(delete_bearer("/api/v1/me/app-token", &access))
        .await;
    assert_eq!(del.status, 204);
    let dead = app.send(get_with_bearer("/api/v1/me", &secret)).await;
    assert_eq!(dead.status, 401);
    let missing = app
        .send(get_with_bearer("/api/v1/me/app-token", &access))
        .await;
    assert_eq!(missing.status, 404);
    let del_again = app
        .send(delete_bearer("/api/v1/me/app-token", &access))
        .await;
    assert_eq!(del_again.status, 404);

    // A deleted token can be re-created.
    let again = app.send(post_bearer("/api/v1/me/app-token", &access)).await;
    assert_eq!(again.status, 201, "{:?}", again.json);
}

#[tokio::test]
async fn reset_reenables_a_disabled_token() {
    require_db!();
    let app = TestApp::spawn().await;
    let access = user(&app, "pat5@x", "patfive").await;
    let _ = mint(&app, &access).await;
    let d = app
        .send(post_bearer("/api/v1/me/app-token/disable", &access))
        .await;
    assert_eq!(d.status, 204);

    let r = app
        .send(post_bearer("/api/v1/me/app-token/reset", &access))
        .await;
    assert_eq!(r.status, 200, "{:?}", r.json);
    assert!(r.json["token"]["disabled_at"].is_null());
    let secret = r.json["secret"].as_str().unwrap();
    let ok = app.send(get_with_bearer("/api/v1/me", secret)).await;
    assert_eq!(ok.status, 200);
}

#[tokio::test]
async fn garbage_and_foreign_prefixes_are_rejected() {
    require_db!();
    let app = TestApp::spawn().await;
    let _ = user(&app, "pat6@x", "patsix").await;

    let garbage = app
        .send(get_with_bearer("/api/v1/me", "ippt_definitely-not-a-token"))
        .await;
    assert_eq!(garbage.status, 401);

    // Admin `ipat_` tokens are still barred from user-only endpoints — the
    // personal prefix must not have loosened that.
    let admin_shaped = app
        .send(get_with_bearer("/api/v1/me", "ipat_not-a-personal-token"))
        .await;
    assert_eq!(admin_shaped.status, 401);
}

// ---------------------------------------------------------------------------
// /api/v1/me/issues — the cross-project work feed
// ---------------------------------------------------------------------------

#[tokio::test]
async fn my_issues_filters_by_role() {
    require_db!();
    let app = TestApp::spawn().await;
    let alice = user(&app, "alice23@x", "alice23").await;
    let bob = user(&app, "bob23@x", "bob23").await;
    let bob_id = user_id(&app, &bob).await;
    // Internal visibility so text mentions of bob are visible to him even as
    // a non-member.
    let pid = create_project(&app, &alice, "Feed", "internal").await;

    let _ = create_issue(
        &app,
        &alice,
        &pid,
        &json!({ "subject": "Assigned to Bob", "assigned_to": bob_id }),
    )
    .await;
    let _ = create_issue(
        &app,
        &alice,
        &pid,
        &json!({ "subject": "Bob reviews", "reviewer_id": bob_id }),
    )
    .await;
    let _ = create_issue(
        &app,
        &alice,
        &pid,
        &json!({ "subject": "Bob tests", "qa_assignee_id": bob_id }),
    )
    .await;
    let _ = create_issue(
        &app,
        &alice,
        &pid,
        &json!({ "subject": "Mentions Bob", "description": "ping @bob23 please" }),
    )
    .await;
    let commented = create_issue(&app, &alice, &pid, &json!({ "subject": "Comment ping" })).await;
    let c = app
        .send(post_json_bearer(
            &format!(
                "/api/v1/projects/{pid}/issues/{}/comments",
                commented["id"].as_str().unwrap()
            ),
            &alice,
            &json!({ "body": "over to you @bob23" }),
        ))
        .await;
    assert_eq!(c.status, 201, "{:?}", c.json);

    // Bob's feed, via his personal token (the MCP path).
    let bob_token = mint(&app, &bob).await;
    assert_eq!(
        my_issue_subjects(&app, &bob_token, "assignee").await,
        vec!["Assigned to Bob"]
    );
    assert_eq!(
        my_issue_subjects(&app, &bob_token, "reviewer").await,
        vec!["Bob reviews"]
    );
    assert_eq!(
        my_issue_subjects(&app, &bob_token, "qa").await,
        vec!["Bob tests"]
    );
    let mentioned = my_issue_subjects(&app, &bob_token, "mentioned").await;
    assert_eq!(mentioned.len(), 2, "{mentioned:?}");
    assert!(mentioned.contains(&"Mentions Bob".to_owned()));
    assert!(mentioned.contains(&"Comment ping".to_owned()));
    assert_eq!(
        my_issue_subjects(&app, &bob_token, "reporter").await,
        Vec::<String>::new()
    );

    // Alice reported all five.
    assert_eq!(my_issue_subjects(&app, &alice, "reporter").await.len(), 5);

    // The feed carries the full display key (prefix-ref) and project context.
    let r = app
        .send(get_with_bearer(
            "/api/v1/me/issues?role=assignee",
            &bob_token,
        ))
        .await;
    let item = &r.json["issues"][0];
    let key = item["key"].as_str().unwrap();
    let reference = item["ref"].as_i64().unwrap();
    assert!(key.ends_with(&format!("-{reference}")), "key: {key}");
    assert_eq!(item["project_id"], pid.as_str());
    assert_eq!(r.json["total"], 1);
}

#[tokio::test]
async fn mentions_in_private_projects_stay_hidden_from_non_members() {
    require_db!();
    let app = TestApp::spawn().await;
    let alice = user(&app, "alice24@x", "alice24").await;
    let bob = user(&app, "bob24@x", "bob24").await;
    let pid = create_project(&app, &alice, "Secret", "private").await;
    let _ = create_issue(
        &app,
        &alice,
        &pid,
        &json!({ "subject": "Covert ping", "description": "cc @bob24" }),
    )
    .await;

    assert_eq!(
        my_issue_subjects(&app, &bob, "mentioned").await,
        Vec::<String>::new(),
        "private-project mention must not leak"
    );
    // The reporter herself (a member) sees it.
    assert_eq!(
        my_issue_subjects(&app, &alice, "mentioned").await,
        Vec::<String>::new(),
        "alice is not mentioned"
    );
    let alice_reported = my_issue_subjects(&app, &alice, "reporter").await;
    assert_eq!(alice_reported, vec!["Covert ping"]);
}
