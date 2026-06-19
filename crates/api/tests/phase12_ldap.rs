//! Phase 12 — LDAP / directory authentication (V002).
//!
//! Covers the parts testable without a live directory:
//!   * Routing: with LDAP on, a non-superadmin is sent to the directory
//!     (unreachable → 503), while a local superadmin still logs in locally.
//!   * Admin settings CRUD + superadmin gating + the test-connection endpoint.
//!   * JIT provisioning / linking + superadmin group sync (direct DB calls).
//!
//! The bind itself is exercised against a real AD via the in-app
//! "Test connection" button — it cannot run in CI.
#![cfg(test)]
#![allow(
    let_underscore_drop,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_panics_doc,
    clippy::too_many_lines
)]

mod common;

use common::{TestApp, get_with_bearer, req};
use intellipilot_db::users;
use serde_json::{Value, json};

const PW: &str = "correct horse battery staple";
// A port that should refuse connections immediately.
const DEAD_LDAP: &str = "ldap://127.0.0.1:14389";

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
    let r = app.register(email, username, PW).await;
    assert_eq!(r.status, 201, "register: {:?}", r.json);
    let l = app.login(email, PW).await;
    assert_eq!(l.status, 200, "login: {:?}", l.json);
    l.access_token().expect("access token")
}

async fn enable_ldap(app: &TestApp, server_url: &str) {
    let client = app.db.pool.get().await.unwrap();
    client
        .execute(
            "UPDATE ldap_settings SET enabled = true, server_url = $1, \
                 base_dn = 'dc=example,dc=com', connection_timeout_secs = 2 WHERE id = 1",
            &[&server_url],
        )
        .await
        .unwrap();
}

fn settings_body(enabled: bool, server_url: &str) -> Value {
    json!({
        "enabled": enabled,
        "server_url": server_url,
        "use_start_tls": false,
        "skip_tls_verify": false,
        "base_dn": "dc=example,dc=com",
        "default_domain": "example.com",
        "bind_dn_format": "%s",
        "user_search_filter": "(sAMAccountName=%s)",
        "superadmin_group": "IntelliPilot Admins",
        "attr_email": "mail",
        "attr_display_name": "displayName",
        "attr_username": "sAMAccountName",
        "connection_timeout_secs": 2
    })
}

#[tokio::test]
async fn ldap_enabled_routes_non_superadmin_to_directory() {
    require_db!();
    let app = TestApp::spawn().await;
    // Works locally while LDAP is off.
    let _ = register_and_login(&app, "user@example.com", "user").await;

    enable_ldap(&app, DEAD_LDAP).await;

    // Now routed to the (unreachable) directory — the local password is ignored.
    let l = app.login("user@example.com", PW).await;
    assert_eq!(l.status, 503, "routed to LDAP: {:?}", l.json);
    assert_eq!(l.json["code"], "ldap_unavailable");
}

#[tokio::test]
async fn ldap_enabled_superadmin_still_local() {
    require_db!();
    let app = TestApp::spawn().await;
    let _ = register_and_login(&app, "admin@example.com", "admin").await;
    promote_to_superadmin(&app, "admin@example.com").await;
    enable_ldap(&app, DEAD_LDAP).await;

    // Correct password → local break-glass login succeeds.
    let ok = app.login("admin@example.com", PW).await;
    assert_eq!(ok.status, 200, "superadmin local login: {:?}", ok.json);

    // Wrong password → 401 from the local path (not 503 from LDAP).
    let bad = app.login("admin@example.com", "nope").await;
    assert_eq!(bad.status, 401, "{:?}", bad.json);
}

#[tokio::test]
async fn ldap_settings_crud_superadmin_only() {
    require_db!();
    let app = TestApp::spawn().await;
    let token = register_and_login(&app, "admin@example.com", "admin").await;

    // Non-superadmin is forbidden.
    let forbidden = app
        .send(get_with_bearer("/api/v1/admin/ldap-settings", &token))
        .await;
    assert_eq!(forbidden.status, 403);

    promote_to_superadmin(&app, "admin@example.com").await;

    let get1 = app
        .send(get_with_bearer("/api/v1/admin/ldap-settings", &token))
        .await;
    assert_eq!(get1.status, 200, "{:?}", get1.json);
    assert_eq!(get1.json["enabled"], false);

    let body = settings_body(true, "ldap://dc.example.com:389");
    let put = app
        .send(req(
            "PUT",
            "/api/v1/admin/ldap-settings",
            Some(&token),
            &[],
            Some(&body),
        ))
        .await;
    assert_eq!(put.status, 200, "{:?}", put.json);
    assert_eq!(put.json["enabled"], true);
    assert_eq!(put.json["superadmin_group"], "IntelliPilot Admins");

    let get2 = app
        .send(get_with_bearer("/api/v1/admin/ldap-settings", &token))
        .await;
    assert_eq!(get2.json["server_url"], "ldap://dc.example.com:389");
    assert_eq!(get2.json["base_dn"], "dc=example,dc=com");
}

#[tokio::test]
async fn ldap_test_endpoint_reports_connection_failure() {
    require_db!();
    let app = TestApp::spawn().await;
    let token = register_and_login(&app, "admin@example.com", "admin").await;
    promote_to_superadmin(&app, "admin@example.com").await;

    let body = json!({
        "settings": settings_body(true, DEAD_LDAP),
        "username": "someone@example.com",
        "password": "secret"
    });
    let r = app
        .send(req(
            "POST",
            "/api/v1/admin/ldap-settings/test",
            Some(&token),
            &[],
            Some(&body),
        ))
        .await;
    assert_eq!(r.status, 200, "{:?}", r.json);
    assert_eq!(r.json["ok"], false);
}

#[tokio::test]
async fn ldap_provisioning_and_superadmin_sync() {
    require_db!();
    let app = TestApp::spawn().await;
    let client = app.db.pool.get().await.unwrap();

    // First login provisions a new local account.
    let u1 = users::find_or_link_ldap_user(
        &client,
        "alice@example.com",
        "alice",
        "Alice A",
        Some("CN=alice,DC=example,DC=com"),
        false,
    )
    .await
    .unwrap();
    assert_eq!(u1.auth_source, "ldap");
    assert!(!u1.is_superadmin);

    // In the superadmin group on the next login → promoted (same row).
    let u2 =
        users::find_or_link_ldap_user(&client, "alice@example.com", "alice", "Alice A", None, true)
            .await
            .unwrap();
    assert_eq!(u2.id, u1.id);
    assert!(u2.is_superadmin);

    // Removed from the group → demoted on the following login.
    let u3 = users::find_or_link_ldap_user(
        &client,
        "alice@example.com",
        "alice",
        "Alice A",
        None,
        false,
    )
    .await
    .unwrap();
    assert_eq!(u3.id, u1.id);
    assert!(!u3.is_superadmin);

    // A different user whose username hint collides gets a suffixed username.
    let u4 = users::find_or_link_ldap_user(
        &client,
        "alice2@example.com",
        "alice",
        "Alice Two",
        None,
        false,
    )
    .await
    .unwrap();
    assert_ne!(u4.id, u1.id);
    assert_ne!(u4.username, u1.username);
}

/// LDAP settings are read-only for an LDAP-authenticated superadmin (so they
/// can't tamper or lock themselves out by disabling LDAP); a local superadmin
/// can change them.
#[tokio::test]
async fn ldap_authed_superadmin_cannot_change_ldap_settings() {
    require_db!();
    let app = TestApp::spawn().await;
    let token = register_and_login(&app, "ldapadmin@example.com", "ldapadmin").await;
    promote_to_superadmin(&app, "ldapadmin@example.com").await;

    // Enable LDAP first (still a local account → allowed).
    let enable = app
        .send(req(
            "PUT",
            "/api/v1/admin/ldap-settings",
            Some(&token),
            &[],
            Some(&settings_body(true, "ldap://dc.example.com:389")),
        ))
        .await;
    assert_eq!(enable.status, 200, "{:?}", enable.json);

    // Mark this superadmin as LDAP-sourced.
    let set_source = |src: &'static str| {
        let app = &app;
        async move {
            let client = app.db.pool.get().await.unwrap();
            client
                .execute(
                    "UPDATE users SET auth_source = $1 WHERE email = 'ldapadmin@example.com'",
                    &[&src],
                )
                .await
                .unwrap();
        }
    };
    set_source("ldap").await;

    // Disabling LDAP is now blocked for this LDAP-authed superadmin.
    let blocked = app
        .send(req(
            "PUT",
            "/api/v1/admin/ldap-settings",
            Some(&token),
            &[],
            Some(&settings_body(false, "ldap://dc.example.com:389")),
        ))
        .await;
    assert_eq!(blocked.status, 403, "{:?}", blocked.json);
    assert_eq!(blocked.json["code"], "ldap_readonly");

    // Back as a local superadmin → disabling is allowed.
    set_source("local").await;
    let ok = app
        .send(req(
            "PUT",
            "/api/v1/admin/ldap-settings",
            Some(&token),
            &[],
            Some(&settings_body(false, "ldap://dc.example.com:389")),
        ))
        .await;
    assert_eq!(ok.status, 200, "{:?}", ok.json);
    assert_eq!(ok.json["enabled"], false);
}
