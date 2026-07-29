//! Phase 27 — admin-driven account recovery and enforcement (V018).
//!
//! The defects this covers:
//!   * A user who lost every second factor could not be recovered by anyone.
//!     `has_active_2fa` counts TOTP **and** passkeys, so a reset that cleared
//!     only TOTP would leave a passkey-only user just as locked out.
//!   * `is_active` could not express a ban for a directory account:
//!     `find_or_link_ldap_user` sets `is_active = true` on every LDAP login,
//!     silently undoing a deactivation. `ban_survives_an_ldap_relink` pins
//!     that down.
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

use common::{
    TestApp, delete_bearer, get_with_bearer, post_bearer, post_json_bearer, post_with_cookie,
};
use intellipilot_db::{audit, users};
use serde_json::{Value, json};
use uuid::Uuid;

const PW: &str = "correct horse battery staple";

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
    let r = app.register(email, username, PW).await;
    assert_eq!(r.status, 201, "register: {:?}", r.json);
    let l = app.login(email, PW).await;
    assert_eq!(l.status, 200, "login: {:?}", l.json);
    l.access_token().expect("access token")
}

async fn user_id_for(app: &TestApp, email: &str) -> Uuid {
    let client = app.db.pool.get().await.unwrap();
    let row = client
        .query_one(
            "SELECT id FROM users WHERE email = $1",
            &[&email.trim().to_lowercase()],
        )
        .await
        .unwrap();
    row.get("id")
}

/// An admin plus an ordinary user, both logged in.
async fn admin_and_user(app: &TestApp) -> (String, String, Uuid) {
    let admin_token = register_and_login(app, "root@example.com", "root").await;
    promote_to_superadmin(app, "root@example.com").await;
    // Re-login so the token is issued after promotion.
    let admin_token2 = app
        .login("root@example.com", PW)
        .await
        .access_token()
        .unwrap_or(admin_token);

    let user_token = register_and_login(app, "bob@example.com", "bob").await;
    let user_id = user_id_for(app, "bob@example.com").await;
    (admin_token2, user_token, user_id)
}

/// Give the user every kind of second factor, so a reset has something to clear.
async fn enrol_all_factors(app: &TestApp, user_id: Uuid) {
    let mut client = app.db.pool.get().await.unwrap();
    users::set_totp_secret(&client, user_id, b"0123456789abcdef")
        .await
        .unwrap();
    users::confirm_totp(&client, user_id).await.unwrap();
    intellipilot_db::webauthn::insert_credential(
        &client,
        user_id,
        b"test-credential-id",
        &json!({"fake": "passkey"}),
        "Test key",
        0,
    )
    .await
    .unwrap();
    intellipilot_db::recovery::replace_all(
        &mut client,
        user_id,
        &[
            "hash-a".to_owned(),
            "hash-b".to_owned(),
            "hash-c".to_owned(),
        ],
    )
    .await
    .unwrap();
}

async fn is_banned(app: &TestApp, user_id: Uuid) -> bool {
    let client = app.db.pool.get().await.unwrap();
    users::is_banned(&client, user_id).await.unwrap()
}

// ---------------------------------------------------------------------------
// 2FA recovery
// ---------------------------------------------------------------------------

#[tokio::test]
async fn admin_reset_clears_every_second_factor() {
    require_db!();
    let app = TestApp::spawn().await;
    let (admin, _user, user_id) = admin_and_user(&app).await;
    enrol_all_factors(&app, user_id).await;

    // Precondition: the user is challenged for 2FA on login.
    let challenged = app.login("bob@example.com", PW).await;
    assert_eq!(challenged.json["mfa_required"], true, "setup sanity check");

    let r = app
        .send(post_bearer(
            &format!("/api/v1/admin/users/{user_id}/reset-2fa"),
            &admin,
        ))
        .await;
    assert_eq!(r.status, 200, "reset: {:?}", r.json);
    assert_eq!(r.json["totp_cleared"], true);
    assert_eq!(
        r.json["passkeys_removed"], 1,
        "a lost passkey locks a user out exactly like a lost authenticator"
    );
    assert_eq!(r.json["recovery_codes_removed"], 3);

    // The whole point: the user can now get back in with just a password.
    let after = app.login("bob@example.com", PW).await;
    assert_eq!(after.status, 200, "login after reset: {:?}", after.json);
    assert!(
        after.json.get("mfa_required").is_none(),
        "no factor should remain to challenge with"
    );
    assert!(after.access_token().is_some());

    let client = app.db.pool.get().await.unwrap();
    assert!(
        !users::has_active_2fa(&client, user_id).await.unwrap(),
        "no second factor may survive the reset"
    );
    assert_eq!(
        audit::count_for_action(&client, "admin_user_2fa_reset")
            .await
            .unwrap(),
        1,
        "the reset must be auditable"
    );
}

#[tokio::test]
async fn reset_on_an_account_without_factors_is_harmless() {
    require_db!();
    let app = TestApp::spawn().await;
    let (admin, _user, user_id) = admin_and_user(&app).await;

    let r = app
        .send(post_bearer(
            &format!("/api/v1/admin/users/{user_id}/reset-2fa"),
            &admin,
        ))
        .await;
    assert_eq!(r.status, 200, "reset: {:?}", r.json);
    assert_eq!(r.json["totp_cleared"], false);
    assert_eq!(r.json["passkeys_removed"], 0);
    assert_eq!(r.json["recovery_codes_removed"], 0);
}

#[tokio::test]
async fn reset_two_factor_is_superadmin_only() {
    require_db!();
    let app = TestApp::spawn().await;
    let (_admin, user, user_id) = admin_and_user(&app).await;

    // An ordinary user must not be able to strip anyone's 2FA — least of all
    // their own way around a challenge.
    let r = app
        .send(post_bearer(
            &format!("/api/v1/admin/users/{user_id}/reset-2fa"),
            &user,
        ))
        .await;
    assert_eq!(r.status, 403, "expected forbidden, got {:?}", r.json);
}

#[tokio::test]
async fn reset_two_factor_on_unknown_user_is_404() {
    require_db!();
    let app = TestApp::spawn().await;
    let (admin, _user, _id) = admin_and_user(&app).await;

    let missing = Uuid::now_v7();
    let r = app
        .send(post_bearer(
            &format!("/api/v1/admin/users/{missing}/reset-2fa"),
            &admin,
        ))
        .await;
    assert_eq!(r.status, 404, "{:?}", r.json);
}

// ---------------------------------------------------------------------------
// Bans
// ---------------------------------------------------------------------------

#[tokio::test]
async fn ban_blocks_login_with_a_distinct_reason() {
    require_db!();
    let app = TestApp::spawn().await;
    let (admin, _user, user_id) = admin_and_user(&app).await;

    let r = app
        .send(post_json_bearer(
            &format!("/api/v1/admin/users/{user_id}/ban"),
            &admin,
            &json!({ "reason": "policy violation" }),
        ))
        .await;
    assert_eq!(r.status, 200, "ban: {:?}", r.json);

    let denied = app.login("bob@example.com", PW).await;
    assert_eq!(denied.status, 403, "banned login: {:?}", denied.json);
    assert_eq!(
        denied.json["code"], "account_banned",
        "a ban is not a credential problem and should not read like one"
    );

    let client = app.db.pool.get().await.unwrap();
    assert_eq!(
        audit::count_for_action(&client, "admin_user_banned")
            .await
            .unwrap(),
        1
    );
}

#[tokio::test]
async fn ban_survives_an_ldap_relink() {
    require_db!();
    let app = TestApp::spawn().await;
    let (admin, _user, _id) = admin_and_user(&app).await;

    // An LDAP-provisioned account.
    let client = app.db.pool.get().await.unwrap();
    let ldap_user = users::find_or_link_ldap_user(
        &client,
        "alice@example.com",
        "alice",
        "Alice A",
        Some("CN=alice,DC=example,DC=com"),
        false,
    )
    .await
    .unwrap();
    drop(client);

    let r = app
        .send(post_json_bearer(
            &format!("/api/v1/admin/users/{}/ban", ldap_user.id),
            &admin,
            &json!({ "reason": "left the company" }),
        ))
        .await;
    assert_eq!(r.status, 200, "ban: {:?}", r.json);

    // Simulate the next directory login. This is the call that resets
    // `is_active = true` — the exact reason a ban cannot live in that column.
    let client = app.db.pool.get().await.unwrap();
    let relinked = users::find_or_link_ldap_user(
        &client,
        "alice@example.com",
        "alice",
        "Alice A",
        Some("CN=alice,DC=example,DC=com"),
        false,
    )
    .await
    .unwrap();
    assert_eq!(relinked.id, ldap_user.id);
    assert!(
        relinked.is_active,
        "the sync does re-enable is_active — this is why ban is a separate column"
    );
    assert!(
        users::is_banned(&client, ldap_user.id).await.unwrap(),
        "the ban must survive a directory re-sync"
    );
}

#[tokio::test]
async fn ban_revokes_sessions_and_stops_refresh() {
    require_db!();
    let app = TestApp::spawn().await;
    let admin = register_and_login(&app, "root@example.com", "root").await;
    promote_to_superadmin(&app, "root@example.com").await;
    let admin = app
        .login("root@example.com", PW)
        .await
        .access_token()
        .unwrap_or(admin);

    app.register("bob@example.com", "bob", PW).await;
    let login = app.login("bob@example.com", PW).await;
    let refresh = login.dev_refresh().expect("dev refresh token");
    let user_id = user_id_for(&app, "bob@example.com").await;

    // Refreshing works before the ban.
    let ok = app
        .send(post_with_cookie("/api/v1/auth/refresh", &refresh))
        .await;
    assert_eq!(ok.status, 200, "pre-ban refresh: {:?}", ok.json);
    let rotated = ok.dev_refresh().expect("rotated refresh token");

    let r = app
        .send(post_json_bearer(
            &format!("/api/v1/admin/users/{user_id}/ban"),
            &admin,
            &json!({}),
        ))
        .await;
    assert_eq!(r.status, 200, "ban: {:?}", r.json);

    // The open session must not survive: otherwise a ban only takes effect
    // once the user happens to stop refreshing.
    let denied = app
        .send(post_with_cookie("/api/v1/auth/refresh", &rotated))
        .await;
    assert_eq!(
        denied.status, 401,
        "a banned account must not extend its session: {:?}",
        denied.json
    );
}

#[tokio::test]
async fn banned_users_lose_an_already_issued_access_token() {
    require_db!();
    let app = TestApp::spawn().await;
    let (admin, user, user_id) = admin_and_user(&app).await;

    // The token works before the ban (and warms the presence cache).
    let before = app.send(get_with_bearer("/api/v1/me", &user)).await;
    assert_eq!(before.status, 200, "pre-ban: {:?}", before.json);

    let r = app
        .send(post_json_bearer(
            &format!("/api/v1/admin/users/{user_id}/ban"),
            &admin,
            &json!({}),
        ))
        .await;
    assert_eq!(r.status, 200, "ban: {:?}", r.json);

    // Access tokens are stateless with a 15-minute life; banning invalidates
    // the cached status so the very next request is refused rather than the
    // user working on for another quarter of an hour.
    let after = app.send(get_with_bearer("/api/v1/me", &user)).await;
    assert_eq!(
        after.status, 403,
        "a banned user must lose access promptly: {:?}",
        after.json
    );
}

#[tokio::test]
async fn an_admin_cannot_ban_themselves() {
    require_db!();
    let app = TestApp::spawn().await;
    let (admin, _user, _id) = admin_and_user(&app).await;
    let admin_id = user_id_for(&app, "root@example.com").await;

    let r = app
        .send(post_json_bearer(
            &format!("/api/v1/admin/users/{admin_id}/ban"),
            &admin,
            &json!({}),
        ))
        .await;
    assert_eq!(r.status, 400, "{:?}", r.json);
    assert_eq!(r.json["code"], "cannot_ban_self");
    assert!(!is_banned(&app, admin_id).await);
}

#[tokio::test]
async fn the_last_superadmin_cannot_be_banned() {
    require_db!();
    let app = TestApp::spawn().await;
    // Two superadmins. Banning one is fine — a usable admin remains. The
    // interesting part is what that does to the guard afterwards: the banned
    // one must stop counting as a survivor.
    let a = register_and_login(&app, "root@example.com", "root").await;
    promote_to_superadmin(&app, "root@example.com").await;
    let a = app
        .login("root@example.com", PW)
        .await
        .access_token()
        .unwrap_or(a);

    register_and_login(&app, "second@example.com", "second").await;
    promote_to_superadmin(&app, "second@example.com").await;
    let second_id = user_id_for(&app, "second@example.com").await;

    // Banning the second admin is allowed — one usable superadmin remains.
    let ok = app
        .send(post_json_bearer(
            &format!("/api/v1/admin/users/{second_id}/ban"),
            &a,
            &json!({}),
        ))
        .await;
    assert_eq!(ok.status, 200, "first ban: {:?}", ok.json);

    // A banned superadmin no longer counts as a survivor, so deactivating the
    // remaining one must now be refused.
    let root_id = user_id_for(&app, "root@example.com").await;
    let refused = app
        .send(common::patch_json_bearer(
            &format!("/api/v1/admin/users/{root_id}"),
            &a,
            &json!({ "is_active": false }),
        ))
        .await;
    assert_eq!(
        refused.status, 409,
        "a banned superadmin must not count towards the last-admin guard: {:?}",
        refused.json
    );
}

#[tokio::test]
async fn unban_restores_access() {
    require_db!();
    let app = TestApp::spawn().await;
    let (admin, _user, user_id) = admin_and_user(&app).await;

    app.send(post_json_bearer(
        &format!("/api/v1/admin/users/{user_id}/ban"),
        &admin,
        &json!({ "reason": "mistake" }),
    ))
    .await;
    assert!(is_banned(&app, user_id).await);

    let r = app
        .send(post_bearer(
            &format!("/api/v1/admin/users/{user_id}/unban"),
            &admin,
        ))
        .await;
    assert_eq!(r.status, 200, "unban: {:?}", r.json);
    assert!(!is_banned(&app, user_id).await);

    let back = app.login("bob@example.com", PW).await;
    assert_eq!(back.status, 200, "login after unban: {:?}", back.json);

    let client = app.db.pool.get().await.unwrap();
    assert_eq!(
        audit::count_for_action(&client, "admin_user_unbanned")
            .await
            .unwrap(),
        1
    );
}

#[tokio::test]
async fn ban_is_superadmin_only() {
    require_db!();
    let app = TestApp::spawn().await;
    let (_admin, user, user_id) = admin_and_user(&app).await;

    let r = app
        .send(post_json_bearer(
            &format!("/api/v1/admin/users/{user_id}/ban"),
            &user,
            &json!({}),
        ))
        .await;
    assert_eq!(r.status, 403, "{:?}", r.json);
}

#[tokio::test]
async fn a_banned_personal_token_stops_working() {
    require_db!();
    let app = TestApp::spawn().await;
    let (admin, _user, user_id) = admin_and_user(&app).await;

    // Mint a personal token straight into the store, then ban the owner.
    let raw = "ippt_testtokenvaluefortestingonly1234";
    let hash = intellipilot_auth::app_token::hash_token(raw);
    {
        let client = app.db.pool.get().await.unwrap();
        client
            .execute(
                "INSERT INTO personal_app_tokens (user_id, token_hash, prefix, last4) \
                 VALUES ($1, $2, 'ippt', '1234')",
                &[&user_id, &hash],
            )
            .await
            .unwrap();
    }

    let ok = app.send(get_with_bearer("/api/v1/me", raw)).await;
    assert_eq!(ok.status, 200, "token should work before the ban");

    app.send(post_json_bearer(
        &format!("/api/v1/admin/users/{user_id}/ban"),
        &admin,
        &json!({}),
    ))
    .await;

    let denied = app.send(get_with_bearer("/api/v1/me", raw)).await;
    assert_eq!(
        denied.status, 401,
        "a ban must reach every credential the user holds, not just passwords"
    );
}

// ---------------------------------------------------------------------------
// Sessions + the admin list
// ---------------------------------------------------------------------------

#[tokio::test]
async fn admin_sees_and_can_revoke_sessions() {
    require_db!();
    let app = TestApp::spawn().await;
    let (admin, _user, user_id) = admin_and_user(&app).await;
    // A second login is a second session.
    app.login("bob@example.com", PW).await;

    let listed = app
        .send(get_with_bearer(
            &format!("/api/v1/admin/users/{user_id}/sessions"),
            &admin,
        ))
        .await;
    assert_eq!(listed.status, 200, "{:?}", listed.json);
    let total = listed.json["total"].as_i64().unwrap();
    assert!(total >= 2, "expected at least two sessions, got {total}");

    let revoked = app
        .send(delete_bearer(
            &format!("/api/v1/admin/users/{user_id}/sessions"),
            &admin,
        ))
        .await;
    assert_eq!(revoked.status, 200, "{:?}", revoked.json);
    assert!(revoked.json["sessions_revoked"].as_u64().unwrap() >= 2);

    let after = app
        .send(get_with_bearer(
            &format!("/api/v1/admin/users/{user_id}/sessions"),
            &admin,
        ))
        .await;
    assert_eq!(after.json["total"], 0, "all sessions should be closed");
}

#[tokio::test]
async fn sessions_endpoints_are_superadmin_only() {
    require_db!();
    let app = TestApp::spawn().await;
    let (_admin, user, user_id) = admin_and_user(&app).await;

    let listed = app
        .send(get_with_bearer(
            &format!("/api/v1/admin/users/{user_id}/sessions"),
            &user,
        ))
        .await;
    assert_eq!(listed.status, 403, "{:?}", listed.json);
}

#[tokio::test]
async fn admin_list_reports_each_account_security_posture() {
    require_db!();
    let app = TestApp::spawn().await;
    let (admin, _user, user_id) = admin_and_user(&app).await;
    enrol_all_factors(&app, user_id).await;

    let r = app
        .send(get_with_bearer("/api/v1/admin/users?limit=50", &admin))
        .await;
    assert_eq!(r.status, 200, "{:?}", r.json);

    let bob = r.json["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|u| u["email"] == "bob@example.com")
        .expect("bob is listed")
        .clone();

    assert_eq!(bob["status"], "active");
    assert_eq!(bob["two_factor"]["enabled"], true);
    assert_eq!(bob["two_factor"]["totp"], true);
    assert_eq!(bob["two_factor"]["passkeys"], 1);
    assert_eq!(bob["two_factor"]["recovery_codes_left"], 3);
    assert_eq!(
        bob["active_sessions"], 1,
        "the user logged in exactly once during setup"
    );
    assert!(
        bob["last_login_at"].is_string(),
        "last login should be recorded: {bob:?}"
    );
    assert!(
        bob["last_seen_at"].is_string(),
        "last activity should be recorded: {bob:?}"
    );
    assert!(
        bob["last_session"]["user_agent"].is_string(),
        "the latest session should be summarised: {bob:?}"
    );
    // Geolocation is off by default, so no location may be reported.
    assert!(bob["last_session"]["country_code"].is_null());
    assert!(bob["last_session"]["city"].is_null());
}

#[tokio::test]
async fn admin_list_marks_banned_accounts() {
    require_db!();
    let app = TestApp::spawn().await;
    let (admin, _user, user_id) = admin_and_user(&app).await;

    app.send(post_json_bearer(
        &format!("/api/v1/admin/users/{user_id}/ban"),
        &admin,
        &json!({ "reason": "spam" }),
    ))
    .await;

    let r = app
        .send(get_with_bearer("/api/v1/admin/users?status=banned", &admin))
        .await;
    assert_eq!(r.status, 200, "{:?}", r.json);
    let items = r.json["items"].as_array().unwrap();
    assert_eq!(items.len(), 1, "only the banned user should match");
    assert_eq!(items[0]["email"], "bob@example.com");
    assert_eq!(items[0]["status"], "banned");
    assert_eq!(items[0]["ban_reason"], "spam");
    assert!(items[0]["banned_at"].is_string());
    assert_eq!(
        items[0]["active_sessions"], 0,
        "banning closes the user's sessions"
    );
}

#[tokio::test]
async fn admin_list_filters_accounts_without_two_factor() {
    require_db!();
    let app = TestApp::spawn().await;
    let (admin, _user, user_id) = admin_and_user(&app).await;
    enrol_all_factors(&app, user_id).await;

    let r = app
        .send(get_with_bearer("/api/v1/admin/users?status=no_2fa", &admin))
        .await;
    assert_eq!(r.status, 200, "{:?}", r.json);
    let emails: Vec<&str> = r.json["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|u| u["email"].as_str().unwrap())
        .collect();
    assert!(
        emails.contains(&"root@example.com"),
        "the admin has no second factor and should be listed: {emails:?}"
    );
    assert!(
        !emails.contains(&"bob@example.com"),
        "bob has TOTP and a passkey and must not be listed: {emails:?}"
    );
}

#[tokio::test]
async fn geoip_is_disabled_by_default_and_gated_to_superadmins() {
    require_db!();
    let app = TestApp::spawn().await;
    let (admin, user, _id) = admin_and_user(&app).await;

    let status = app
        .send(get_with_bearer("/api/v1/admin/geoip", &admin))
        .await;
    assert_eq!(status.status, 200, "{:?}", status.json);
    assert_eq!(
        status.json["enabled"], false,
        "IP geolocation must be opt-in"
    );
    assert_eq!(status.json["database_loaded"], false);
    assert!(
        status.json["attribution"]
            .as_str()
            .unwrap()
            .contains("DB-IP"),
        "the database licence requires attribution to be surfaced"
    );

    let denied = app
        .send(get_with_bearer("/api/v1/admin/geoip", &user))
        .await;
    assert_eq!(
        denied.status, 403,
        "only a superadmin may see or change geolocation settings"
    );
}

#[tokio::test]
async fn geoip_can_be_enabled_and_purged_by_a_superadmin() {
    require_db!();
    let app = TestApp::spawn().await;
    let (admin, _user, _id) = admin_and_user(&app).await;

    let updated = app
        .send(common::patch_json_bearer(
            "/api/v1/admin/geoip",
            &admin,
            &json!({ "enabled": true, "variant": "country" }),
        ))
        .await;
    assert_eq!(updated.status, 200, "{:?}", updated.json);
    assert_eq!(updated.json["enabled"], true);
    assert_eq!(updated.json["variant"], "country");

    let bad = app
        .send(common::patch_json_bearer(
            "/api/v1/admin/geoip",
            &admin,
            &json!({ "variant": "planet" }),
        ))
        .await;
    assert_eq!(bad.status, 422, "unknown variants must be rejected");

    // The purge exists because IP-derived city data is personal data: turning
    // the feature off has to be able to erase what was already collected.
    let purged = app
        .send(post_bearer("/api/v1/admin/geoip/purge", &admin))
        .await;
    assert_eq!(purged.status, 200, "{:?}", purged.json);
    assert!(purged.json["sessions_cleared"].is_number());

    // Only the accepted change is recorded — the rejected variant never
    // reached the settings table, so it must not appear in the audit trail.
    let client = app.db.pool.get().await.unwrap();
    assert_eq!(
        audit::count_for_action(&client, "admin_geoip_settings_updated")
            .await
            .unwrap(),
        1
    );
}

#[tokio::test]
async fn deactivation_and_ban_remain_distinct() {
    require_db!();
    let app = TestApp::spawn().await;
    let (admin, _user, user_id) = admin_and_user(&app).await;

    // Deactivate — the account is inactive but not banned.
    let deactivated = app
        .send(common::patch_json_bearer(
            &format!("/api/v1/admin/users/{user_id}"),
            &admin,
            &json!({ "is_active": false }),
        ))
        .await;
    assert_eq!(deactivated.status, 200, "{:?}", deactivated.json);
    assert!(!is_banned(&app, user_id).await, "deactivation is not a ban");

    let listed = app
        .send(get_with_bearer(
            "/api/v1/admin/users?status=inactive",
            &admin,
        ))
        .await;
    let items = listed.json["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["status"], "inactive");

    // Reactivating leaves ban state untouched, and vice versa.
    app.send(common::patch_json_bearer(
        &format!("/api/v1/admin/users/{user_id}"),
        &admin,
        &json!({ "is_active": true }),
    ))
    .await;
    app.send(post_json_bearer(
        &format!("/api/v1/admin/users/{user_id}/ban"),
        &admin,
        &json!({}),
    ))
    .await;

    let client = app.db.pool.get().await.unwrap();
    let row = client
        .query_one(
            "SELECT is_active, banned_at IS NOT NULL AS banned FROM users WHERE id = $1",
            &[&user_id],
        )
        .await
        .unwrap();
    assert!(
        row.get::<_, bool>("is_active"),
        "a ban must not silently flip is_active — they are separate concepts"
    );
    assert!(row.get::<_, bool>("banned"));
}

#[tokio::test]
async fn session_revocation_is_audited() {
    require_db!();
    let app = TestApp::spawn().await;
    let (admin, _user, user_id) = admin_and_user(&app).await;

    app.send(delete_bearer(
        &format!("/api/v1/admin/users/{user_id}/sessions"),
        &admin,
    ))
    .await;

    let client = app.db.pool.get().await.unwrap();
    assert_eq!(
        audit::count_for_action(&client, "admin_sessions_revoked")
            .await
            .unwrap(),
        1
    );
}

#[tokio::test]
async fn unknown_user_session_endpoints_are_404() {
    require_db!();
    let app = TestApp::spawn().await;
    let (admin, _user, _id) = admin_and_user(&app).await;
    let missing = Uuid::now_v7();

    let listed = app
        .send(get_with_bearer(
            &format!("/api/v1/admin/users/{missing}/sessions"),
            &admin,
        ))
        .await;
    assert_eq!(listed.status, 404, "{:?}", listed.json);

    let revoked = app
        .send(delete_bearer(
            &format!("/api/v1/admin/users/{missing}/sessions"),
            &admin,
        ))
        .await;
    assert_eq!(revoked.status, 404, "{:?}", revoked.json);

    let banned = app
        .send(post_json_bearer(
            &format!("/api/v1/admin/users/{missing}/ban"),
            &admin,
            &json!({}),
        ))
        .await;
    assert_eq!(banned.status, 404, "{:?}", banned.json);
}

/// Guards the shape the frontend reads. A silent rename here would leave the
/// admin list rendering blanks with nothing failing.
#[tokio::test]
async fn admin_row_shape_is_stable() {
    require_db!();
    let app = TestApp::spawn().await;
    let (admin, _user, _id) = admin_and_user(&app).await;

    let r = app
        .send(get_with_bearer("/api/v1/admin/users?limit=1", &admin))
        .await;
    let row: &Value = &r.json["items"][0];
    for key in [
        "id",
        "email",
        "username",
        "status",
        "two_factor",
        "active_sessions",
        "last_session",
        "last_seen_at",
        "last_login_at",
        "banned_at",
        "ban_reason",
    ] {
        assert!(
            row.get(key).is_some(),
            "admin row is missing `{key}`: {row:?}"
        );
    }
    for key in ["enabled", "totp", "passkeys", "recovery_codes_left"] {
        assert!(
            row["two_factor"].get(key).is_some(),
            "two_factor is missing `{key}`"
        );
    }
}
