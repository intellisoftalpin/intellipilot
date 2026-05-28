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
//! Phase 2 acceptance: TOTP, recovery codes, MFA login flow, passkey endpoints.
//!
//! Needs a real Postgres (skips without INTELLIPILOT_TEST_DB_URL/DATABASE_URL).

mod common;

use common::{TestApp, delete_bearer, get_with_bearer, json_post, post_bearer, post_json_bearer};
use intellipilot_auth::totp;
use serde_json::json;

const STRONG_PW: &str = "7xK!pq2$mz9Wbe#aQ";

/// Enroll TOTP for a freshly-registered user; returns (access_token, secret_bytes,
/// recovery_codes).
async fn enroll_totp(app: &TestApp, email: &str, username: &str) -> (String, Vec<u8>, Vec<String>) {
    let _ = app.register(email, username, STRONG_PW).await;
    let token = app.login(email, STRONG_PW).await.access_token().unwrap();

    let start = app.send(post_bearer("/api/v1/me/totp/start", &token)).await;
    assert_eq!(start.status, 200, "totp start: {:?}", start.json);
    let b32 = start.json["secret_base32"].as_str().unwrap();
    let secret = totp::secret_from_base32(b32).expect("decode base32");

    let code = totp::current_code(&secret).unwrap();
    let confirm = app
        .send(post_json_bearer(
            "/api/v1/me/totp/confirm",
            &token,
            &json!({ "code": code }),
        ))
        .await;
    assert_eq!(confirm.status, 200, "totp confirm: {:?}", confirm.json);
    let codes: Vec<String> = confirm.json["recovery_codes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_owned())
        .collect();
    assert_eq!(codes.len(), 10);
    (token, secret, codes)
}

#[tokio::test]
async fn totp_enroll_then_login_requires_second_factor() {
    require_db!();
    let app = TestApp::spawn().await;
    let (_token, secret, _codes) = enroll_totp(&app, "totp@example.com", "totpuser").await;

    // Login now returns an MFA challenge instead of tokens.
    let login = app.login("totp@example.com", STRONG_PW).await;
    assert_eq!(login.status, 200);
    assert_eq!(login.json["mfa_required"], true);
    let mfa_token = login.json["mfa_token"].as_str().unwrap().to_owned();
    assert!(
        login.json.get("access_token").is_none(),
        "no session before 2FA"
    );

    // Complete with a current TOTP code.
    let code = totp::current_code(&secret).unwrap();
    let verify = app
        .send(json_post(
            "/api/v1/auth/2fa/verify",
            &json!({ "mfa_token": mfa_token, "method": "totp", "code": code }),
        ))
        .await;
    assert_eq!(verify.status, 200, "2fa verify: {:?}", verify.json);
    assert!(verify.access_token().is_some(), "session issued after 2FA");
}

#[tokio::test]
async fn totp_wrong_code_rejected() {
    require_db!();
    let app = TestApp::spawn().await;
    let _ = enroll_totp(&app, "totpw@example.com", "totpw").await;
    let mfa_token = app.login("totpw@example.com", STRONG_PW).await.json["mfa_token"]
        .as_str()
        .unwrap()
        .to_owned();
    let verify = app
        .send(json_post(
            "/api/v1/auth/2fa/verify",
            &json!({ "mfa_token": mfa_token, "method": "totp", "code": "000000" }),
        ))
        .await;
    assert_eq!(verify.status, 401);
}

#[tokio::test]
async fn recovery_code_is_single_use() {
    require_db!();
    let app = TestApp::spawn().await;
    let (_t, _s, codes) = enroll_totp(&app, "rec@example.com", "recuser").await;

    // Use the first recovery code to complete login.
    let mfa1 = app.login("rec@example.com", STRONG_PW).await.json["mfa_token"]
        .as_str()
        .unwrap()
        .to_owned();
    let v1 = app
        .send(json_post(
            "/api/v1/auth/2fa/verify",
            &json!({ "mfa_token": mfa1, "method": "recovery", "code": codes[0] }),
        ))
        .await;
    assert_eq!(v1.status, 200, "first recovery use: {:?}", v1.json);

    // Reusing the same code fails.
    let mfa2 = app.login("rec@example.com", STRONG_PW).await.json["mfa_token"]
        .as_str()
        .unwrap()
        .to_owned();
    let v2 = app
        .send(json_post(
            "/api/v1/auth/2fa/verify",
            &json!({ "mfa_token": mfa2, "method": "recovery", "code": codes[0] }),
        ))
        .await;
    assert_eq!(v2.status, 401, "reused recovery code must be rejected");

    // A different code still works.
    let mfa3 = app.login("rec@example.com", STRONG_PW).await.json["mfa_token"]
        .as_str()
        .unwrap()
        .to_owned();
    let v3 = app
        .send(json_post(
            "/api/v1/auth/2fa/verify",
            &json!({ "mfa_token": mfa3, "method": "recovery", "code": codes[1] }),
        ))
        .await;
    assert_eq!(v3.status, 200);
}

#[tokio::test]
async fn disabling_totp_removes_second_factor() {
    require_db!();
    let app = TestApp::spawn().await;
    let (token, _s, _c) = enroll_totp(&app, "dis@example.com", "disuser").await;

    let del = app.send(delete_bearer("/api/v1/me/totp", &token)).await;
    assert_eq!(del.status, 204);

    // Login no longer challenges for 2FA.
    let login = app.login("dis@example.com", STRONG_PW).await;
    assert_eq!(login.status, 200);
    assert!(login.access_token().is_some());
    assert!(login.json.get("mfa_required").is_none());
}

#[tokio::test]
async fn totp_start_requires_authentication() {
    require_db!();
    let app = TestApp::spawn().await;
    let resp = app
        .send(post_bearer("/api/v1/me/totp/start", "garbage"))
        .await;
    assert_eq!(resp.status, 401);
}

// --- passkeys (endpoint behaviour; full ceremony covered by webauthn-rs) ---

#[tokio::test]
async fn passkey_register_start_returns_options() {
    require_db!();
    let app = TestApp::spawn().await;
    let _ = app.register("pk@example.com", "pkuser", STRONG_PW).await;
    let token = app
        .login("pk@example.com", STRONG_PW)
        .await
        .access_token()
        .unwrap();

    let resp = app
        .send(post_bearer("/api/v1/me/passkeys/register/start", &token))
        .await;
    assert_eq!(resp.status, 200, "body: {:?}", resp.json);
    assert!(resp.json.get("state_id").is_some());
    assert!(resp.json["creation_options"]["publicKey"].is_object());
}

#[tokio::test]
async fn passkey_register_finish_rejects_garbage_credential() {
    require_db!();
    let app = TestApp::spawn().await;
    let _ = app.register("pk2@example.com", "pk2user", STRONG_PW).await;
    let token = app
        .login("pk2@example.com", STRONG_PW)
        .await
        .access_token()
        .unwrap();
    let start = app
        .send(post_bearer("/api/v1/me/passkeys/register/start", &token))
        .await;
    let state_id = start.json["state_id"].as_str().unwrap();

    let finish = app
        .send(post_json_bearer(
            "/api/v1/me/passkeys/register/finish",
            &token,
            &json!({ "state_id": state_id, "credential": { "bogus": true } }),
        ))
        .await;
    assert_eq!(finish.status, 400);
}

#[tokio::test]
async fn passkey_list_starts_empty() {
    require_db!();
    let app = TestApp::spawn().await;
    let _ = app.register("pk3@example.com", "pk3user", STRONG_PW).await;
    let token = app
        .login("pk3@example.com", STRONG_PW)
        .await
        .access_token()
        .unwrap();
    let resp = app
        .send(get_with_bearer("/api/v1/me/passkeys", &token))
        .await;
    assert_eq!(resp.status, 200);
    assert_eq!(resp.json["passkeys"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn passkey_authenticate_start_unknown_user_is_401() {
    require_db!();
    let app = TestApp::spawn().await;
    let resp = app
        .send(json_post(
            "/api/v1/auth/passkeys/authenticate/start",
            &json!({ "email": "nobody@example.com" }),
        ))
        .await;
    assert_eq!(resp.status, 401);
}
