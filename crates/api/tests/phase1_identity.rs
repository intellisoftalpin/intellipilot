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
//! Phase 1 acceptance: identity & sessions.
//!
//! These tests need a real Postgres. They no-op (with a printed notice) when
//! neither INTELLIPILOT_TEST_DB_URL nor DATABASE_URL is set, so local runs
//! without a DB stay green; CI always provides one.

mod common;

use axum::body::Body;
use axum::http::Request;
use common::{TestApp, get, get_with_bearer, json_post, post_with_cookie};

const STRONG_PW: &str = "7xK!pq2$mz9Wbe#aQ";

#[tokio::test]
async fn register_returns_201_and_user() {
    require_db!();
    let app = TestApp::spawn().await;
    let resp = app.register("alice@example.com", "alice", STRONG_PW).await;
    assert_eq!(resp.status, 201, "body: {:?}", resp.json);
    assert_eq!(resp.json["email"], "alice@example.com");
    assert_eq!(resp.json["username"], "alice");
    assert!(
        resp.json.get("password_hash").is_none(),
        "must never expose hash"
    );
}

#[tokio::test]
async fn register_duplicate_email_returns_409() {
    require_db!();
    let app = TestApp::spawn().await;
    let _ = app.register("dup@example.com", "dup1", STRONG_PW).await;
    let second = app.register("dup@example.com", "dup2", STRONG_PW).await;
    assert_eq!(second.status, 409, "body: {:?}", second.json);
}

#[tokio::test]
async fn register_rejects_weak_password() {
    require_db!();
    let app = TestApp::spawn().await;
    let resp = app
        .register("weak@example.com", "weakuser", "password1234")
        .await;
    assert_eq!(resp.status, 422);
    assert_eq!(resp.json["code"], "weak_password");
}

#[tokio::test]
async fn register_rejects_invalid_email() {
    require_db!();
    let app = TestApp::spawn().await;
    let resp = app.register("not-an-email", "bob", STRONG_PW).await;
    assert_eq!(resp.status, 422);
    assert_eq!(resp.json["code"], "validation_failed");
}

#[tokio::test]
async fn login_succeeds_and_sets_refresh_cookie() {
    require_db!();
    let app = TestApp::spawn().await;
    let _ = app
        .register("login@example.com", "loginuser", STRONG_PW)
        .await;
    let resp = app.login("login@example.com", STRONG_PW).await;
    assert_eq!(resp.status, 200, "body: {:?}", resp.json);
    assert!(resp.access_token().is_some());
    assert_eq!(resp.json["token_type"], "Bearer");
    // Refresh cookie present with security attributes.
    let cookie = resp
        .cookies
        .iter()
        .find(|c| c.starts_with("refresh_token="));
    let cookie = cookie.expect("refresh cookie set");
    assert!(cookie.contains("HttpOnly"), "cookie: {cookie}");
    assert!(cookie.contains("SameSite=Strict"), "cookie: {cookie}");
    assert!(cookie.contains("Path=/api/v1/auth"), "cookie: {cookie}");
}

#[tokio::test]
async fn login_wrong_password_returns_401() {
    require_db!();
    let app = TestApp::spawn().await;
    let _ = app.register("wp@example.com", "wpuser", STRONG_PW).await;
    let resp = app.login("wp@example.com", "totally-wrong-password").await;
    assert_eq!(resp.status, 401);
    assert_eq!(resp.json["code"], "invalid_credentials");
}

#[tokio::test]
async fn login_unknown_user_returns_401_same_shape() {
    require_db!();
    let app = TestApp::spawn().await;
    let resp = app.login("ghost@example.com", STRONG_PW).await;
    assert_eq!(resp.status, 401);
    assert_eq!(resp.json["code"], "invalid_credentials");
}

#[tokio::test]
async fn me_requires_auth() {
    require_db!();
    let app = TestApp::spawn().await;
    let resp = app
        .send(get_with_bearer("/api/v1/me", "garbage-token"))
        .await;
    assert_eq!(resp.status, 401);
}

#[tokio::test]
async fn me_returns_current_user_with_valid_token() {
    require_db!();
    let app = TestApp::spawn().await;
    let _ = app.register("me@example.com", "meuser", STRONG_PW).await;
    let login = app.login("me@example.com", STRONG_PW).await;
    let token = login.access_token().unwrap();
    let resp = app.send(get_with_bearer("/api/v1/me", &token)).await;
    assert_eq!(resp.status, 200, "body: {:?}", resp.json);
    assert_eq!(resp.json["email"], "me@example.com");
}

#[tokio::test]
async fn refresh_rotates_token() {
    require_db!();
    let app = TestApp::spawn().await;
    let _ = app.register("ref@example.com", "refuser", STRONG_PW).await;
    let login = app.login("ref@example.com", STRONG_PW).await;
    let refresh1 = login.dev_refresh().expect("dev refresh in development env");

    let resp = app
        .send(post_with_cookie("/api/v1/auth/refresh", &refresh1))
        .await;
    assert_eq!(resp.status, 200, "body: {:?}", resp.json);
    let refresh2 = resp.dev_refresh().expect("rotated refresh");
    assert_ne!(refresh1, refresh2, "refresh token must rotate");
}

#[tokio::test]
async fn refresh_reuse_detected_revokes_family() {
    require_db!();
    let app = TestApp::spawn().await;
    let _ = app
        .register("reuse@example.com", "reuseuser", STRONG_PW)
        .await;
    let login = app.login("reuse@example.com", STRONG_PW).await;
    let refresh1 = login.dev_refresh().unwrap();

    // First rotation succeeds.
    let r2 = app
        .send(post_with_cookie("/api/v1/auth/refresh", &refresh1))
        .await;
    assert_eq!(r2.status, 200);
    let refresh2 = r2.dev_refresh().unwrap();

    // Replaying the OLD token is reuse → 401.
    let reuse = app
        .send(post_with_cookie("/api/v1/auth/refresh", &refresh1))
        .await;
    assert_eq!(reuse.status, 401, "reused token must be rejected");

    // And the whole family is now revoked: the previously-valid refresh2 fails.
    let after = app
        .send(post_with_cookie("/api/v1/auth/refresh", &refresh2))
        .await;
    assert_eq!(after.status, 401, "family must be revoked after reuse");
}

#[tokio::test]
async fn logout_revokes_session() {
    require_db!();
    let app = TestApp::spawn().await;
    let _ = app.register("out@example.com", "outuser", STRONG_PW).await;
    let login = app.login("out@example.com", STRONG_PW).await;
    let refresh = login.dev_refresh().unwrap();

    let logout = app
        .send(post_with_cookie("/api/v1/auth/logout", &refresh))
        .await;
    assert_eq!(logout.status, 204);

    // Refresh after logout must fail.
    let after = app
        .send(post_with_cookie("/api/v1/auth/refresh", &refresh))
        .await;
    assert_eq!(after.status, 401);
}

#[tokio::test]
async fn patch_me_updates_profile() {
    require_db!();
    let app = TestApp::spawn().await;
    let _ = app
        .register("patch@example.com", "patchuser", STRONG_PW)
        .await;
    let token = app
        .login("patch@example.com", STRONG_PW)
        .await
        .access_token()
        .unwrap();

    let req = Request::builder()
        .method("PATCH")
        .uri("/api/v1/me")
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_vec(&serde_json::json!({ "full_name": "Patched Name", "lang": "de" }))
                .unwrap(),
        ))
        .unwrap();
    let resp = app.send(req).await;
    assert_eq!(resp.status, 200, "body: {:?}", resp.json);
    assert_eq!(resp.json["full_name"], "Patched Name");
    assert_eq!(resp.json["lang"], "de");
}

#[tokio::test]
async fn gdpr_export_returns_user_data() {
    require_db!();
    let app = TestApp::spawn().await;
    let _ = app.register("exp@example.com", "expuser", STRONG_PW).await;
    let token = app
        .login("exp@example.com", STRONG_PW)
        .await
        .access_token()
        .unwrap();
    let resp = app.send(get_with_bearer("/api/v1/me/export", &token)).await;
    assert_eq!(resp.status, 200, "body: {:?}", resp.json);
    assert_eq!(resp.json["user"]["email"], "exp@example.com");
    assert!(resp.json["audit_events"].is_array());
}

#[tokio::test]
async fn gdpr_erase_soft_deletes_and_blocks_login() {
    require_db!();
    let app = TestApp::spawn().await;
    let _ = app
        .register("erase@example.com", "eraseuser", STRONG_PW)
        .await;
    let token = app
        .login("erase@example.com", STRONG_PW)
        .await
        .access_token()
        .unwrap();

    let del = app
        .send(
            Request::builder()
                .method("DELETE")
                .uri("/api/v1/me")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(del.status, 202, "body: {:?}", del.json);

    // Login should now fail (account inactive).
    let login = app.login("erase@example.com", STRONG_PW).await;
    assert_eq!(login.status, 401);
}

#[tokio::test]
async fn password_reset_flow_dev_token() {
    require_db!();
    let app = TestApp::spawn().await;
    let _ = app
        .register("reset@example.com", "resetuser", STRONG_PW)
        .await;

    // Request reset — dev mode surfaces the token in the response.
    let req = app
        .send(json_post(
            "/api/v1/auth/password/reset/request",
            &serde_json::json!({ "email": "reset@example.com" }),
        ))
        .await;
    assert_eq!(req.status, 200);
    let reset_token = req.json["reset_token"]
        .as_str()
        .expect("dev reset token")
        .to_owned();

    // Confirm with a new strong password.
    let new_pw = "Zq9@wk2Lm!ppXr";
    let confirm = app
        .send(json_post(
            "/api/v1/auth/password/reset/confirm",
            &serde_json::json!({ "token": reset_token, "new_password": new_pw }),
        ))
        .await;
    assert_eq!(confirm.status, 204, "body: {:?}", confirm.json);

    // Old password no longer works; new one does.
    assert_eq!(app.login("reset@example.com", STRONG_PW).await.status, 401);
    assert_eq!(app.login("reset@example.com", new_pw).await.status, 200);
}

#[tokio::test]
async fn unknown_email_reset_still_returns_200_without_token() {
    require_db!();
    let app = TestApp::spawn().await;
    let resp = app
        .send(json_post(
            "/api/v1/auth/password/reset/request",
            &serde_json::json!({ "email": "nobody@example.com" }),
        ))
        .await;
    assert_eq!(resp.status, 200, "anti-enumeration: always 200");
    assert!(resp.json.get("reset_token").is_none() || resp.json["reset_token"].is_null());
}

#[tokio::test]
async fn rate_limit_returns_429_with_retry_after() {
    require_db!();
    let app = TestApp::spawn().await;
    // Unauthenticated budget is 60/min; the 61st request is throttled.
    let mut statuses = Vec::new();
    for _ in 0..61 {
        statuses.push(app.send(get("/api/v1/me")).await.status);
    }
    assert_eq!(statuses[0], 401, "unauth /me is 401 before the limit");
    assert_eq!(
        *statuses.last().unwrap(),
        429,
        "61st request must be throttled"
    );

    // 429 must carry Retry-After.
    let resp = app.send(get("/api/v1/me")).await;
    assert_eq!(resp.status, 429);
    assert!(
        resp.retry_after.is_some(),
        "429 must include Retry-After header"
    );
}

#[tokio::test]
async fn audit_log_records_register_and_login() {
    require_db!();
    let app = TestApp::spawn().await;
    let _ = app
        .register("audit@example.com", "audituser", STRONG_PW)
        .await;
    let _ = app.login("audit@example.com", STRONG_PW).await;

    let client = app.db.pool.get().await.unwrap();
    let register_count: i64 = client
        .query_one(
            "SELECT count(*) AS n FROM audit_log WHERE action = 'register'",
            &[],
        )
        .await
        .unwrap()
        .get("n");
    let login_count: i64 = client
        .query_one(
            "SELECT count(*) AS n FROM audit_log WHERE action = 'login_success'",
            &[],
        )
        .await
        .unwrap()
        .get("n");
    assert_eq!(register_count, 1);
    assert_eq!(login_count, 1);
}
