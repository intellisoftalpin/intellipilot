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
//! Phase 32 acceptance: refreshing and logging out with the token in the body.
//!
//! Desktop and mobile hold several accounts at once, so they cannot keep one
//! refresh cookie per account in a single jar. `/auth/refresh` and
//! `/auth/logout` therefore accept the token in an optional JSON body.
//!
//! The cookie is read FIRST in both. That is what guarantees the browser
//! client's behaviour is unchanged, and several tests below pin it.

mod common;

use axum::body::Body;
use axum::http::Request;
use common::{TestApp, json_post, post_with_cookie};
use serde_json::json;

const STRONG_PW: &str = "7xK!pq2$mz9Wbe#aQ";

/// Register + login, returning the refresh token the dev env echoes back.
async fn login(app: &TestApp, tag: &str) -> String {
    let email = format!("{tag}@example.com");
    let _ = app.register(&email, tag, STRONG_PW).await;
    let res = app.login(&email, STRONG_PW).await;
    res.dev_refresh().expect("refresh token in development env")
}

/// POST with the refresh token in the body and no cookie at all.
fn post_with_body(uri: &str, refresh: &str) -> Request<Body> {
    json_post(uri, &json!({ "refresh_token": refresh }))
}

#[tokio::test]
async fn refresh_by_body_rotates_and_returns_the_new_token() {
    require_db!();
    let app = TestApp::spawn().await;
    let first = login(&app, "bodyrefresh").await;

    let res = app
        .send(post_with_body("/api/v1/auth/refresh", &first))
        .await;
    assert_eq!(res.status, 200, "{:?}", res.json);

    // A body caller has no cookie jar, so it must be handed the rotated token
    // — the one it sent is now spent.
    let second = res.json["refresh_token"]
        .as_str()
        .expect("rotated token returned to a body caller");
    assert_ne!(second, first, "refresh token must rotate");
    assert!(res.json["access_token"].as_str().is_some());
}

#[tokio::test]
async fn refresh_by_cookie_still_works_unchanged() {
    require_db!();
    let app = TestApp::spawn().await;
    let first = login(&app, "cookierefresh").await;

    // The web client's path. Nothing about it may change.
    let res = app
        .send(post_with_cookie("/api/v1/auth/refresh", &first))
        .await;
    assert_eq!(res.status, 200, "{:?}", res.json);
    assert!(res.json["access_token"].as_str().is_some());
}

#[tokio::test]
async fn cookie_wins_when_both_are_present() {
    require_db!();
    let app = TestApp::spawn().await;
    let a = login(&app, "bothcookie").await;
    let b = login(&app, "bothbody").await;

    // Send A's cookie and B's body token together. Cookie-first ordering means
    // A is the session that rotates; B's token must remain untouched and
    // therefore still usable afterwards.
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/refresh")
        .header("cookie", format!("refresh_token={a}"))
        .header("content-type", "application/json")
        .body(Body::from(json!({ "refresh_token": b }).to_string()))
        .unwrap();
    let res = app.send(req).await;
    assert_eq!(res.status, 200, "{:?}", res.json);

    // B untouched: still spends successfully.
    let b_res = app.send(post_with_body("/api/v1/auth/refresh", &b)).await;
    assert_eq!(
        b_res.status, 200,
        "the body token must not have been consumed when a cookie was present"
    );
}

#[tokio::test]
async fn a_replayed_body_token_still_revokes_the_family() {
    require_db!();
    let app = TestApp::spawn().await;
    let first = login(&app, "bodyreplay").await;

    let ok = app
        .send(post_with_body("/api/v1/auth/refresh", &first))
        .await;
    assert_eq!(ok.status, 200);
    let second = ok.json["refresh_token"].as_str().unwrap().to_owned();

    // Reuse of a spent token is treated as a compromise, exactly as over the
    // cookie path: the whole family goes.
    let replay = app
        .send(post_with_body("/api/v1/auth/refresh", &first))
        .await;
    assert_eq!(replay.status, 401, "{:?}", replay.json);

    // And the rotated token is dead too, because the family was revoked.
    let after = app
        .send(post_with_body("/api/v1/auth/refresh", &second))
        .await;
    assert_eq!(
        after.status, 401,
        "family revocation must invalidate the rotated token as well"
    );
}

#[tokio::test]
async fn garbage_and_empty_body_tokens_are_rejected() {
    require_db!();
    let app = TestApp::spawn().await;
    let _ = login(&app, "bodygarbage").await;

    let bad = app
        .send(post_with_body("/api/v1/auth/refresh", "not-a-token"))
        .await;
    assert_eq!(bad.status, 401, "{:?}", bad.json);

    // An empty/whitespace token must be treated as absent, not as a lookup.
    let empty = app
        .send(post_with_body("/api/v1/auth/refresh", "   "))
        .await;
    assert_eq!(empty.status, 401, "{:?}", empty.json);

    // No cookie and no body at all.
    let none = app
        .send(json_post("/api/v1/auth/refresh", &json!({})))
        .await;
    assert_eq!(none.status, 401, "{:?}", none.json);
}

#[tokio::test]
async fn logout_by_body_revokes_the_session() {
    require_db!();
    let app = TestApp::spawn().await;
    let token = login(&app, "bodylogout").await;

    let out = app
        .send(post_with_body("/api/v1/auth/logout", &token))
        .await;
    assert_eq!(out.status, 204, "{:?}", out.json);

    // The token is dead afterwards.
    let after = app
        .send(post_with_body("/api/v1/auth/refresh", &token))
        .await;
    assert_eq!(after.status, 401, "{:?}", after.json);
}

#[tokio::test]
async fn one_account_logging_out_leaves_the_other_alive() {
    require_db!();
    let app = TestApp::spawn().await;
    // Two accounts held at once — the whole reason this endpoint shape exists.
    let a = login(&app, "twoaccta").await;
    let b = login(&app, "twoacctb").await;

    let out = app.send(post_with_body("/api/v1/auth/logout", &a)).await;
    assert_eq!(out.status, 204);

    let a_after = app.send(post_with_body("/api/v1/auth/refresh", &a)).await;
    assert_eq!(a_after.status, 401, "logged-out account must be dead");

    let b_after = app.send(post_with_body("/api/v1/auth/refresh", &b)).await;
    assert_eq!(
        b_after.status, 200,
        "the other account's session must survive"
    );
}
