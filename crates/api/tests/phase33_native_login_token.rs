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
//! Phase 33 acceptance: a cookie-less client can obtain a refresh token when it
//! signs in, not only when it rotates one.
//!
//! Phase 32 let desktop and mobile refresh and log out with the token in the
//! body, but every session-minting endpoint still returned it in the body only
//! when the server ran in development. Against a production server a native
//! client could sign in, receive a `Set-Cookie` it has no jar for, and end up
//! with nothing to persist — so multi-account switching stored no accounts at
//! all and its UI never appeared.
//!
//! Everything here runs against a PRODUCTION-env app on purpose: development
//! echoes the token unconditionally and would pass no matter what.

mod common;

use axum::body::Body;
use axum::http::Request;
use common::{TestApp, json_post};
use serde_json::json;

const STRONG_PW: &str = "7xK!pq2$mz9Wbe#aQ";
const REFRESH_IN_BODY: &str = "x-intellipilot-refresh-in-body";

fn login_req(email: &str, header: Option<&str>) -> Request<Body> {
    let base = json_post(
        "/api/v1/auth/login",
        &json!({ "email": email, "password": STRONG_PW }),
    );
    let Some(value) = header else { return base };
    let (mut parts, body) = base.into_parts();
    parts.headers.insert(
        axum::http::HeaderName::from_static(REFRESH_IN_BODY),
        axum::http::HeaderValue::from_str(value).unwrap(),
    );
    Request::from_parts(parts, body)
}

fn set_cookie_has_refresh(res: &common::TestResponse) -> bool {
    res.cookies.iter().any(|c| c.starts_with("refresh_token="))
}

#[tokio::test]
async fn a_browser_login_never_receives_the_token_in_the_body() {
    require_db!();
    let app = TestApp::spawn_in_production().await;
    let _ = app.register("web@example.com", "webuser", STRONG_PW).await;

    let res = app.send(login_req("web@example.com", None)).await;

    assert_eq!(res.status, 200, "{:?}", res.json);
    // The whole point of the HttpOnly cookie: JS must not be able to read it.
    assert!(
        res.json["refresh_token"].is_null(),
        "browser login must not echo the refresh token: {:?}",
        res.json
    );
    assert!(set_cookie_has_refresh(&res), "cookie must still be set");
}

#[tokio::test]
async fn a_native_login_that_asks_receives_the_token() {
    require_db!();
    let app = TestApp::spawn_in_production().await;
    let _ = app
        .register("native@example.com", "nativeuser", STRONG_PW)
        .await;

    let res = app.send(login_req("native@example.com", Some("1"))).await;

    assert_eq!(res.status, 200, "{:?}", res.json);
    assert!(
        res.json["refresh_token"]
            .as_str()
            .is_some_and(|t| !t.is_empty()),
        "a client that asked must be handed a token it can store: {:?}",
        res.json
    );
    // Set alongside, not instead: nothing about the browser's carrier changes.
    assert!(set_cookie_has_refresh(&res));
}

#[tokio::test]
async fn the_token_from_a_native_login_actually_works() {
    require_db!();
    let app = TestApp::spawn_in_production().await;
    let _ = app.register("e2e@example.com", "e2euser", STRONG_PW).await;

    let login = app.send(login_req("e2e@example.com", Some("1"))).await;
    let first = login.json["refresh_token"].as_str().unwrap().to_owned();

    // The desktop flow end to end: store the token from login, then rotate it
    // by body with no cookie jar anywhere in sight.
    let res = app
        .send(json_post(
            "/api/v1/auth/refresh",
            &json!({ "refresh_token": first }),
        ))
        .await;

    assert_eq!(res.status, 200, "{:?}", res.json);
    let second = res.json["refresh_token"].as_str().expect("rotated token");
    assert_ne!(second, first, "refresh token must rotate");
}

#[tokio::test]
async fn only_an_affirmative_header_counts() {
    require_db!();
    let app = TestApp::spawn_in_production().await;
    let _ = app.register("off@example.com", "offuser", STRONG_PW).await;

    // A header present but not asserting anything must not be read as consent.
    let res = app.send(login_req("off@example.com", Some("0"))).await;

    assert_eq!(res.status, 200, "{:?}", res.json);
    assert!(res.json["refresh_token"].is_null(), "{:?}", res.json);
}
