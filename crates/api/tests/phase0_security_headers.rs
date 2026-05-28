#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_panics_doc
)]
//! Phase 0 acceptance: baseline security headers on every response.
//!
//! HSTS is left to the reverse proxy in non-TLS local tests; we assert
//! everything else the app sets itself.

use axum::body::Body;
use axum::http::Request;
use intellipilot_api::{AppState, build_router};
use intellipilot_testkit::init_tracing;
use tower::ServiceExt;

fn assert_header(headers: &axum::http::HeaderMap, name: &str, expected_contains: &str) {
    let value = headers
        .get(name)
        .unwrap_or_else(|| panic!("missing header {name}"))
        .to_str()
        .unwrap();
    assert!(
        value.contains(expected_contains),
        "header {name} = {value:?} does not contain {expected_contains:?}"
    );
}

#[tokio::test]
async fn baseline_security_headers_present() {
    init_tracing();
    let app = build_router(AppState::builder().build());

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/health/live")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let h = resp.headers();
    assert_header(h, "x-content-type-options", "nosniff");
    assert_header(h, "referrer-policy", "strict-origin-when-cross-origin");
    assert_header(h, "x-frame-options", "DENY");
    // CSP applies to API-served HTML (Swagger / Scalar pages); on JSON it
    // should still be safe to send a restrictive default.
    assert_header(h, "content-security-policy", "default-src");
    assert_header(h, "permissions-policy", "");
    // Cross-origin isolation primitives.
    assert_header(h, "cross-origin-opener-policy", "same-origin");
    assert_header(h, "cross-origin-resource-policy", "same-site");
}

#[tokio::test]
async fn server_header_is_stripped() {
    init_tracing();
    let app = build_router(AppState::builder().build());

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/health/live")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert!(
        resp.headers().get("server").is_none(),
        "Server header must not be exposed"
    );
    assert!(
        resp.headers().get("x-powered-by").is_none(),
        "X-Powered-By must not be exposed"
    );
}
