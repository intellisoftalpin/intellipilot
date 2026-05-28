#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_panics_doc,
    clippy::type_complexity,
    clippy::needless_lifetimes,
    clippy::significant_drop_tightening
)]
//! Phase 0 acceptance: the request id MUST appear in tracing context for
//! every request. Verified by registering a custom tracing layer that
//! captures span field values when new spans are created.

use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::http::Request;
use intellipilot_api::{AppState, build_router};
use tower::ServiceExt;
use tracing::field::{Field, Visit};
use tracing::span::Attributes;
use tracing_subscriber::Layer;
use tracing_subscriber::layer::{Context, SubscriberExt};

#[derive(Clone, Default)]
struct CapturedSpans(Arc<Mutex<Vec<(String, std::collections::HashMap<String, String>)>>>);

struct FieldVisitor<'a>(&'a mut std::collections::HashMap<String, String>);

impl Visit for FieldVisitor<'_> {
    fn record_str(&mut self, field: &Field, value: &str) {
        self.0.insert(field.name().to_owned(), value.to_owned());
    }
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.0.insert(field.name().to_owned(), format!("{value:?}"));
    }
}

impl<S: tracing::Subscriber> Layer<S> for CapturedSpans {
    fn on_new_span(&self, attrs: &Attributes<'_>, _id: &tracing::span::Id, _ctx: Context<'_, S>) {
        let metadata = attrs.metadata();
        let mut fields = std::collections::HashMap::new();
        attrs.record(&mut FieldVisitor(&mut fields));
        self.0
            .lock()
            .unwrap()
            .push((metadata.name().to_owned(), fields));
    }
}

#[tokio::test]
async fn request_id_attached_to_http_request_span() {
    let captured = CapturedSpans::default();
    let subscriber = tracing_subscriber::registry().with(captured.clone());
    let _guard = tracing::subscriber::set_default(subscriber);

    let app = build_router(AppState::builder().build());
    let given = "abc123def456ababab1234567890abcd";

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/health/live")
                .header("x-request-id", given)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(resp.status().is_success());

    let spans = captured.0.lock().unwrap();
    let http_span = spans
        .iter()
        .find(|(name, _)| name == "http_request")
        .expect("`http_request` span must be created per request");
    assert_eq!(
        http_span.1.get("request_id").map(String::as_str),
        Some(given),
        "http_request span must carry request_id={given:?} as a field; got {:?}",
        http_span.1
    );
}

#[tokio::test]
async fn generated_request_id_attached_when_header_missing() {
    let captured = CapturedSpans::default();
    let subscriber = tracing_subscriber::registry().with(captured.clone());
    let _guard = tracing::subscriber::set_default(subscriber);

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
    let id_from_resp = resp
        .headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .unwrap()
        .to_owned();

    let spans = captured.0.lock().unwrap();
    let http_span = spans
        .iter()
        .find(|(name, _)| name == "http_request")
        .expect("`http_request` span must be created per request");
    assert_eq!(
        http_span.1.get("request_id").map(String::as_str),
        Some(id_from_resp.as_str()),
        "span request_id must match the id echoed in the response header"
    );
}
