//! Request ID middleware.
//!
//! - When the client sends a valid `x-request-id` (alphanumeric + `-`/`_`,
//!   1..=128 chars), it is preserved and echoed in the response.
//! - When the header is absent, a fresh UUIDv7 is generated.
//! - When the header is malformed, the request is rejected with 400
//!   Problem+JSON and a fresh request id is still surfaced in the response.

use axum::extract::Request;
use axum::http::{HeaderName, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::Response;
use intellipilot_core::ids;
use tracing::Instrument;

use crate::problem::Problem;

pub static REQUEST_ID_HEADER: HeaderName = HeaderName::from_static("x-request-id");

const MAX_LEN: usize = 128;

/// UUIDv7 textual form is always ASCII `[0-9a-f\-]`, which is a strict subset
/// of [`HeaderValue`]'s permitted byte set (0x20..=0x7E). Any failure here
/// would indicate memory corruption.
#[allow(clippy::expect_used)]
fn header_from_id(s: &str) -> HeaderValue {
    HeaderValue::from_str(s).expect("UUIDv7 is valid header value")
}

/// Marker placed in request extensions so handlers can read the resolved id.
#[derive(Debug, Clone)]
pub struct RequestId(pub String);

fn is_valid(v: &str) -> bool {
    let len = v.len();
    if len == 0 || len > MAX_LEN {
        return false;
    }
    v.bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

pub async fn layer(mut req: Request, next: Next) -> Response {
    let provided = req
        .headers()
        .get(&REQUEST_ID_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);

    let fresh = ids::new_v7().to_string();

    // The active id flows through both request extensions (handler access)
    // and a tracing::info_span so every log line emitted while serving this
    // request carries `request_id=<id>` as a structured field.
    let run_with_span = |req: Request, id: String| {
        let span = tracing::info_span!(
            "http_request",
            request_id = %id,
            method = %req.method(),
            uri = %req.uri(),
        );
        async move { next.run(req).await }.instrument(span)
    };

    match provided {
        // Valid client-supplied id: preserve.
        Some(id) if is_valid(&id) => {
            let header_value =
                HeaderValue::from_str(&id).unwrap_or_else(|_| header_from_id(&fresh));
            req.extensions_mut().insert(RequestId(id.clone()));
            req.headers_mut()
                .insert(REQUEST_ID_HEADER.clone(), header_value.clone());
            let mut resp = run_with_span(req, id).await;
            resp.headers_mut()
                .insert(REQUEST_ID_HEADER.clone(), header_value);
            resp
        }
        // Malformed: reject with 400, fresh id.
        Some(_) => {
            let problem = Problem::new(
                StatusCode::BAD_REQUEST,
                "invalid_request_id",
                "Invalid Request ID",
                Some(format!(
                    "x-request-id must be 1..={MAX_LEN} chars of [a-zA-Z0-9_-]"
                )),
                &fresh,
            );
            let mut resp = problem.into_response_with_status(StatusCode::BAD_REQUEST);
            resp.headers_mut()
                .insert(REQUEST_ID_HEADER.clone(), header_from_id(&fresh));
            // Drop the request body so the connection can be released.
            drop(req);
            resp
        }
        // Absent: generate.
        None => {
            let header_value = header_from_id(&fresh);
            req.extensions_mut().insert(RequestId(fresh.clone()));
            req.headers_mut()
                .insert(REQUEST_ID_HEADER.clone(), header_value.clone());
            let id = fresh.clone();
            let mut resp = run_with_span(req, id).await;
            resp.headers_mut()
                .insert(REQUEST_ID_HEADER.clone(), header_value);
            resp
        }
    }
}
