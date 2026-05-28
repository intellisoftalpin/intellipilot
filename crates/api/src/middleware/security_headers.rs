//! Baseline security headers.
//!
//! CSP is intentionally strict on API responses; on `/docs` and `/reference`
//! we relax script-src so Swagger UI / Scalar can load.

use axum::extract::Request;
use axum::http::{HeaderName, HeaderValue, header};
use axum::middleware::Next;
use axum::response::Response;

const CSP_STRICT: &str =
    "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'";
const CSP_DOCS: &str = "default-src 'self' https://cdn.jsdelivr.net; \
     script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; \
     style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; \
     img-src 'self' data: https:; \
     font-src 'self' data: https://cdn.jsdelivr.net; \
     connect-src 'self'; \
     frame-ancestors 'none'; \
     base-uri 'none'";

const PERMISSIONS_POLICY: &str = "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), \
     microphone=(), payment=(), usb=(), interest-cohort=()";

pub async fn layer(req: Request, next: Next) -> Response {
    let is_docs = matches!(req.uri().path(), "/docs" | "/reference")
        || req.uri().path().starts_with("/docs/")
        || req.uri().path().starts_with("/reference/");

    let mut resp = next.run(req).await;
    let h = resp.headers_mut();

    h.insert(
        header::HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("strict-origin-when-cross-origin"),
    );
    h.insert(
        HeaderName::from_static("x-frame-options"),
        HeaderValue::from_static("DENY"),
    );
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(if is_docs { CSP_DOCS } else { CSP_STRICT }),
    );
    h.insert(
        HeaderName::from_static("permissions-policy"),
        HeaderValue::from_static(PERMISSIONS_POLICY),
    );
    h.insert(
        HeaderName::from_static("cross-origin-opener-policy"),
        HeaderValue::from_static("same-origin"),
    );
    h.insert(
        HeaderName::from_static("cross-origin-resource-policy"),
        HeaderValue::from_static("same-site"),
    );
    // Strip identification headers if any framework set them.
    h.remove(header::SERVER);
    h.remove(HeaderName::from_static("x-powered-by"));

    resp
}
