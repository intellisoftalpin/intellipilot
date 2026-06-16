//! Public white-label branding endpoint.
//!
//! Serves the admin-configured custom app icon so unauthenticated UIs (the
//! login screen) can render it before any session exists. Returns 404 when no
//! custom icon is set, letting clients fall back to their bundled default.

use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use intellipilot_db::platform_settings;

use crate::auth::request_id;
use crate::state::AppState;

/// `GET /api/v1/branding/icon` — public.
///
/// Streams the stored custom icon bytes, or 404 when none is configured. Cache
/// headers are conservative: clients cache-bust with the
/// `?v=<app_icon_updated_at>` query the config endpoint hands them, so the icon
/// may be cached privately for a short window.
#[utoipa::path(
    get,
    path = "/api/v1/branding/icon",
    responses(
        (status = 200, description = "Custom app icon bytes", content_type = "image/*"),
        (status = 404, description = "No custom icon configured"),
    )
)]
pub async fn get_icon(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let rid = request_id(&headers);
    let Some(auth) = state.auth.as_ref() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Ok(client) = auth.db.pool.get().await else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    let icon = match platform_settings::get_app_icon(&client).await {
        Ok(Some(icon)) => icon,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(_) => {
            tracing::warn!(request_id = %rid, "failed to read branding icon");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    let (bytes, mime) = icon;

    let mut resp = Response::new(Body::from(bytes));
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(&mime)
            .unwrap_or(HeaderValue::from_static("application/octet-stream")),
    );
    h.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, max-age=300"),
    );
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    resp
}
