//! `AuthUser` extractor — validates the Bearer access token.
//!
//! `result_large_err`: the rejection type is an axum `Response` by design.
#![allow(clippy::result_large_err)]

use axum::extract::FromRequestParts;
use axum::http::StatusCode;
use axum::http::request::Parts;
use axum::response::Response;
use intellipilot_auth::token::verify_access_token;
use uuid::Uuid;

use crate::auth::request_id;
use crate::problem::Problem;
use crate::state::AppState;

/// An authenticated principal, extracted from a valid Paseto access token.
#[derive(Debug, Clone, Copy)]
pub struct AuthUser {
    pub user_id: Uuid,
}

impl FromRequestParts<AppState> for AuthUser {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let rid = request_id(&parts.headers);
        let auth = state.auth.as_ref().ok_or_else(|| {
            Problem::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "Internal Server Error",
                None,
                &rid,
            )
            .into_response_with_status(StatusCode::INTERNAL_SERVER_ERROR)
        })?;

        let token = parts
            .headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .map(str::trim);

        let Some(token) = token else {
            return Err(unauthorized(&rid));
        };

        verify_access_token(&auth.access_key, token).map_or_else(
            |_| Err(unauthorized(&rid)),
            |claims| {
                Ok(Self {
                    user_id: claims.user_id,
                })
            },
        )
    }
}

fn unauthorized(rid: &str) -> Response {
    Problem::new(
        StatusCode::UNAUTHORIZED,
        "unauthorized",
        "Unauthorized",
        Some("missing or invalid access token".to_owned()),
        rid,
    )
    .into_response_with_status(StatusCode::UNAUTHORIZED)
}
