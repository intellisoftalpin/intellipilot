//! `AuthUser` extractor — validates the Bearer access token.
//!
//! Besides Paseto access tokens, `AuthUser` also accepts a personal app token
//! (`ippt_…`): it resolves to the owning user, so the bearer acts exactly as
//! if that user were logged in. Admin app tokens (`ipat_…`) are deliberately
//! NOT accepted here — they act as INTELLIBOT and only work on
//! project-scoped routes via [`Caller`].
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

        let Some(token) = bearer(parts) else {
            return Err(unauthorized(&rid));
        };

        if token.starts_with(intellipilot_core::app_token::PERSONAL_TOKEN_PREFIX) {
            let user_id = personal_token_user(state, token, &rid).await?;
            return Ok(Self { user_id });
        }

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

/// Resolve an `ippt_…` bearer to its owning user.
///
/// Active means: token not disabled, owner active and not deleted. Best-effort
/// stamps `last_used_at`.
async fn personal_token_user(state: &AppState, token: &str, rid: &str) -> Result<Uuid, Response> {
    let auth = state.auth.as_ref().ok_or_else(|| internal(rid))?;
    let hash = intellipilot_auth::app_token::hash_token(token);
    let client = auth.db.pool.get().await.map_err(|_| internal(rid))?;
    match intellipilot_db::personal_tokens::find_active_by_hash(&client, &hash).await {
        Ok(Some(t)) => {
            if let Err(e) = intellipilot_db::personal_tokens::touch_last_used(&client, t.id).await {
                tracing::warn!(error = %e, "failed to stamp personal token last_used_at");
            }
            Ok(t.user_id)
        }
        _ => Err(unauthorized(rid)),
    }
}

/// Extract the raw bearer credential from the `Authorization` header.
fn bearer(parts: &Parts) -> Option<&str> {
    parts
        .headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::trim)
}

/// The authenticated caller behind a request.
///
/// Either a human user (Paseto access token, or a personal `ippt_` token that
/// resolves to its owner) or an app token (the `ipat_` bearer). App tokens
/// carry their granted permissions + project scope and act as the INTELLIBOT
/// user.
#[derive(Debug, Clone)]
pub enum Caller {
    User(Uuid),
    AppToken(intellipilot_db::app_tokens::AppTokenAuth),
}

impl FromRequestParts<AppState> for Caller {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        authenticate(parts, state).await
    }
}

/// Resolve the [`Caller`] from the bearer credential.
///
/// An `ipat_…` bearer is validated against the app-token store (must be active:
/// not revoked, not expired); an `ippt_…` bearer resolves to the owning user
/// (a personal token acts exactly as that user); anything else is verified as
/// a Paseto access token. Token auth best-effort stamps `last_used_at`.
///
/// `result_large_err`: the rejection is an axum `Response`, by design.
#[allow(clippy::result_large_err)]
pub async fn authenticate(parts: &Parts, state: &AppState) -> Result<Caller, Response> {
    let rid = request_id(&parts.headers);
    let auth = state.auth.as_ref().ok_or_else(|| internal(&rid))?;
    let Some(token) = bearer(parts) else {
        return Err(unauthorized(&rid));
    };
    if token.starts_with(intellipilot_core::app_token::PERSONAL_TOKEN_PREFIX) {
        return personal_token_user(state, token, &rid)
            .await
            .map(Caller::User);
    }
    if token.starts_with(intellipilot_core::app_token::TOKEN_PREFIX) {
        let hash = intellipilot_auth::app_token::hash_token(token);
        let client = auth.db.pool.get().await.map_err(|_| internal(&rid))?;
        match intellipilot_db::app_tokens::find_active_by_hash(&client, &hash).await {
            Ok(Some(t)) => {
                if let Err(e) = intellipilot_db::app_tokens::touch_last_used(&client, t.id).await {
                    tracing::warn!(error = %e, "failed to stamp app token last_used_at");
                }
                Ok(Caller::AppToken(t))
            }
            _ => Err(unauthorized(&rid)),
        }
    } else {
        verify_access_token(&auth.access_key, token)
            .map(|c| Caller::User(c.user_id))
            .map_err(|_| unauthorized(&rid))
    }
}

fn internal(rid: &str) -> Response {
    Problem::new(
        StatusCode::INTERNAL_SERVER_ERROR,
        "internal_error",
        "Internal Server Error",
        None,
        rid,
    )
    .into_response_with_status(StatusCode::INTERNAL_SERVER_ERROR)
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

/// An authenticated **superadmin**. Wraps the [`AuthUser`] extraction, then
/// checks `users.is_superadmin AND is_active AND NOT deleted` with a single
/// SELECT. Used as the only gate on `/api/v1/admin/*`.
#[derive(Debug, Clone, Copy)]
pub struct SuperadminUser {
    pub user_id: Uuid,
}

impl FromRequestParts<AppState> for SuperadminUser {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let rid = request_id(&parts.headers);
        let user = AuthUser::from_request_parts(parts, state).await?;
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

        let client = auth.db.pool.get().await.map_err(|_| {
            Problem::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "Internal Server Error",
                None,
                &rid,
            )
            .into_response_with_status(StatusCode::INTERNAL_SERVER_ERROR)
        })?;

        let row = client
            .query_opt(
                "SELECT is_superadmin, is_active FROM users \
                 WHERE id = $1 AND deleted_at IS NULL",
                &[&user.user_id],
            )
            .await
            .map_err(|_| {
                Problem::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    "Internal Server Error",
                    None,
                    &rid,
                )
                .into_response_with_status(StatusCode::INTERNAL_SERVER_ERROR)
            })?;

        let allowed = row
            .as_ref()
            .is_some_and(|r| r.get::<_, bool>("is_superadmin") && r.get::<_, bool>("is_active"));

        if !allowed {
            return Err(Problem::new(
                StatusCode::FORBIDDEN,
                "forbidden",
                "Forbidden",
                Some("superadmin role required".to_owned()),
                &rid,
            )
            .into_response_with_status(StatusCode::FORBIDDEN));
        }

        Ok(Self {
            user_id: user.user_id,
        })
    }
}
