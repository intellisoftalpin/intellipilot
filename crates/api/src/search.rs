//! Unified search endpoint across the actor's accessible projects.
#![allow(
    clippy::result_large_err,
    clippy::collapsible_if,
    clippy::manual_let_else
)]

use axum::Json;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use crate::auth::{AuthUser, request_id};
use crate::markdown::sanitize_snippet;
use crate::problem::Problem;
use crate::state::AppState;

const SNIPPET_MAX: usize = 200;
const RESULT_LIMIT: i64 = 50;
/// Queries with fewer than this many tokens also use trigram fuzzy matching.
const FUZZY_TOKEN_THRESHOLD: usize = 4;

const ENTITY_TYPES: [&str; 6] = ["epic", "user_story", "task", "issue", "wiki", "comment"];

#[derive(Debug, Deserialize)]
pub struct SearchParams {
    q: String,
    #[serde(default)]
    project_id: Option<Uuid>,
    /// Comma-separated entity types (e.g. `us,task,issue`).
    #[serde(default)]
    types: Option<String>,
}

/// Normalize a requested type token to a stored `entity_type`.
fn normalize_type(t: &str) -> Option<&'static str> {
    match t.trim() {
        "epic" => Some("epic"),
        "us" | "user_story" | "userstory" => Some("user_story"),
        "task" => Some("task"),
        "issue" => Some("issue"),
        "wiki" => Some("wiki"),
        "comment" => Some("comment"),
        _ => None,
    }
}

/// `GET /api/v1/search?q=...&project_id=...&types=us,task,...`
pub async fn search(
    State(state): State<AppState>,
    user: AuthUser,
    headers: axum::http::HeaderMap,
    Query(params): Query<SearchParams>,
) -> Response {
    let rid = request_id(&headers);
    let auth = state.auth();

    let q = params.q.trim();
    if q.is_empty() || q.len() > 200 {
        return Problem::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid_query",
            "Invalid query",
            Some("q must be 1..=200 characters".to_owned()),
            &rid,
        )
        .into_response_with_status(StatusCode::UNPROCESSABLE_ENTITY);
    }

    // Parse the type filter; unknown tokens are ignored. An explicitly empty
    // filter (all unknown) means "no matchable types" → empty result.
    let types: Option<Vec<String>> = params.types.as_ref().map(|raw| {
        raw.split(',')
            .filter_map(normalize_type)
            .map(str::to_owned)
            .collect::<Vec<_>>()
    });
    if let Some(t) = &types {
        if t.is_empty() {
            return Json(json!({ "results": [] })).into_response();
        }
    }

    let fuzzy = q.split_whitespace().count() < FUZZY_TOKEN_THRESHOLD;

    let Ok(client) = auth.db.pool.get().await else {
        return Problem::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "Internal Server Error",
            None,
            &rid,
        )
        .into_response_with_status(StatusCode::INTERNAL_SERVER_ERROR);
    };

    let hits = match intellipilot_db::search::search(
        &client,
        user.user_id,
        q,
        params.project_id,
        types.as_deref(),
        fuzzy,
        RESULT_LIMIT,
    )
    .await
    {
        Ok(h) => h,
        Err(_) => {
            return Problem::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "Internal Server Error",
                None,
                &rid,
            )
            .into_response_with_status(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    // Sanitize + bound each snippet before returning it.
    let results: Vec<_> = hits
        .into_iter()
        .map(|mut h| {
            h.snippet = sanitize_snippet(&h.snippet, SNIPPET_MAX);
            h
        })
        .collect();

    Json(json!({ "results": results, "fuzzy": fuzzy })).into_response()
}

/// The set of valid entity-type tokens, for documentation/clients.
#[must_use]
pub fn entity_types() -> [&'static str; 6] {
    ENTITY_TYPES
}
