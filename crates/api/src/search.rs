//! Unified search endpoint across the actor's accessible projects.
//!
//! A query that reads as a work-item key (`PS-1262`, `ps-1262`, `PS-E-12`,
//! `#1262`, `1262`) returns the exact item(s) first; text matches follow.
#![allow(
    clippy::result_large_err,
    clippy::collapsible_if,
    clippy::manual_let_else
)]

use axum::Json;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use intellipilot_core::search::SearchHit;
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use intellipilot_core::search::{parse_key, prefix_tsquery};
use intellipilot_db::search::SearchScope;

use crate::auth::{AuthUser, request_id};
use crate::markdown::sanitize_snippet;
use crate::problem::Problem;
use crate::state::AppState;

const SNIPPET_MAX: usize = 200;
const RESULT_LIMIT: i64 = 50;
/// Queries with fewer than this many tokens also use trigram fuzzy matching.
const FUZZY_TOKEN_THRESHOLD: usize = 4;

const ENTITY_TYPES: [&str; 7] = [
    "epic",
    "user_story",
    "task",
    "issue",
    "wiki",
    "comment",
    "meeting",
];

#[derive(Debug, Deserialize, IntoParams)]
pub struct SearchParams {
    /// Search text or a work-item key, 1-200 characters.
    q: String,
    /// Restrict results to this project.
    #[serde(default)]
    project_id: Option<Uuid>,
    /// Search everywhere, but rank this project's results first (the project
    /// the user is in). Ignored when `project_id` is set.
    #[serde(default)]
    boost_project_id: Option<Uuid>,
    /// Comma-separated entity types: `epic`, `issue`, `wiki`, `comment`,
    /// `meeting`
    /// (`us`/`task` are accepted as legacy aliases).
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
        "meeting" => Some("meeting"),
        _ => None,
    }
}

/// Search results: key hits first, then text hits by rank.
#[derive(Debug, Serialize, ToSchema)]
pub struct SearchResponse {
    pub results: Vec<SearchHit>,
    /// Trigram (typo-tolerant) title matching was used — short queries only.
    pub fuzzy: bool,
}

/// `GET /api/v1/search?q=...&project_id=...&boost_project_id=...&types=...`
///
/// Searches every project the caller may read: projects they are a member of
/// (per-type view permission), or all projects for a superadmin. A query that
/// reads as a key (`PS-1262`, `ps-1262`, `PS-E-12`, `#1262`, `1262`) returns
/// the exact item(s) first, flagged `key_match`.
#[utoipa::path(get, path = "/api/v1/search", params(SearchParams),
    responses((status = 200, body = SearchResponse), (status = 401), (status = 422)))]
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
            return Json(SearchResponse {
                results: Vec::new(),
                fuzzy: false,
            })
            .into_response();
        }
    }

    let fuzzy = q.split_whitespace().count() < FUZZY_TOKEN_THRESHOLD;

    let Ok(mut client) = auth.db.pool.get().await else {
        return internal(&rid);
    };

    let is_superadmin =
        match intellipilot_db::users::is_active_superadmin(&client, user.user_id).await {
            Ok(v) => v,
            Err(_) => return internal(&rid),
        };
    let scope = SearchScope {
        actor_id: user.user_id,
        is_superadmin,
        project_id: params.project_id,
        boost_project_id: params.boost_project_id.or(params.project_id),
        types: types.as_deref(),
    };

    let mut hits = match parse_key(q) {
        Some(key) => {
            match intellipilot_db::search::search_keys(&client, &scope, &key, RESULT_LIMIT).await {
                Ok(h) => h,
                Err(_) => return internal(&rid),
            }
        }
        None => Vec::new(),
    };
    let text = match intellipilot_db::search::search_text(
        &mut client,
        &scope,
        q,
        prefix_tsquery(q).as_deref(),
        fuzzy,
        RESULT_LIMIT,
    )
    .await
    {
        Ok(h) => h,
        Err(_) => return internal(&rid),
    };
    // Key hits lead; a text hit for the same item is a duplicate.
    for h in text {
        if !hits.iter().any(|k| k.entity_id == h.entity_id) {
            hits.push(h);
        }
    }
    hits.truncate(usize::try_from(RESULT_LIMIT).unwrap_or(usize::MAX));

    // Sanitize + bound each snippet before returning it.
    let results: Vec<_> = hits
        .into_iter()
        .map(|mut h| {
            h.snippet = sanitize_snippet(&h.snippet, SNIPPET_MAX);
            h
        })
        .collect();

    Json(SearchResponse { results, fuzzy }).into_response()
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

/// The set of valid entity-type tokens, for documentation/clients.
#[must_use]
pub fn entity_types() -> [&'static str; 7] {
    ENTITY_TYPES
}
