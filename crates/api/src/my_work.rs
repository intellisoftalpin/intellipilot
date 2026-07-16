//! Cross-project personal work feed (`GET /api/v1/me/issues`).
//!
//! Lists the caller's issues by role — assignee, reporter, reviewer, QA, or
//! mentioned — across every project, newest-modified first. Built for API
//! clients (the IntelliPilot MCP server in particular) that need "my tasks"
//! without walking each project's backlog.

use axum::Json;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use intellipilot_core::my_work::{MyIssue, MyIssueRole};
use intellipilot_db::{my_issues, users};
use serde::Deserialize;
use serde::Serialize;
use utoipa::{IntoParams, ToSchema};

use crate::auth::{AuthUser, request_id};
use crate::problem::Problem;
use crate::state::AppState;

const DEFAULT_LIMIT: i64 = 50;
const MAX_LIMIT: i64 = 200;

#[derive(Debug, Deserialize, IntoParams)]
pub struct MyIssuesQuery {
    /// Relation to the issue: `assignee` (default), `reporter`, `reviewer`,
    /// `qa`, or `mentioned`.
    pub role: Option<MyIssueRole>,
    /// Narrow the feed to one project.
    pub project: Option<uuid::Uuid>,
    /// Include issues whose status is closed (default false).
    pub include_closed: Option<bool>,
    /// Case-insensitive substring match on the subject.
    pub search: Option<String>,
    /// Page size, 1..=200 (default 50).
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct MyIssuesResponse {
    pub issues: Vec<MyIssue>,
    pub total: i64,
    pub limit: i64,
    pub offset: i64,
}

/// `GET /api/v1/me/issues`
#[utoipa::path(get, path = "/api/v1/me/issues", params(MyIssuesQuery),
    responses((status = 200, body = MyIssuesResponse), (status = 401)))]
pub async fn list_my_issues(
    State(state): State<AppState>,
    headers: HeaderMap,
    user: AuthUser,
    Query(q): Query<MyIssuesQuery>,
) -> Response {
    let rid = request_id(&headers);
    let auth = state.auth();
    let Ok(client) = auth.db.pool.get().await else {
        return internal(&rid);
    };

    let role = q.role.unwrap_or(MyIssueRole::Assignee);
    let include_closed = q.include_closed.unwrap_or(false);
    let limit = q.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);
    let offset = q.offset.unwrap_or(0).max(0);
    let search = q.search.as_deref().filter(|s| !s.trim().is_empty());

    // The mention filter needs the caller's handle; fetching the user also
    // guards against tokens outliving a since-deleted account.
    let username = match users::find_by_id(&client, user.user_id).await {
        Ok(Some(u)) => u.username,
        Ok(None) => {
            return Problem::new(StatusCode::NOT_FOUND, "not_found", "Not Found", None, &rid)
                .into_response_with_status(StatusCode::NOT_FOUND);
        }
        Err(_) => return internal(&rid),
    };

    match my_issues::list(
        &client,
        user.user_id,
        &username,
        role,
        q.project,
        include_closed,
        search,
        limit,
        offset,
    )
    .await
    {
        Ok((issues, total)) => Json(MyIssuesResponse {
            issues,
            total,
            limit,
            offset,
        })
        .into_response(),
        Err(_) => internal(&rid),
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
