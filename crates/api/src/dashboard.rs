//! Dashboard endpoints: the global home dashboard (current user, all projects)
//! and the per-project dashboard.

use axum::Json;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use intellipilot_core::perms::Permission;
use intellipilot_db::{dashboard as dashdb, time_tracking};

use crate::auth::{AuthUser, request_id};
use crate::problem::Problem;
use crate::projects::ProjectContext;
use crate::state::AppState;

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

/// `GET /api/v1/me/dashboard` — the current user's cross-project home dashboard.
#[utoipa::path(get, path = "/api/v1/me/dashboard",
    responses((status = 200, body = intellipilot_core::dashboard::HomeDashboard), (status = 401)))]
pub async fn get_home(
    State(state): State<AppState>,
    headers: HeaderMap,
    user: AuthUser,
) -> Response {
    let rid = request_id(&headers);
    let auth = state.auth();
    let Ok(client) = auth.db.pool.get().await else {
        return internal(&rid);
    };
    let today = time_tracking::today_utc();
    dashdb::home(&client, user.user_id, today)
        .await
        .map_or_else(|_| internal(&rid), |d| Json(d).into_response())
}

/// `GET /api/v1/projects/{project_id}/dashboard` — one project's dashboard.
#[utoipa::path(get, path = "/api/v1/projects/{project_id}/dashboard",
    responses((status = 200, body = intellipilot_core::dashboard::ProjectDashboard),
        (status = 401), (status = 403)))]
pub async fn get_project(State(state): State<AppState>, ctx: ProjectContext) -> Response {
    if let Err(r) = ctx.require(Permission::IssueView) {
        return r;
    }
    let auth = state.auth();
    let Ok(client) = auth.db.pool.get().await else {
        return internal(&ctx.rid);
    };
    let today = time_tracking::today_utc();
    dashdb::project(&client, ctx.project.id, ctx.actor_id, today)
        .await
        .map_or_else(|_| internal(&ctx.rid), |d| Json(d).into_response())
}
