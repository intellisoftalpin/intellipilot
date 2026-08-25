//! Project navigation counts (`GET /api/v1/projects/{project_id}/counts`).
//!
//! Feeds the badge on each rail section. Sections are gated by separate view
//! permissions, so a caller who may not see epics gets `null` rather than a
//! misleading `0`.

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use intellipilot_core::counts::CountScopes;
use intellipilot_core::perms::Permission;
use intellipilot_db::counts as cdb;

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

/// `GET /api/v1/projects/{project_id}/counts`
#[utoipa::path(get, path = "/api/v1/projects/{project_id}/counts",
    params(("project_id" = String, Path, description = "Project id or slug")),
    responses((status = 200, body = intellipilot_core::counts::ProjectCounts),
        (status = 401), (status = 403)))]
pub async fn get_counts(State(state): State<AppState>, ctx: ProjectContext) -> Response {
    // Seeing the rail at all is `project.view`; each badge is then gated
    // individually.
    if let Err(r) = ctx.require(Permission::ProjectView) {
        return r;
    }
    let scopes = CountScopes {
        issues: ctx.require(Permission::IssueView).is_ok(),
        epics: ctx.require(Permission::EpicView).is_ok(),
        milestones: ctx.require(Permission::MilestoneView).is_ok(),
    };
    let auth = state.auth();
    let Ok(client) = auth.db.pool.get().await else {
        return internal(&ctx.rid);
    };
    // The mention pattern is only needed for the My Issues count.
    let mention = if scopes.issues {
        crate::my_role::actor(&client, ctx.actor_id)
            .await
            .mention_like
    } else {
        None
    };
    match cdb::project_counts(
        &client,
        ctx.project.id,
        ctx.actor_id,
        mention.as_deref(),
        scopes,
    )
    .await
    {
        Ok(counts) => Json(counts).into_response(),
        Err(_) => internal(&ctx.rid),
    }
}
