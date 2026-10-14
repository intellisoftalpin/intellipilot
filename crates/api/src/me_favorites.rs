//! Favorite projects self-service (`/api/v1/me/project-favorites`).
//!
//! A user stars up to [`MAX_FAVORITES`] projects; the clients list them first.
//! The set is read and written whole — the client sends the new list, the
//! server validates it and swaps it in — so there is no add/remove pair to
//! keep consistent across tabs and devices.

use std::collections::HashSet;

use axum::Json;
use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use intellipilot_db::{project_favorites, users};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::auth::{AuthUser, request_id};
use crate::problem::Problem;
use crate::state::AppState;

/// The most projects one user can star.
pub const MAX_FAVORITES: usize = 4;

/// The user's favorite projects, in the order they were starred.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ProjectFavorites {
    pub project_ids: Vec<Uuid>,
}

fn problem(
    status: StatusCode,
    code: &'static str,
    title: &str,
    detail: Option<String>,
    rid: &str,
) -> Response {
    Problem::new(status, code, title, detail, rid).into_response_with_status(status)
}

fn internal(rid: &str) -> Response {
    problem(
        StatusCode::INTERNAL_SERVER_ERROR,
        "internal_error",
        "Internal Server Error",
        None,
        rid,
    )
}

/// `GET /api/v1/me/project-favorites` — the caller's favorites. Projects they
/// can no longer see are left out.
#[utoipa::path(get, path = "/api/v1/me/project-favorites",
    responses((status = 200, body = ProjectFavorites), (status = 401)))]
pub async fn get_favorites(
    State(state): State<AppState>,
    headers: HeaderMap,
    user: AuthUser,
) -> Response {
    let rid = request_id(&headers);
    let auth = state.auth();
    let Ok(client) = auth.db.pool.get().await else {
        return internal(&rid);
    };
    let superadmin = users::is_active_superadmin(&client, user.user_id)
        .await
        .unwrap_or(false);
    project_favorites::list(&client, user.user_id, superadmin)
        .await
        .map_or_else(
            |_| internal(&rid),
            |project_ids| Json(ProjectFavorites { project_ids }).into_response(),
        )
}

/// `PUT /api/v1/me/project-favorites` — replace the caller's favorites.
///
/// 422 `too_many_favorites` above [`MAX_FAVORITES`], `duplicate_favorite` for a
/// repeated id, and `unknown_project` for a project the caller cannot see.
#[utoipa::path(put, path = "/api/v1/me/project-favorites", request_body = ProjectFavorites,
    responses((status = 200, body = ProjectFavorites), (status = 400), (status = 401), (status = 422)))]
pub async fn put_favorites(
    State(state): State<AppState>,
    headers: HeaderMap,
    user: AuthUser,
    body: Result<Json<ProjectFavorites>, JsonRejection>,
) -> Response {
    let rid = request_id(&headers);
    let Ok(Json(req)) = body else {
        return problem(
            StatusCode::BAD_REQUEST,
            "invalid_body",
            "Invalid Request Body",
            None,
            &rid,
        );
    };
    let ids = req.project_ids;
    if ids.len() > MAX_FAVORITES {
        return problem(
            StatusCode::UNPROCESSABLE_ENTITY,
            "too_many_favorites",
            "Too many favorites",
            Some(format!("at most {MAX_FAVORITES} favorite projects")),
            &rid,
        );
    }
    if ids.iter().collect::<HashSet<_>>().len() != ids.len() {
        return problem(
            StatusCode::UNPROCESSABLE_ENTITY,
            "duplicate_favorite",
            "Duplicate favorite",
            None,
            &rid,
        );
    }

    let auth = state.auth();
    let Ok(mut client) = auth.db.pool.get().await else {
        return internal(&rid);
    };
    let superadmin = users::is_active_superadmin(&client, user.user_id)
        .await
        .unwrap_or(false);
    match project_favorites::count_visible(&client, user.user_id, superadmin, &ids).await {
        Ok(n) if usize::try_from(n).ok() == Some(ids.len()) => {}
        Ok(_) => {
            return problem(
                StatusCode::UNPROCESSABLE_ENTITY,
                "unknown_project",
                "Unknown project",
                Some("every favorite must be a project you can see".to_owned()),
                &rid,
            );
        }
        Err(_) => return internal(&rid),
    }
    if project_favorites::replace(&mut client, user.user_id, &ids)
        .await
        .is_err()
    {
        return internal(&rid);
    }
    Json(ProjectFavorites { project_ids: ids }).into_response()
}
