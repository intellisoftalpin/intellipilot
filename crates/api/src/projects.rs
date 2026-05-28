//! Project, role, membership, and invitation endpoints + the permission-aware
//! `ProjectContext` extractor.
//!
//! Several style lints are relaxed: handlers extract `Path<HashMap<..>>`
//! (axum's standard hasher), match on pool/result with a tailored error arm
//! (`manual_let_else`/`collapsible_if`), and use small if/else over options.
#![allow(
    clippy::arithmetic_side_effects,
    clippy::result_large_err,
    clippy::implicit_hasher,
    clippy::manual_let_else,
    clippy::collapsible_if,
    clippy::option_if_let_else
)]

use std::collections::HashMap;

use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::extract::{FromRequestParts, Path, State};
use axum::http::StatusCode;
use axum::http::request::Parts;
use axum::response::{IntoResponse, Response};
use garde::Validate;
use intellipilot_auth::refresh;
use intellipilot_core::perms::Permission;
use intellipilot_core::project::{NewProject, ProjectUpdate, Visibility};
use intellipilot_db::memberships::MemberAccess;
use intellipilot_db::{
    audit, invitations as invdb, memberships as memdb, projects as projdb, roles as roledb,
};
use serde_json::json;
use time::{Duration as TimeDuration, OffsetDateTime};
use uuid::Uuid;

use crate::auth::{AuthUser, client_ip, request_id, user_agent};
use crate::dto::{
    AcceptInviteRequest, ChangeMemberRoleRequest, CreateProjectRequest, CreateRoleRequest,
    InviteRequest, InviteResponse, UpdateProjectRequest, UpdateRoleRequest,
};
use crate::problem::Problem;
use crate::state::AppState;

const INVITE_TTL_SECS: i64 = 7 * 24 * 60 * 60; // 7 days

// --------------------------------------------------------------------------
// helpers
// --------------------------------------------------------------------------

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
fn not_found(rid: &str) -> Response {
    problem(StatusCode::NOT_FOUND, "not_found", "Not Found", None, rid)
}
fn forbidden(rid: &str) -> Response {
    problem(StatusCode::FORBIDDEN, "forbidden", "Forbidden", None, rid)
}
fn conflict(rid: &str, detail: &str) -> Response {
    problem(
        StatusCode::CONFLICT,
        "conflict",
        "Conflict",
        Some(detail.to_owned()),
        rid,
    )
}

fn parse_body<T: serde::de::DeserializeOwned + Validate<Context = ()>>(
    body: Result<Json<T>, JsonRejection>,
    rid: &str,
) -> Result<T, Response> {
    let Ok(Json(v)) = body else {
        return Err(problem(
            StatusCode::BAD_REQUEST,
            "invalid_body",
            "Invalid Request Body",
            None,
            rid,
        ));
    };
    if v.validate().is_err() {
        return Err(problem(
            StatusCode::UNPROCESSABLE_ENTITY,
            "validation_failed",
            "Validation failed",
            None,
            rid,
        ));
    }
    Ok(v)
}

/// Slugify a name into a URL-safe slug.
pub(crate) fn slugify(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut prev_dash = false;
    for ch in name.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
            prev_dash = false;
        } else if !prev_dash && !out.is_empty() {
            out.push('-');
            prev_dash = true;
        }
    }
    let trimmed = out.trim_matches('-').to_owned();
    if trimmed.is_empty() {
        "project".to_owned()
    } else {
        trimmed
    }
}

// --------------------------------------------------------------------------
// ProjectContext extractor
// --------------------------------------------------------------------------

/// Loads the project named by the `{project_id}` path param plus the actor's
/// access. Enforces the visibility rule: a private project is invisible (404)
/// to non-members, so existence is never disclosed.
#[derive(Debug)]
pub struct ProjectContext {
    pub project: intellipilot_core::project::Project,
    pub actor_id: Uuid,
    pub access: Option<MemberAccess>,
    pub rid: String,
}

impl ProjectContext {
    /// Require a specific permission; 403 if the member lacks it.
    pub fn require(&self, perm: Permission) -> Result<(), Response> {
        if self.access.as_ref().is_some_and(|a| a.has(perm)) {
            Ok(())
        } else {
            Err(forbidden(&self.rid))
        }
    }

    /// Whether the actor may view the project (member with view, or the
    /// project is internal/public).
    #[must_use]
    pub fn can_view(&self) -> bool {
        self.access
            .as_ref()
            .is_some_and(|a| a.has(Permission::ProjectView))
            || self.project.visibility != Visibility::Private
    }
}

impl FromRequestParts<AppState> for ProjectContext {
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Response> {
        let rid = request_id(&parts.headers);
        let auth = state.auth.as_ref().ok_or_else(|| internal(&rid))?;
        let user = AuthUser::from_request_parts(parts, state).await?;

        let params = Path::<HashMap<String, String>>::from_request_parts(parts, state)
            .await
            .map_err(|_| not_found(&rid))?;
        let project_id = params
            .get("project_id")
            .and_then(|s| Uuid::parse_str(s).ok())
            .ok_or_else(|| not_found(&rid))?;

        let client = auth.db.pool.get().await.map_err(|_| internal(&rid))?;
        let project = projdb::find_by_id(&client, project_id)
            .await
            .map_err(|_| internal(&rid))?
            .ok_or_else(|| not_found(&rid))?;
        let access = memdb::access(&client, project_id, user.user_id)
            .await
            .map_err(|_| internal(&rid))?;

        // Private projects are hidden from non-members.
        if project.visibility == Visibility::Private && access.is_none() {
            return Err(not_found(&rid));
        }

        Ok(Self {
            project,
            actor_id: user.user_id,
            access,
            rid,
        })
    }
}

// --------------------------------------------------------------------------
// projects
// --------------------------------------------------------------------------

/// `POST /api/v1/projects`
#[utoipa::path(post, path = "/api/v1/projects", request_body = CreateProjectRequest,
    responses((status = 201), (status = 409), (status = 422)))]
pub async fn create_project(
    State(state): State<AppState>,
    user: AuthUser,
    headers: axum::http::HeaderMap,
    body: Result<Json<CreateProjectRequest>, JsonRejection>,
) -> Response {
    let rid = request_id(&headers);
    let auth = state.auth();
    let req = match parse_body(body, &rid) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let visibility = match req.visibility.as_deref().map(Visibility::parse) {
        Some(Some(v)) => v,
        Some(None) => {
            return problem(
                StatusCode::UNPROCESSABLE_ENTITY,
                "invalid_visibility",
                "Invalid visibility",
                None,
                &rid,
            );
        }
        None => Visibility::Private,
    };

    let mut client = match auth.db.pool.get().await {
        Ok(c) => c,
        Err(_) => return internal(&rid),
    };

    // Determine a unique slug.
    let base = req.slug.clone().unwrap_or_else(|| slugify(&req.name));
    let slug = match unique_slug(&client, &base).await {
        Ok(s) => s,
        Err(_) => return internal(&rid),
    };

    let new = NewProject {
        name: req.name.clone(),
        slug,
        description: req.description.clone(),
        owner_id: user.user_id,
        visibility,
    };
    match projdb::create_with_defaults(&mut client, &new).await {
        Ok(project) => {
            audit::record(
                &client,
                Some(user.user_id),
                "project_created",
                Some(client_ip(&headers)),
                Some(&user_agent(&headers)),
                &json!({ "project_id": project.id.to_string() }),
            )
            .await;
            (StatusCode::CREATED, Json(project)).into_response()
        }
        Err(e) if e.is_unique_violation() => conflict(&rid, "project slug already exists"),
        Err(_) => internal(&rid),
    }
}

async fn unique_slug(
    client: &deadpool_postgres::Client,
    base: &str,
) -> Result<String, intellipilot_db::DbError> {
    if !projdb::slug_exists(client, base).await? {
        return Ok(base.to_owned());
    }
    for _ in 0..5 {
        let raw = refresh::generate().raw;
        let suffix = raw.get(..6).unwrap_or(raw.as_str()).to_lowercase();
        let candidate = format!("{base}-{suffix}");
        if !projdb::slug_exists(client, &candidate).await? {
            return Ok(candidate);
        }
    }
    Ok(format!("{base}-{}", Uuid::now_v7().simple()))
}

/// `GET /api/v1/projects` — projects the caller is a member of.
#[utoipa::path(get, path = "/api/v1/projects", responses((status = 200)))]
pub async fn list_projects(
    State(state): State<AppState>,
    user: AuthUser,
    headers: axum::http::HeaderMap,
) -> Response {
    let rid = request_id(&headers);
    let auth = state.auth();
    let Ok(client) = auth.db.pool.get().await else {
        return internal(&rid);
    };
    match projdb::list_for_member(&client, user.user_id).await {
        Ok(projects) => Json(json!({ "projects": projects })).into_response(),
        Err(_) => internal(&rid),
    }
}

/// `GET /api/v1/projects/{project_id}`
#[utoipa::path(get, path = "/api/v1/projects/{project_id}", responses((status = 200), (status = 404)))]
pub async fn get_project(ctx: ProjectContext) -> Response {
    if !ctx.can_view() {
        return forbidden(&ctx.rid);
    }
    Json(ctx.project).into_response()
}

/// `PATCH /api/v1/projects/{project_id}`
#[utoipa::path(patch, path = "/api/v1/projects/{project_id}", request_body = UpdateProjectRequest,
    responses((status = 200), (status = 403), (status = 404)))]
pub async fn update_project(
    State(state): State<AppState>,
    ctx: ProjectContext,
    body: Result<Json<UpdateProjectRequest>, JsonRejection>,
) -> Response {
    if let Err(r) = ctx.require(Permission::ProjectModify) {
        return r;
    }
    let req = match parse_body(body, &ctx.rid) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let visibility = match req.visibility.as_deref().map(Visibility::parse) {
        Some(Some(v)) => Some(v),
        Some(None) => {
            return problem(
                StatusCode::UNPROCESSABLE_ENTITY,
                "invalid_visibility",
                "Invalid visibility",
                None,
                &ctx.rid,
            );
        }
        None => None,
    };
    let upd = ProjectUpdate {
        name: req.name.clone(),
        description: req.description.clone(),
        visibility,
        kanban_enabled: req.kanban_enabled,
        backlog_enabled: req.backlog_enabled,
        wiki_enabled: req.wiki_enabled,
        epics_enabled: req.epics_enabled,
    };
    let auth = state.auth();
    let Ok(client) = auth.db.pool.get().await else {
        return internal(&ctx.rid);
    };
    match projdb::update(&client, ctx.project.id, &upd).await {
        Ok(Some(p)) => Json(p).into_response(),
        Ok(None) => not_found(&ctx.rid),
        Err(_) => internal(&ctx.rid),
    }
}

/// `DELETE /api/v1/projects/{project_id}`
#[utoipa::path(delete, path = "/api/v1/projects/{project_id}",
    responses((status = 204), (status = 403), (status = 404)))]
pub async fn delete_project(
    State(state): State<AppState>,
    ctx: ProjectContext,
    headers: axum::http::HeaderMap,
) -> Response {
    if let Err(r) = ctx.require(Permission::ProjectDelete) {
        return r;
    }
    let auth = state.auth();
    let Ok(client) = auth.db.pool.get().await else {
        return internal(&ctx.rid);
    };
    match projdb::soft_delete(&client, ctx.project.id).await {
        Ok(true) => {
            audit::record(
                &client,
                Some(ctx.actor_id),
                "project_deleted",
                Some(client_ip(&headers)),
                Some(&user_agent(&headers)),
                &json!({ "project_id": ctx.project.id.to_string() }),
            )
            .await;
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => not_found(&ctx.rid),
        Err(_) => internal(&ctx.rid),
    }
}

// --------------------------------------------------------------------------
// roles
// --------------------------------------------------------------------------

/// `GET /api/v1/projects/{project_id}/roles`
pub async fn list_roles(State(state): State<AppState>, ctx: ProjectContext) -> Response {
    if let Err(r) = ctx.require(Permission::RoleView) {
        return r;
    }
    let auth = state.auth();
    let Ok(client) = auth.db.pool.get().await else {
        return internal(&ctx.rid);
    };
    match roledb::list_for_project(&client, ctx.project.id).await {
        Ok(roles) => Json(json!({ "roles": roles })).into_response(),
        Err(_) => internal(&ctx.rid),
    }
}

/// `POST /api/v1/projects/{project_id}/roles`
pub async fn create_role(
    State(state): State<AppState>,
    ctx: ProjectContext,
    body: Result<Json<CreateRoleRequest>, JsonRejection>,
) -> Response {
    if let Err(r) = ctx.require(Permission::RoleCreate) {
        return r;
    }
    let req = match parse_body(body, &ctx.rid) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let auth = state.auth();
    let Ok(client) = auth.db.pool.get().await else {
        return internal(&ctx.rid);
    };
    match roledb::create(
        &client,
        ctx.project.id,
        &req.slug,
        &req.name,
        100,
        &req.permissions,
    )
    .await
    {
        Ok(role) => (StatusCode::CREATED, Json(role)).into_response(),
        Err(e) if e.is_unique_violation() => conflict(&ctx.rid, "role slug already exists"),
        Err(_) => internal(&ctx.rid),
    }
}

/// `PATCH /api/v1/projects/{project_id}/roles/{role_id}`
pub async fn update_role(
    State(state): State<AppState>,
    ctx: ProjectContext,
    Path(params): Path<HashMap<String, String>>,
    headers: axum::http::HeaderMap,
    body: Result<Json<UpdateRoleRequest>, JsonRejection>,
) -> Response {
    if let Err(r) = ctx.require(Permission::RoleModify) {
        return r;
    }
    let Some(role_id) = params.get("role_id").and_then(|s| Uuid::parse_str(s).ok()) else {
        return not_found(&ctx.rid);
    };
    let req = match parse_body(body, &ctx.rid) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let auth = state.auth();
    let Ok(client) = auth.db.pool.get().await else {
        return internal(&ctx.rid);
    };
    match roledb::update_permissions(
        &client,
        ctx.project.id,
        role_id,
        req.name.as_deref(),
        req.permissions.as_deref(),
    )
    .await
    {
        Ok(Some(role)) => {
            audit::record(
                &client,
                Some(ctx.actor_id),
                "role_modified",
                Some(client_ip(&headers)),
                Some(&user_agent(&headers)),
                &json!({ "role_id": role_id.to_string() }),
            )
            .await;
            Json(role).into_response()
        }
        Ok(None) => not_found(&ctx.rid),
        Err(_) => internal(&ctx.rid),
    }
}

/// `DELETE /api/v1/projects/{project_id}/roles/{role_id}`
pub async fn delete_role(
    State(state): State<AppState>,
    ctx: ProjectContext,
    Path(params): Path<HashMap<String, String>>,
) -> Response {
    if let Err(r) = ctx.require(Permission::RoleDelete) {
        return r;
    }
    let Some(role_id) = params.get("role_id").and_then(|s| Uuid::parse_str(s).ok()) else {
        return not_found(&ctx.rid);
    };
    let auth = state.auth();
    let Ok(client) = auth.db.pool.get().await else {
        return internal(&ctx.rid);
    };
    match roledb::delete(&client, ctx.project.id, role_id).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => not_found(&ctx.rid),
        // FK violation: role still has members.
        Err(e) if matches!(&e, intellipilot_db::DbError::Postgres(_)) => {
            conflict(&ctx.rid, "role still has members")
        }
        Err(_) => internal(&ctx.rid),
    }
}

// --------------------------------------------------------------------------
// members
// --------------------------------------------------------------------------

/// `GET /api/v1/projects/{project_id}/members`
pub async fn list_members(State(state): State<AppState>, ctx: ProjectContext) -> Response {
    if let Err(r) = ctx.require(Permission::MemberView) {
        return r;
    }
    let auth = state.auth();
    let Ok(client) = auth.db.pool.get().await else {
        return internal(&ctx.rid);
    };
    match memdb::list_for_project(&client, ctx.project.id).await {
        Ok(members) => Json(json!({ "members": members })).into_response(),
        Err(_) => internal(&ctx.rid),
    }
}

/// `PATCH /api/v1/projects/{project_id}/members/{user_id}` — change role.
pub async fn change_member_role(
    State(state): State<AppState>,
    ctx: ProjectContext,
    Path(params): Path<HashMap<String, String>>,
    headers: axum::http::HeaderMap,
    body: Result<Json<ChangeMemberRoleRequest>, JsonRejection>,
) -> Response {
    if let Err(r) = ctx.require(Permission::MemberModifyRole) {
        return r;
    }
    let Some(target) = params.get("user_id").and_then(|s| Uuid::parse_str(s).ok()) else {
        return not_found(&ctx.rid);
    };
    let req = match parse_body(body, &ctx.rid) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let auth = state.auth();
    let Ok(client) = auth.db.pool.get().await else {
        return internal(&ctx.rid);
    };
    let Ok(Some(role)) = roledb::find_by_slug(&client, ctx.project.id, &req.role).await else {
        return problem(
            StatusCode::UNPROCESSABLE_ENTITY,
            "unknown_role",
            "Unknown role",
            None,
            &ctx.rid,
        );
    };

    // Don't allow demoting the last admin.
    if let Ok(Some(target_access)) = memdb::access(&client, ctx.project.id, target).await {
        if target_access.is_admin
            && !role.is_admin
            && memdb::admin_count(&client, ctx.project.id)
                .await
                .unwrap_or(0)
                <= 1
        {
            return conflict(&ctx.rid, "cannot demote the last admin");
        }
    }

    match memdb::change_role(&client, ctx.project.id, target, role.id).await {
        Ok(true) => {
            audit::record(
                &client,
                Some(ctx.actor_id),
                "member_role_changed",
                Some(client_ip(&headers)),
                Some(&user_agent(&headers)),
                &json!({ "user_id": target.to_string(), "role": req.role }),
            )
            .await;
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => not_found(&ctx.rid),
        Err(_) => internal(&ctx.rid),
    }
}

/// `DELETE /api/v1/projects/{project_id}/members/{user_id}`
pub async fn remove_member(
    State(state): State<AppState>,
    ctx: ProjectContext,
    Path(params): Path<HashMap<String, String>>,
    headers: axum::http::HeaderMap,
) -> Response {
    let Some(target) = params.get("user_id").and_then(|s| Uuid::parse_str(s).ok()) else {
        return not_found(&ctx.rid);
    };
    // Self-removal (leave) is always allowed; removing others needs the perm.
    if target != ctx.actor_id {
        if let Err(r) = ctx.require(Permission::MemberRemove) {
            return r;
        }
    }
    let auth = state.auth();
    let Ok(client) = auth.db.pool.get().await else {
        return internal(&ctx.rid);
    };

    // Never remove the last admin.
    if let Ok(Some(target_access)) = memdb::access(&client, ctx.project.id, target).await {
        if target_access.is_admin
            && memdb::admin_count(&client, ctx.project.id)
                .await
                .unwrap_or(0)
                <= 1
        {
            return conflict(&ctx.rid, "cannot remove the last admin");
        }
    }

    match memdb::remove(&client, ctx.project.id, target).await {
        Ok(true) => {
            audit::record(
                &client,
                Some(ctx.actor_id),
                "member_removed",
                Some(client_ip(&headers)),
                Some(&user_agent(&headers)),
                &json!({ "user_id": target.to_string() }),
            )
            .await;
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => not_found(&ctx.rid),
        Err(_) => internal(&ctx.rid),
    }
}

// --------------------------------------------------------------------------
// invitations
// --------------------------------------------------------------------------

/// `POST /api/v1/projects/{project_id}/invitations`
pub async fn invite(
    State(state): State<AppState>,
    ctx: ProjectContext,
    headers: axum::http::HeaderMap,
    body: Result<Json<InviteRequest>, JsonRejection>,
) -> Response {
    if let Err(r) = ctx.require(Permission::MemberAdd) {
        return r;
    }
    let req = match parse_body(body, &ctx.rid) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let auth = state.auth();
    let Ok(client) = auth.db.pool.get().await else {
        return internal(&ctx.rid);
    };
    let Ok(Some(role)) = roledb::find_by_slug(&client, ctx.project.id, &req.role).await else {
        return problem(
            StatusCode::UNPROCESSABLE_ENTITY,
            "unknown_role",
            "Unknown role",
            None,
            &ctx.rid,
        );
    };

    let token = refresh::generate();
    let expires = OffsetDateTime::now_utc() + TimeDuration::seconds(INVITE_TTL_SECS);
    let invitation_id = match invdb::create(
        &client,
        ctx.project.id,
        &req.email,
        role.id,
        &token.hash,
        Some(ctx.actor_id),
        expires,
    )
    .await
    {
        Ok(id) => id,
        Err(_) => return internal(&ctx.rid),
    };
    audit::record(
        &client,
        Some(ctx.actor_id),
        "member_invited",
        Some(client_ip(&headers)),
        Some(&user_agent(&headers)),
        &json!({ "email": req.email, "role": req.role }),
    )
    .await;

    // Mailer is off by default; surface the raw token in dev only.
    let invite_token =
        (!auth.mailer.is_configured() && auth.config.env.is_dev()).then(|| token.raw.clone());
    (
        StatusCode::CREATED,
        Json(InviteResponse {
            invitation_id,
            invite_token,
        }),
    )
        .into_response()
}

/// `GET /api/v1/projects/{project_id}/invitations`
pub async fn list_invitations(State(state): State<AppState>, ctx: ProjectContext) -> Response {
    if let Err(r) = ctx.require(Permission::MemberView) {
        return r;
    }
    let auth = state.auth();
    let Ok(client) = auth.db.pool.get().await else {
        return internal(&ctx.rid);
    };
    match invdb::list_pending(&client, ctx.project.id).await {
        Ok(invs) => Json(json!({ "invitations": invs })).into_response(),
        Err(_) => internal(&ctx.rid),
    }
}

/// `POST /api/v1/invitations/accept` — accept an invitation as the caller.
#[utoipa::path(post, path = "/api/v1/invitations/accept", request_body = AcceptInviteRequest,
    responses((status = 200), (status = 410)))]
pub async fn accept_invitation(
    State(state): State<AppState>,
    user: AuthUser,
    headers: axum::http::HeaderMap,
    body: Result<Json<AcceptInviteRequest>, JsonRejection>,
) -> Response {
    let rid = request_id(&headers);
    let auth = state.auth();
    let req = match parse_body(body, &rid) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let Ok(client) = auth.db.pool.get().await else {
        return internal(&rid);
    };
    let token_hash = refresh::hash_token(&req.token);

    let pending = match invdb::find_pending(&client, &token_hash).await {
        Ok(p) => p,
        Err(_) => return internal(&rid),
    };
    let Some(inv) = pending else {
        // Distinguish "never existed" (404) from "already used/expired" (410).
        return match invdb::exists(&client, &token_hash).await {
            Ok(true) => problem(
                StatusCode::GONE,
                "invitation_consumed",
                "Invitation no longer valid",
                None,
                &rid,
            ),
            _ => not_found(&rid),
        };
    };

    // Consume atomically (single-use).
    match invdb::mark_accepted(&client, &token_hash).await {
        Ok(true) => {}
        Ok(false) => {
            return problem(
                StatusCode::GONE,
                "invitation_consumed",
                "Invitation no longer valid",
                None,
                &rid,
            );
        }
        Err(_) => return internal(&rid),
    }

    if memdb::upsert(&client, inv.project_id, user.user_id, inv.role_id, None)
        .await
        .is_err()
    {
        return internal(&rid);
    }
    audit::record(
        &client,
        Some(user.user_id),
        "membership_granted",
        Some(client_ip(&headers)),
        Some(&user_agent(&headers)),
        &json!({ "project_id": inv.project_id.to_string() }),
    )
    .await;

    Json(json!({ "status": "joined", "project_id": inv.project_id })).into_response()
}
