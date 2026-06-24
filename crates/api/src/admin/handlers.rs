//! Platform-admin HTTP handlers (V011).
//!
//! All endpoints below are gated by [`crate::auth::SuperadminUser`]. The
//! extractor returns 401 if not authenticated and 403 if authenticated but
//! not a superadmin, so handlers can assume the caller is authorised.
#![allow(clippy::arithmetic_side_effects, clippy::result_large_err)]

use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::extract::{Multipart, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use garde::Validate;
use intellipilot_auth::app_token;
use intellipilot_auth::password::hash_password;
use intellipilot_auth::refresh;
use intellipilot_core::user::{NewUser, NewUserWithFlags};
use intellipilot_db::app_tokens as appdb;
use intellipilot_db::ldap_settings::{self, LdapSettingsUpdate};
use intellipilot_db::notification_settings::{self, NotificationSettingsUpdate};
use intellipilot_db::platform_invitations::{self, PlatformInviteRole};
use intellipilot_db::platform_settings;
use intellipilot_db::users::{self, AdminUpdateOutcome, ListFilter};
use intellipilot_db::{audit, password_reset};
use rand::Rng;
use rand::distributions::Alphanumeric;
use serde::Deserialize;
use serde_json::json;
use time::{Duration as TimeDuration, OffsetDateTime};
use uuid::Uuid;

use crate::admin::dto::{
    CreateAppTokenRequest, CreateAppTokenResponse, CreateInvitationRequest,
    CreateInvitationResponse, CreateUserRequest, CreateUserResponse, LdapSettingsResponse,
    NotificationSettingsResponse, NotificationTestResponse, PasswordResetIssuedResponse,
    PendingInvitation, PlatformSettingsResponse, TestLdapRequest, TestLdapResponse,
    TestMailRequest, UpdateAppTokenRequest, UpdateBrandingRequest, UpdateLdapSettingsRequest,
    UpdateNotificationSettingsRequest, UpdateSettingsRequest, UpdateUserRequest, UserListResponse,
};
use crate::auth::{SuperadminUser, client_ip, request_id, user_agent};
use crate::ldap::{LdapAuthenticator, LdapConfig, LdapError, RealLdap};
use crate::problem::Problem;
use crate::state::{AppState, AuthContext};

/// Platform invitations expire after 7 days, matching project invitations.
const PLATFORM_INVITE_TTL_SECS: i64 = 7 * 24 * 60 * 60;
/// Admin-initiated password reset tokens live one hour.
const RESET_TTL_SECS: i64 = 60 * 60;
/// Server-generated temporary password length.
const GENERATED_PASSWORD_LEN: usize = 24;

// ---------------------------------------------------------------------------
// Local helpers (kept independent of crate::auth::handlers so each module
// owns its own response shaping).
// ---------------------------------------------------------------------------

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

fn parse_json<T: serde::de::DeserializeOwned>(
    body: Result<Json<T>, JsonRejection>,
    rid: &str,
) -> Result<T, Response> {
    match body {
        Ok(Json(v)) => Ok(v),
        Err(JsonRejection::MissingJsonContentType(_)) => Err(problem(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "unsupported_media_type",
            "Unsupported Media Type",
            Some("expected application/json".to_owned()),
            rid,
        )),
        Err(e) => {
            tracing::warn!(request_id = %rid, error = %e, "request body parse failed");
            Err(problem(
                StatusCode::BAD_REQUEST,
                "invalid_body",
                "Invalid Request Body",
                Some("could not parse JSON".to_owned()),
                rid,
            ))
        }
    }
}

fn validation_problem(report: &garde::Report, rid: &str) -> Response {
    use intellipilot_core::error::FieldError;
    let errors: Vec<FieldError> = report
        .iter()
        .map(|(path, err)| FieldError {
            field: path.to_string(),
            code: "invalid".to_owned(),
            message: err.to_string(),
        })
        .collect();
    let summary = errors
        .iter()
        .map(|e| format!("{}: {}", e.field, e.message))
        .collect::<Vec<_>>()
        .join("; ");
    tracing::warn!(request_id = %rid, fields = %summary, "request validation failed");
    Problem::new(
        StatusCode::UNPROCESSABLE_ENTITY,
        "validation_failed",
        "Validation failed",
        None,
        rid,
    )
    .with_errors(errors)
    .into_response_with_status(StatusCode::UNPROCESSABLE_ENTITY)
}

fn pepper_bytes(auth: &AuthContext) -> Option<&[u8]> {
    auth.pepper.as_deref().map(Vec::as_slice)
}

fn outcome_to_response(rid: &str, outcome: AdminUpdateOutcome) -> Option<Response> {
    match outcome {
        AdminUpdateOutcome::Updated => None,
        AdminUpdateOutcome::NotFound => Some(problem(
            StatusCode::NOT_FOUND,
            "not_found",
            "Not Found",
            None,
            rid,
        )),
        AdminUpdateOutcome::LastSuperadmin => Some(problem(
            StatusCode::CONFLICT,
            "last_superadmin",
            "Last superadmin",
            Some(
                "the requested change would leave the platform with no active superadmin"
                    .to_owned(),
            ),
            rid,
        )),
    }
}

fn random_password() -> String {
    let mut rng = rand::thread_rng();
    (0..GENERATED_PASSWORD_LEN)
        .map(|_| rng.sample(Alphanumeric) as char)
        .collect()
}

// ===========================================================================
// Users
// ===========================================================================

#[derive(Debug, Deserialize)]
pub struct ListUsersQuery {
    #[serde(default)]
    pub q: Option<String>,
    #[serde(default)]
    pub limit: Option<u32>,
    #[serde(default)]
    pub offset: Option<u32>,
}

/// Query params for the activity log.
#[derive(Debug, Deserialize)]
pub struct ListActivityQuery {
    /// Optional exact `action` filter (e.g. `login_failure`).
    #[serde(default)]
    pub action: Option<String>,
    #[serde(default)]
    pub limit: Option<u32>,
    #[serde(default)]
    pub offset: Option<u32>,
}

/// `GET /api/v1/admin/activity` — universal activity log (auth attempts and
/// other recorded events), newest first. Superadmin only.
pub async fn list_activity(
    State(state): State<AppState>,
    headers: HeaderMap,
    _admin: SuperadminUser,
    Query(q): Query<ListActivityQuery>,
) -> Response {
    let rid = request_id(&headers);
    let auth = state.auth();
    let Ok(client) = auth.db.pool.get().await else {
        return internal(&rid);
    };
    let limit = q.limit.unwrap_or(50).clamp(1, 200);
    let offset = q.offset.unwrap_or(0);
    let action = q.action.filter(|s| !s.is_empty());
    let action_ref = action.as_deref();
    let Ok(items) = audit::list(&client, action_ref, i64::from(limit), i64::from(offset)).await
    else {
        return internal(&rid);
    };
    let total = audit::count(&client, action_ref).await.unwrap_or(0);
    Json(crate::admin::dto::ActivityListResponse {
        items,
        total,
        limit,
        offset,
    })
    .into_response()
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/users",
    params(
        ("q" = Option<String>, Query, description = "case-insensitive substring search over email + username + full_name"),
        ("limit" = Option<u32>, Query, description = "page size, 1..=200, default 50"),
        ("offset" = Option<u32>, Query, description = "skip count, default 0"),
    ),
    responses((status = 200, body = UserListResponse), (status = 401), (status = 403))
)]
pub async fn list_users(
    State(state): State<AppState>,
    headers: HeaderMap,
    _admin: SuperadminUser,
    Query(q): Query<ListUsersQuery>,
) -> Response {
    let rid = request_id(&headers);
    let auth = state.auth();
    let Ok(client) = auth.db.pool.get().await else {
        return internal(&rid);
    };
    let filter = ListFilter {
        q: q.q.filter(|s| !s.is_empty()),
        limit: q.limit.unwrap_or(50),
        offset: q.offset.unwrap_or(0),
    };
    match users::list(&client, &filter).await {
        Ok((items, total)) => Json(UserListResponse {
            items,
            total,
            limit: filter.limit.clamp(1, 200),
            offset: filter.offset,
        })
        .into_response(),
        Err(_) => internal(&rid),
    }
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/users",
    request_body = CreateUserRequest,
    responses(
        (status = 201, body = CreateUserResponse),
        (status = 401),
        (status = 403),
        (status = 409),
        (status = 422),
    )
)]
pub async fn create_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    admin: SuperadminUser,
    body: Result<Json<CreateUserRequest>, JsonRejection>,
) -> Response {
    let rid = request_id(&headers);
    let auth = state.auth();
    let req = match parse_json(body, &rid) {
        Ok(v) => v,
        Err(r) => return r,
    };
    if let Err(report) = req.validate() {
        return validation_problem(&report, &rid);
    }

    // Decide whether the admin supplied a password or we generate one.
    let (password, generated) = req
        .password
        .as_deref()
        .filter(|s| !s.is_empty())
        .map_or_else(
            || {
                let p = random_password();
                (p.clone(), Some(p))
            },
            |p| (p.to_owned(), None),
        );
    // No zxcvbn check on admin-set passwords — we trust the admin's judgement
    // and the temp password will be force-rotated on first login anyway.

    let Ok(hash) = hash_password(&password, pepper_bytes(auth)) else {
        return internal(&rid);
    };

    let Ok(client) = auth.db.pool.get().await else {
        return internal(&rid);
    };

    let new = NewUserWithFlags {
        new: NewUser {
            email: req.email.clone(),
            username: req.username.clone(),
            full_name: req.full_name.clone(),
            password_hash: hash,
        },
        is_superadmin: req.is_superadmin,
        // Force a rotation when we generated the password OR when no password
        // was supplied by the admin (we generated it). Admins who explicitly
        // type a password still see the new user with the flag set so the
        // user knows to change it.
        must_change_password: true,
    };
    match users::create_with_flags(&client, &new).await {
        Ok(user) => {
            audit::record(
                &client,
                Some(admin.user_id),
                "admin_user_created",
                Some(client_ip(&headers)),
                Some(&user_agent(&headers)),
                &json!({ "target_user_id": user.id, "is_superadmin": user.is_superadmin }),
            )
            .await;
            (
                StatusCode::CREATED,
                Json(CreateUserResponse {
                    user,
                    generated_password: generated,
                }),
            )
                .into_response()
        }
        Err(e) if e.is_unique_violation() => problem(
            StatusCode::CONFLICT,
            "already_exists",
            "Already Exists",
            Some("email or username is already taken".to_owned()),
            &rid,
        ),
        Err(_) => internal(&rid),
    }
}

#[utoipa::path(
    patch,
    path = "/api/v1/admin/users/{id}",
    request_body = UpdateUserRequest,
    responses(
        (status = 200, body = intellipilot_core::user::User),
        (status = 401),
        (status = 403),
        (status = 404),
        (status = 409, description = "would leave the platform without a superadmin"),
        (status = 422),
    )
)]
pub async fn update_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    admin: SuperadminUser,
    Path(id): Path<Uuid>,
    body: Result<Json<UpdateUserRequest>, JsonRejection>,
) -> Response {
    let rid = request_id(&headers);
    let auth = state.auth();
    let req = match parse_json(body, &rid) {
        Ok(v) => v,
        Err(r) => return r,
    };
    if let Err(report) = req.validate() {
        return validation_problem(&report, &rid);
    }

    let Ok(mut client) = auth.db.pool.get().await else {
        return internal(&rid);
    };

    // Apply each requested update in sequence, surfacing the first failure.
    if let Some(value) = req.is_superadmin {
        match users::set_superadmin(&mut client, id, value).await {
            Ok(outcome) => {
                if let Some(r) = outcome_to_response(&rid, outcome) {
                    return r;
                }
            }
            Err(_) => return internal(&rid),
        }
    }
    if let Some(value) = req.is_active {
        match users::set_active(&mut client, id, value).await {
            Ok(outcome) => {
                if let Some(r) = outcome_to_response(&rid, outcome) {
                    return r;
                }
            }
            Err(_) => return internal(&rid),
        }
    }
    if let Some(full_name) = req.full_name.as_deref() {
        let upd = intellipilot_core::user::ProfileUpdate {
            full_name: Some(full_name.to_owned()),
            ..Default::default()
        };
        match users::update_profile(&client, id, &upd).await {
            Ok(None) => {
                return problem(StatusCode::NOT_FOUND, "not_found", "Not Found", None, &rid);
            }
            Ok(Some(_)) => {}
            Err(_) => return internal(&rid),
        }
    }

    // Re-fetch the canonical user state to return.
    let Ok(updated) = users::find_by_id(&client, id).await else {
        return internal(&rid);
    };
    let Some(updated) = updated else {
        return problem(StatusCode::NOT_FOUND, "not_found", "Not Found", None, &rid);
    };
    audit::record(
        &client,
        Some(admin.user_id),
        "admin_user_updated",
        Some(client_ip(&headers)),
        Some(&user_agent(&headers)),
        &json!({
            "target_user_id": id,
            "is_superadmin": req.is_superadmin,
            "is_active": req.is_active,
            "full_name_changed": req.full_name.is_some(),
        }),
    )
    .await;
    Json(updated).into_response()
}

#[utoipa::path(
    delete,
    path = "/api/v1/admin/users/{id}",
    responses(
        (status = 204),
        (status = 401),
        (status = 403),
        (status = 404),
        (status = 409, description = "would leave the platform without a superadmin"),
    )
)]
pub async fn delete_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    admin: SuperadminUser,
    Path(id): Path<Uuid>,
) -> Response {
    let rid = request_id(&headers);
    let auth = state.auth();
    let Ok(mut client) = auth.db.pool.get().await else {
        return internal(&rid);
    };
    let grace_until = OffsetDateTime::now_utc() + TimeDuration::days(30);
    match users::soft_delete_guarded(&mut client, id, grace_until).await {
        Ok(AdminUpdateOutcome::Updated) => {
            audit::record(
                &client,
                Some(admin.user_id),
                "admin_user_deleted",
                Some(client_ip(&headers)),
                Some(&user_agent(&headers)),
                &json!({ "target_user_id": id }),
            )
            .await;
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(other) => outcome_to_response(&rid, other).unwrap_or_else(|| internal(&rid)),
        Err(_) => internal(&rid),
    }
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/users/{id}/reset-password",
    responses(
        (status = 201, body = PasswordResetIssuedResponse),
        (status = 401),
        (status = 403),
        (status = 404),
    )
)]
pub async fn reset_password(
    State(state): State<AppState>,
    headers: HeaderMap,
    admin: SuperadminUser,
    Path(id): Path<Uuid>,
) -> Response {
    let rid = request_id(&headers);
    let auth = state.auth();
    let Ok(client) = auth.db.pool.get().await else {
        return internal(&rid);
    };
    let user = match users::find_by_id(&client, id).await {
        Ok(Some(u)) => u,
        Ok(None) => {
            return problem(StatusCode::NOT_FOUND, "not_found", "Not Found", None, &rid);
        }
        Err(_) => return internal(&rid),
    };

    let token = refresh::generate();
    let expires_at = OffsetDateTime::now_utc() + TimeDuration::seconds(RESET_TTL_SECS);
    if password_reset::create(&client, user.id, &token.hash, expires_at)
        .await
        .is_err()
    {
        return internal(&rid);
    }

    audit::record(
        &client,
        Some(admin.user_id),
        "admin_password_reset_issued",
        Some(client_ip(&headers)),
        Some(&user_agent(&headers)),
        &json!({ "target_user_id": id }),
    )
    .await;

    // Reveal the raw token only when the mailer is not configured (dev). In
    // production we expect the mailer to deliver a reset link to the user.
    let reset_token =
        (!auth.mailer.is_configured() && auth.config.env.is_dev()).then(|| token.raw.clone());

    (
        StatusCode::CREATED,
        Json(PasswordResetIssuedResponse {
            reset_token,
            expires_at,
        }),
    )
        .into_response()
}

// ===========================================================================
// Invitations
// ===========================================================================

#[utoipa::path(
    post,
    path = "/api/v1/admin/invitations",
    request_body = CreateInvitationRequest,
    responses(
        (status = 201, body = CreateInvitationResponse),
        (status = 401),
        (status = 403),
        (status = 422),
    )
)]
pub async fn create_invitation(
    State(state): State<AppState>,
    headers: HeaderMap,
    admin: SuperadminUser,
    body: Result<Json<CreateInvitationRequest>, JsonRejection>,
) -> Response {
    let rid = request_id(&headers);
    let auth = state.auth();
    let req = match parse_json(body, &rid) {
        Ok(v) => v,
        Err(r) => return r,
    };
    if let Err(report) = req.validate() {
        return validation_problem(&report, &rid);
    }
    let Some(role) = PlatformInviteRole::parse(&req.role) else {
        return problem(
            StatusCode::UNPROCESSABLE_ENTITY,
            "unknown_role",
            "Unknown role",
            Some("role must be 'user' or 'superadmin'".to_owned()),
            &rid,
        );
    };

    let Ok(client) = auth.db.pool.get().await else {
        return internal(&rid);
    };

    let token = refresh::generate();
    let expires_at = OffsetDateTime::now_utc() + TimeDuration::seconds(PLATFORM_INVITE_TTL_SECS);
    let Ok(invitation_id) = platform_invitations::create(
        &client,
        &req.email,
        role,
        &token.hash,
        Some(admin.user_id),
        expires_at,
    )
    .await
    else {
        return internal(&rid);
    };

    audit::record(
        &client,
        Some(admin.user_id),
        "admin_invitation_created",
        Some(client_ip(&headers)),
        Some(&user_agent(&headers)),
        &json!({ "email": req.email, "role": role.as_str() }),
    )
    .await;

    let invite_token =
        (!auth.mailer.is_configured() && auth.config.env.is_dev()).then(|| token.raw.clone());

    (
        StatusCode::CREATED,
        Json(CreateInvitationResponse {
            invitation_id,
            email: req.email,
            role: role.as_str().to_owned(),
            expires_at,
            invite_token,
        }),
    )
        .into_response()
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/invitations",
    responses((status = 200, body = Vec<PendingInvitation>), (status = 401), (status = 403))
)]
pub async fn list_invitations(
    State(state): State<AppState>,
    headers: HeaderMap,
    _admin: SuperadminUser,
) -> Response {
    let rid = request_id(&headers);
    let auth = state.auth();
    let Ok(client) = auth.db.pool.get().await else {
        return internal(&rid);
    };
    platform_invitations::list_pending(&client)
        .await
        .map_or_else(
            |_| internal(&rid),
            |items| {
                let mapped: Vec<PendingInvitation> = items
                    .into_iter()
                    .map(|i| PendingInvitation {
                        id: i.id,
                        email: i.email,
                        role: i.role.as_str().to_owned(),
                        invited_by: i.invited_by,
                        expires_at: i.expires_at,
                        created_at: i.created_at,
                    })
                    .collect();
                Json(mapped).into_response()
            },
        )
}

#[utoipa::path(
    delete,
    path = "/api/v1/admin/invitations/{id}",
    responses(
        (status = 204),
        (status = 401),
        (status = 403),
        (status = 404),
    )
)]
pub async fn revoke_invitation(
    State(state): State<AppState>,
    headers: HeaderMap,
    admin: SuperadminUser,
    Path(id): Path<Uuid>,
) -> Response {
    let rid = request_id(&headers);
    let auth = state.auth();
    let Ok(client) = auth.db.pool.get().await else {
        return internal(&rid);
    };
    match platform_invitations::revoke(&client, id).await {
        Ok(true) => {
            audit::record(
                &client,
                Some(admin.user_id),
                "admin_invitation_revoked",
                Some(client_ip(&headers)),
                Some(&user_agent(&headers)),
                &json!({ "invitation_id": id }),
            )
            .await;
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => problem(StatusCode::NOT_FOUND, "not_found", "Not Found", None, &rid),
        Err(_) => internal(&rid),
    }
}

// ===========================================================================
// App tokens (V004)
// ===========================================================================

/// True when every id in `ids` names an existing project. `ids` must be
/// de-duplicated by the caller.
async fn projects_all_exist(
    client: &deadpool_postgres::Client,
    ids: &[Uuid],
) -> Result<bool, intellipilot_db::DbError> {
    if ids.is_empty() {
        return Ok(true);
    }
    let row = client
        .query_one(
            "SELECT count(*)::bigint AS n FROM projects WHERE id = ANY($1)",
            &[&ids],
        )
        .await?;
    Ok(usize::try_from(row.get::<_, i64>("n")).unwrap_or(0) == ids.len())
}

fn unknown_project(rid: &str) -> Response {
    problem(
        StatusCode::UNPROCESSABLE_ENTITY,
        "unknown_project",
        "Unknown project",
        Some("one or more project_ids do not exist".to_owned()),
        rid,
    )
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/app-tokens",
    request_body = CreateAppTokenRequest,
    responses(
        (status = 201, body = CreateAppTokenResponse),
        (status = 401),
        (status = 403),
        (status = 422),
    )
)]
pub async fn create_app_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    admin: SuperadminUser,
    body: Result<Json<CreateAppTokenRequest>, JsonRejection>,
) -> Response {
    let rid = request_id(&headers);
    let auth = state.auth();
    let req = match parse_json(body, &rid) {
        Ok(v) => v,
        Err(r) => return r,
    };
    if let Err(report) = req.validate() {
        return validation_problem(&report, &rid);
    }
    let mut project_ids = req.project_ids.clone();
    project_ids.sort();
    project_ids.dedup();

    let Ok(mut client) = auth.db.pool.get().await else {
        return internal(&rid);
    };
    match projects_all_exist(&client, &project_ids).await {
        Ok(true) => {}
        Ok(false) => return unknown_project(&rid),
        Err(_) => return internal(&rid),
    }

    let minted = app_token::generate();
    let Ok(id) = appdb::create(
        &mut client,
        &req.name,
        &minted.hash,
        &minted.prefix,
        &minted.last4,
        &req.permissions,
        Some(admin.user_id),
        req.expires_at,
        &project_ids,
    )
    .await
    else {
        return internal(&rid);
    };
    let Ok(Some(token)) = appdb::get(&client, id).await else {
        return internal(&rid);
    };

    audit::record(
        &client,
        Some(admin.user_id),
        "admin_app_token_created",
        Some(client_ip(&headers)),
        Some(&user_agent(&headers)),
        &json!({ "app_token_id": id, "name": req.name }),
    )
    .await;

    (
        StatusCode::CREATED,
        Json(CreateAppTokenResponse {
            token,
            secret: minted.raw,
        }),
    )
        .into_response()
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/app-tokens",
    responses(
        (status = 200, body = Vec<intellipilot_core::app_token::AppToken>),
        (status = 401),
        (status = 403),
    )
)]
pub async fn list_app_tokens(
    State(state): State<AppState>,
    headers: HeaderMap,
    _admin: SuperadminUser,
) -> Response {
    let rid = request_id(&headers);
    let auth = state.auth();
    let Ok(client) = auth.db.pool.get().await else {
        return internal(&rid);
    };
    appdb::list(&client)
        .await
        .map_or_else(|_| internal(&rid), |items| Json(items).into_response())
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/app-tokens/{id}",
    responses(
        (status = 200, body = intellipilot_core::app_token::AppToken),
        (status = 401),
        (status = 403),
        (status = 404),
    )
)]
pub async fn get_app_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    _admin: SuperadminUser,
    Path(id): Path<Uuid>,
) -> Response {
    let rid = request_id(&headers);
    let auth = state.auth();
    let Ok(client) = auth.db.pool.get().await else {
        return internal(&rid);
    };
    match appdb::get(&client, id).await {
        Ok(Some(token)) => Json(token).into_response(),
        Ok(None) => problem(StatusCode::NOT_FOUND, "not_found", "Not Found", None, &rid),
        Err(_) => internal(&rid),
    }
}

#[utoipa::path(
    patch,
    path = "/api/v1/admin/app-tokens/{id}",
    request_body = UpdateAppTokenRequest,
    responses(
        (status = 200, body = intellipilot_core::app_token::AppToken),
        (status = 401),
        (status = 403),
        (status = 404),
        (status = 422),
    )
)]
pub async fn update_app_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    admin: SuperadminUser,
    Path(id): Path<Uuid>,
    body: Result<Json<UpdateAppTokenRequest>, JsonRejection>,
) -> Response {
    let rid = request_id(&headers);
    let auth = state.auth();
    let req = match parse_json(body, &rid) {
        Ok(v) => v,
        Err(r) => return r,
    };
    if let Err(report) = req.validate() {
        return validation_problem(&report, &rid);
    }
    let deduped: Option<Vec<Uuid>> = req.project_ids.clone().map(|mut v| {
        v.sort();
        v.dedup();
        v
    });

    let Ok(mut client) = auth.db.pool.get().await else {
        return internal(&rid);
    };
    if let Some(ref pids) = deduped {
        match projects_all_exist(&client, pids).await {
            Ok(true) => {}
            Ok(false) => return unknown_project(&rid),
            Err(_) => return internal(&rid),
        }
    }

    match appdb::update(
        &mut client,
        id,
        req.name.as_deref(),
        req.permissions.as_deref(),
        deduped.as_deref(),
    )
    .await
    {
        Ok(true) => {}
        Ok(false) => return problem(StatusCode::NOT_FOUND, "not_found", "Not Found", None, &rid),
        Err(_) => return internal(&rid),
    }
    let Ok(Some(token)) = appdb::get(&client, id).await else {
        return internal(&rid);
    };
    audit::record(
        &client,
        Some(admin.user_id),
        "admin_app_token_updated",
        Some(client_ip(&headers)),
        Some(&user_agent(&headers)),
        &json!({ "app_token_id": id }),
    )
    .await;
    Json(token).into_response()
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/app-tokens/{id}/revoke",
    responses(
        (status = 204),
        (status = 401),
        (status = 403),
        (status = 404),
    )
)]
pub async fn revoke_app_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    admin: SuperadminUser,
    Path(id): Path<Uuid>,
) -> Response {
    let rid = request_id(&headers);
    let auth = state.auth();
    let Ok(client) = auth.db.pool.get().await else {
        return internal(&rid);
    };
    match appdb::revoke(&client, id).await {
        Ok(true) => {
            audit::record(
                &client,
                Some(admin.user_id),
                "admin_app_token_revoked",
                Some(client_ip(&headers)),
                Some(&user_agent(&headers)),
                &json!({ "app_token_id": id }),
            )
            .await;
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => problem(StatusCode::NOT_FOUND, "not_found", "Not Found", None, &rid),
        Err(_) => internal(&rid),
    }
}

// ===========================================================================
// Settings
// ===========================================================================

/// Largest accepted custom-icon upload. Branding icons are small (a logo PNG);
/// this caps abuse well below the attachment limit.
const MAX_ICON_BYTES: usize = 1024 * 1024;

fn settings_response(s: platform_settings::PlatformSettings) -> PlatformSettingsResponse {
    PlatformSettingsResponse {
        open_registration: s.open_registration,
        app_name: s.app_name,
        app_message: s.app_message,
        has_custom_icon: s.app_icon_mime.is_some(),
        app_icon_updated_at: s.app_icon_updated_at,
        updated_at: s.updated_at,
        updated_by: s.updated_by,
    }
}

/// Normalise an optional, trimmed string: blank → `None` (clears the field).
fn normalise(value: Option<String>) -> Option<String> {
    value.map(|v| v.trim().to_owned()).filter(|v| !v.is_empty())
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/settings",
    responses((status = 200, body = PlatformSettingsResponse), (status = 401), (status = 403))
)]
pub async fn get_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
    _admin: SuperadminUser,
) -> Response {
    let rid = request_id(&headers);
    let auth = state.auth();
    let Ok(client) = auth.db.pool.get().await else {
        return internal(&rid);
    };
    platform_settings::get(&client).await.map_or_else(
        |_| internal(&rid),
        |s| Json(settings_response(s)).into_response(),
    )
}

#[utoipa::path(
    patch,
    path = "/api/v1/admin/settings",
    request_body = UpdateSettingsRequest,
    responses((status = 200, body = PlatformSettingsResponse), (status = 401), (status = 403))
)]
pub async fn update_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
    admin: SuperadminUser,
    body: Result<Json<UpdateSettingsRequest>, JsonRejection>,
) -> Response {
    let rid = request_id(&headers);
    let auth = state.auth();
    let req = match parse_json(body, &rid) {
        Ok(v) => v,
        Err(r) => return r,
    };

    let Ok(client) = auth.db.pool.get().await else {
        return internal(&rid);
    };
    match platform_settings::set_open_registration(&client, req.open_registration, admin.user_id)
        .await
    {
        Ok(s) => {
            audit::record(
                &client,
                Some(admin.user_id),
                "admin_settings_updated",
                Some(client_ip(&headers)),
                Some(&user_agent(&headers)),
                &json!({ "open_registration": req.open_registration }),
            )
            .await;
            Json(settings_response(s)).into_response()
        }
        Err(_) => internal(&rid),
    }
}

// ---------------------------------------------------------------------------
// Branding (white-label) — superadmin only
// ---------------------------------------------------------------------------

#[utoipa::path(
    patch,
    path = "/api/v1/admin/branding",
    request_body = UpdateBrandingRequest,
    responses((status = 200, body = PlatformSettingsResponse), (status = 401), (status = 403), (status = 422))
)]
pub async fn update_branding(
    State(state): State<AppState>,
    headers: HeaderMap,
    admin: SuperadminUser,
    body: Result<Json<UpdateBrandingRequest>, JsonRejection>,
) -> Response {
    let rid = request_id(&headers);
    let auth = state.auth();
    let req = match parse_json(body, &rid) {
        Ok(v) => v,
        Err(r) => return r,
    };
    if let Err(report) = req.validate() {
        return validation_problem(&report, &rid);
    }

    let app_name = normalise(req.app_name);
    let app_message = normalise(req.app_message);

    let Ok(client) = auth.db.pool.get().await else {
        return internal(&rid);
    };
    match platform_settings::set_branding(
        &client,
        app_name.as_deref(),
        app_message.as_deref(),
        admin.user_id,
    )
    .await
    {
        Ok(s) => {
            audit::record(
                &client,
                Some(admin.user_id),
                "admin_branding_updated",
                Some(client_ip(&headers)),
                Some(&user_agent(&headers)),
                &json!({ "app_name": app_name, "has_message": app_message.is_some() }),
            )
            .await;
            Json(settings_response(s)).into_response()
        }
        Err(_) => internal(&rid),
    }
}

#[utoipa::path(
    put,
    path = "/api/v1/admin/branding/icon",
    request_body(content = inline(Vec<u8>), description = "multipart/form-data with a single image file field"),
    responses((status = 200, body = PlatformSettingsResponse), (status = 401), (status = 403), (status = 413), (status = 422))
)]
pub async fn upload_branding_icon(
    State(state): State<AppState>,
    headers: HeaderMap,
    admin: SuperadminUser,
    mut multipart: Multipart,
) -> Response {
    let rid = request_id(&headers);
    let auth = state.auth();

    // Pull the first file field.
    let mut data: Option<bytes::Bytes> = None;
    loop {
        match multipart.next_field().await {
            Ok(Some(field)) => {
                let is_file = field.file_name().is_some();
                let Ok(bytes) = field.bytes().await else {
                    return problem(
                        StatusCode::PAYLOAD_TOO_LARGE,
                        "too_large",
                        "Payload Too Large",
                        Some(format!("icon exceeds {MAX_ICON_BYTES} bytes")),
                        &rid,
                    );
                };
                if is_file {
                    data = Some(bytes);
                    break;
                }
            }
            Ok(None) => break,
            Err(_) => {
                return problem(
                    StatusCode::BAD_REQUEST,
                    "invalid_multipart",
                    "Invalid multipart body",
                    None,
                    &rid,
                );
            }
        }
    }
    let Some(bytes) = data else {
        return problem(
            StatusCode::UNPROCESSABLE_ENTITY,
            "no_file",
            "No file part",
            Some("expected a file field".to_owned()),
            &rid,
        );
    };
    if bytes.len() > MAX_ICON_BYTES {
        return problem(
            StatusCode::PAYLOAD_TOO_LARGE,
            "too_large",
            "Payload Too Large",
            Some(format!("icon exceeds {MAX_ICON_BYTES} bytes")),
            &rid,
        );
    }

    // Derive MIME from magic bytes and require it to be an image; the
    // client-declared type is ignored.
    let mime = match infer::get(&bytes) {
        Some(t) if t.mime_type().starts_with("image/") => t.mime_type().to_owned(),
        _ => {
            return problem(
                StatusCode::UNPROCESSABLE_ENTITY,
                "not_an_image",
                "Unsupported icon",
                Some("the uploaded file is not a recognised image".to_owned()),
                &rid,
            );
        }
    };

    let Ok(client) = auth.db.pool.get().await else {
        return internal(&rid);
    };
    match platform_settings::set_app_icon(&client, &bytes, &mime, admin.user_id).await {
        Ok(s) => {
            audit::record(
                &client,
                Some(admin.user_id),
                "admin_branding_icon_set",
                Some(client_ip(&headers)),
                Some(&user_agent(&headers)),
                &json!({ "mime": mime, "bytes": bytes.len() }),
            )
            .await;
            Json(settings_response(s)).into_response()
        }
        Err(_) => internal(&rid),
    }
}

#[utoipa::path(
    delete,
    path = "/api/v1/admin/branding/icon",
    responses((status = 200, body = PlatformSettingsResponse), (status = 401), (status = 403))
)]
pub async fn delete_branding_icon(
    State(state): State<AppState>,
    headers: HeaderMap,
    admin: SuperadminUser,
) -> Response {
    let rid = request_id(&headers);
    let auth = state.auth();
    let Ok(client) = auth.db.pool.get().await else {
        return internal(&rid);
    };
    match platform_settings::clear_app_icon(&client, admin.user_id).await {
        Ok(s) => {
            audit::record(
                &client,
                Some(admin.user_id),
                "admin_branding_icon_cleared",
                Some(client_ip(&headers)),
                Some(&user_agent(&headers)),
                &json!({}),
            )
            .await;
            Json(settings_response(s)).into_response()
        }
        Err(_) => internal(&rid),
    }
}

// ---------------------------------------------------------------------------
// LDAP settings (superadmin only)
// ---------------------------------------------------------------------------

fn ldap_response(s: ldap_settings::LdapSettings) -> LdapSettingsResponse {
    LdapSettingsResponse {
        enabled: s.enabled,
        server_url: s.server_url,
        use_start_tls: s.use_start_tls,
        skip_tls_verify: s.skip_tls_verify,
        base_dn: s.base_dn,
        default_domain: s.default_domain,
        bind_dn_format: s.bind_dn_format,
        user_search_filter: s.user_search_filter,
        superadmin_group: s.superadmin_group,
        attr_email: s.attr_email,
        attr_display_name: s.attr_display_name,
        attr_username: s.attr_username,
        connection_timeout_secs: s.connection_timeout_secs,
        bind_mode: s.bind_mode,
        service_bind_dn: s.service_bind_dn,
        service_bind_password_set: !s.service_bind_password.is_empty(),
        user_search_base: s.user_search_base,
        group_search_base: s.group_search_base,
        group_search_filter: s.group_search_filter,
        updated_at: s.updated_at,
        updated_by: s.updated_by,
    }
}

fn ldap_update_from(req: &UpdateLdapSettingsRequest) -> LdapSettingsUpdate {
    LdapSettingsUpdate {
        enabled: req.enabled,
        server_url: req.server_url.trim().to_owned(),
        use_start_tls: req.use_start_tls,
        skip_tls_verify: req.skip_tls_verify,
        base_dn: req.base_dn.trim().to_owned(),
        default_domain: req.default_domain.trim().to_owned(),
        bind_dn_format: req.bind_dn_format.trim().to_owned(),
        user_search_filter: req.user_search_filter.trim().to_owned(),
        superadmin_group: req.superadmin_group.trim().to_owned(),
        attr_email: req.attr_email.trim().to_owned(),
        attr_display_name: req.attr_display_name.trim().to_owned(),
        attr_username: req.attr_username.trim().to_owned(),
        connection_timeout_secs: req.connection_timeout_secs,
        bind_mode: req.bind_mode.trim().to_owned(),
        service_bind_dn: req.service_bind_dn.trim().to_owned(),
        service_bind_password: keep_if_blank(req.service_bind_password.clone()),
        user_search_base: req.user_search_base.trim().to_owned(),
        group_search_base: req.group_search_base.trim().to_owned(),
        group_search_filter: req.group_search_filter.trim().to_owned(),
    }
}

fn ldap_config_of(u: &LdapSettingsUpdate) -> LdapConfig {
    LdapConfig {
        server_url: u.server_url.clone(),
        use_start_tls: u.use_start_tls,
        skip_tls_verify: u.skip_tls_verify,
        base_dn: u.base_dn.clone(),
        default_domain: u.default_domain.clone(),
        bind_dn_format: u.bind_dn_format.clone(),
        user_search_filter: u.user_search_filter.clone(),
        superadmin_group: u.superadmin_group.clone(),
        attr_email: u.attr_email.clone(),
        attr_display_name: u.attr_display_name.clone(),
        attr_username: u.attr_username.clone(),
        connection_timeout_secs: u.connection_timeout_secs,
        bind_mode: u.bind_mode.clone(),
        service_bind_dn: u.service_bind_dn.clone(),
        service_bind_password: u.service_bind_password.clone().unwrap_or_default(),
        user_search_base: u.user_search_base.clone(),
        group_search_base: u.group_search_base.clone(),
        group_search_filter: u.group_search_filter.clone(),
    }
}

fn invalid_settings(rid: &str) -> Response {
    problem(
        StatusCode::UNPROCESSABLE_ENTITY,
        "validation_failed",
        "Validation failed",
        None,
        rid,
    )
}

/// `GET /api/v1/admin/ldap-settings`
pub async fn get_ldap_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
    _admin: SuperadminUser,
) -> Response {
    let rid = request_id(&headers);
    let auth = state.auth();
    let Ok(client) = auth.db.pool.get().await else {
        return internal(&rid);
    };
    ldap_settings::get(&client).await.map_or_else(
        |_| internal(&rid),
        |s| Json(ldap_response(s)).into_response(),
    )
}

/// `PUT /api/v1/admin/ldap-settings`
pub async fn update_ldap_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
    admin: SuperadminUser,
    body: Result<Json<UpdateLdapSettingsRequest>, JsonRejection>,
) -> Response {
    let rid = request_id(&headers);
    let auth = state.auth();
    let req = match parse_json(body, &rid) {
        Ok(v) => v,
        Err(r) => return r,
    };
    if req.validate().is_err() {
        return invalid_settings(&rid);
    }
    let Ok(client) = auth.db.pool.get().await else {
        return internal(&rid);
    };
    // LDAP settings are read-only for accounts signed in via LDAP: only a
    // superadmin who signs in with a local password may change them. This
    // prevents tampering and, in particular, an LDAP-authenticated admin
    // disabling LDAP and locking themselves out (LDAP accounts have no local
    // password). The frontend enforces the same as a read-only view.
    match users::find_by_id(&client, admin.user_id).await {
        Ok(Some(me)) if me.auth_source.eq_ignore_ascii_case("ldap") => {
            return problem(
                StatusCode::FORBIDDEN,
                "ldap_readonly",
                "LDAP settings are read-only",
                Some(
                    "You are signed in via LDAP. LDAP settings can only be changed by a \
                     superadmin who signs in with a local password."
                        .to_owned(),
                ),
                &rid,
            );
        }
        Ok(_) => {}
        Err(_) => return internal(&rid),
    }
    let upd = ldap_update_from(&req);
    match ldap_settings::set(&client, &upd, admin.user_id).await {
        Ok(s) => {
            audit::record(
                &client,
                Some(admin.user_id),
                "ldap_settings_updated",
                Some(client_ip(&headers)),
                Some(&user_agent(&headers)),
                &json!({ "enabled": s.enabled, "server_url": s.server_url }),
            )
            .await;
            Json(ldap_response(s)).into_response()
        }
        Err(_) => internal(&rid),
    }
}

/// `POST /api/v1/admin/ldap-settings/test` — attempt a real bind with the given
/// (possibly unsaved) settings + credentials and report the outcome.
pub async fn test_ldap_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
    _admin: SuperadminUser,
    body: Result<Json<TestLdapRequest>, JsonRejection>,
) -> Response {
    let rid = request_id(&headers);
    let auth = state.auth();
    let req = match parse_json(body, &rid) {
        Ok(v) => v,
        Err(r) => return r,
    };
    if req.validate().is_err() {
        return invalid_settings(&rid);
    }
    let upd = ldap_update_from(&req.settings);
    let mut cfg = ldap_config_of(&upd);
    // In search mode, fall back to the stored service password when the form
    // left it blank, so admins can test without re-entering the secret.
    if cfg.bind_mode.eq_ignore_ascii_case("search")
        && cfg.service_bind_password.is_empty()
        && let Ok(client) = auth.db.pool.get().await
        && let Ok(stored) = ldap_settings::get(&client).await
    {
        cfg.service_bind_password = stored.service_bind_password;
    }
    let result = RealLdap::new(cfg)
        .authenticate(&req.username, &req.password)
        .await;
    let resp = match result {
        Ok(u) => TestLdapResponse {
            ok: true,
            message: "Bind succeeded.".to_owned(),
            email: Some(u.email),
            username: Some(u.username),
            display_name: Some(u.display_name),
            would_be_superadmin: Some(u.is_superadmin),
        },
        Err(LdapError::InvalidCredentials) => TestLdapResponse {
            ok: false,
            message: "Bind failed: invalid username or password.".to_owned(),
            email: None,
            username: None,
            display_name: None,
            would_be_superadmin: None,
        },
        // A misconfiguration (e.g. wrong service bind DN/password) is not a
        // connectivity problem — label it accordingly so admins look in the
        // right place.
        Err(LdapError::Config(msg)) => TestLdapResponse {
            ok: false,
            message: format!("Configuration error: {msg}"),
            email: None,
            username: None,
            display_name: None,
            would_be_superadmin: None,
        },
        Err(e) => TestLdapResponse {
            ok: false,
            message: format!("Connection error: {e}"),
            email: None,
            username: None,
            display_name: None,
            would_be_superadmin: None,
        },
    };
    Json(resp).into_response()
}

// Re-export the symbols the router needs.
// ---------------------------------------------------------------------------
// Notification settings (superadmin only)
// ---------------------------------------------------------------------------

fn notification_response(
    s: notification_settings::NotificationSettings,
) -> NotificationSettingsResponse {
    NotificationSettingsResponse {
        mail_enabled: s.mail_enabled,
        mail_provider: s.mail_provider,
        mail_from_address: s.mail_from_address,
        mail_from_name: s.mail_from_name,
        smtp_host: s.smtp_host,
        smtp_port: s.smtp_port,
        smtp_username: s.smtp_username,
        smtp_password_set: !s.smtp_password.is_empty(),
        smtp_use_starttls: s.smtp_use_starttls,
        smtp_skip_tls_verify: s.smtp_skip_tls_verify,
        mailgun_api_key_set: !s.mailgun_api_key.is_empty(),
        mailgun_domain: s.mailgun_domain,
        mailgun_base_url: s.mailgun_base_url,
        matrix_enabled: s.matrix_enabled,
        matrix_homeserver: s.matrix_homeserver,
        matrix_room_id: s.matrix_room_id,
        matrix_access_token_set: !s.matrix_access_token.is_empty(),
        telegram_enabled: s.telegram_enabled,
        telegram_bot_token_set: !s.telegram_bot_token.is_empty(),
        telegram_chat_id: s.telegram_chat_id,
        mail_on_login: s.mail_on_login,
        mail_on_issue_created: s.mail_on_issue_created,
        mail_on_issue_resolved: s.mail_on_issue_resolved,
        mail_on_daily_report: s.mail_on_daily_report,
        msg_on_login: s.msg_on_login,
        msg_on_issue_created: s.msg_on_issue_created,
        msg_on_issue_resolved: s.msg_on_issue_resolved,
        msg_on_daily_report: s.msg_on_daily_report,
        updated_at: s.updated_at,
        updated_by: s.updated_by,
    }
}

/// Map a secret field: an empty/absent value means "keep the stored secret".
fn keep_if_blank(v: Option<String>) -> Option<String> {
    v.filter(|s| !s.is_empty())
}

fn notification_update_from(req: UpdateNotificationSettingsRequest) -> NotificationSettingsUpdate {
    NotificationSettingsUpdate {
        mail_enabled: req.mail_enabled,
        mail_provider: req.mail_provider.trim().to_owned(),
        mail_from_address: req.mail_from_address.trim().to_owned(),
        mail_from_name: req.mail_from_name.trim().to_owned(),
        smtp_host: req.smtp_host.trim().to_owned(),
        smtp_port: req.smtp_port,
        smtp_username: req.smtp_username.trim().to_owned(),
        smtp_password: keep_if_blank(req.smtp_password),
        smtp_use_starttls: req.smtp_use_starttls,
        smtp_skip_tls_verify: req.smtp_skip_tls_verify,
        mailgun_api_key: keep_if_blank(req.mailgun_api_key),
        mailgun_domain: req.mailgun_domain.trim().to_owned(),
        mailgun_base_url: req.mailgun_base_url.trim().to_owned(),
        matrix_enabled: req.matrix_enabled,
        matrix_homeserver: req.matrix_homeserver.trim().to_owned(),
        matrix_room_id: req.matrix_room_id.trim().to_owned(),
        matrix_access_token: keep_if_blank(req.matrix_access_token),
        telegram_enabled: req.telegram_enabled,
        telegram_bot_token: keep_if_blank(req.telegram_bot_token),
        telegram_chat_id: req.telegram_chat_id.trim().to_owned(),
        mail_on_login: req.mail_on_login,
        mail_on_issue_created: req.mail_on_issue_created,
        mail_on_issue_resolved: req.mail_on_issue_resolved,
        mail_on_daily_report: req.mail_on_daily_report,
        msg_on_login: req.msg_on_login,
        msg_on_issue_created: req.msg_on_issue_created,
        msg_on_issue_resolved: req.msg_on_issue_resolved,
        msg_on_daily_report: req.msg_on_daily_report,
    }
}

/// `GET /api/v1/admin/notification-settings`
pub async fn get_notification_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
    _admin: SuperadminUser,
) -> Response {
    let rid = request_id(&headers);
    let auth = state.auth();
    let Ok(client) = auth.db.pool.get().await else {
        return internal(&rid);
    };
    notification_settings::get(&client).await.map_or_else(
        |_| internal(&rid),
        |s| Json(notification_response(s)).into_response(),
    )
}

/// `PUT /api/v1/admin/notification-settings`
pub async fn update_notification_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
    admin: SuperadminUser,
    body: Result<Json<UpdateNotificationSettingsRequest>, JsonRejection>,
) -> Response {
    let rid = request_id(&headers);
    let auth = state.auth();
    let req = match parse_json(body, &rid) {
        Ok(v) => v,
        Err(r) => return r,
    };
    if req.validate().is_err() {
        return invalid_settings(&rid);
    }
    let Ok(client) = auth.db.pool.get().await else {
        return internal(&rid);
    };
    let upd = notification_update_from(req);
    match notification_settings::set(&client, &upd, admin.user_id).await {
        Ok(s) => {
            audit::record(
                &client,
                Some(admin.user_id),
                "notification_settings_updated",
                Some(client_ip(&headers)),
                Some(&user_agent(&headers)),
                &json!({
                    "mail_enabled": s.mail_enabled,
                    "mail_provider": s.mail_provider,
                    "matrix_enabled": s.matrix_enabled,
                    "telegram_enabled": s.telegram_enabled,
                }),
            )
            .await;
            Json(notification_response(s)).into_response()
        }
        Err(_) => internal(&rid),
    }
}

fn test_outcome(result: Result<(), String>) -> Response {
    let resp = match result {
        Ok(()) => NotificationTestResponse {
            ok: true,
            message: "Test message sent.".to_owned(),
        },
        Err(e) => NotificationTestResponse {
            ok: false,
            message: e,
        },
    };
    Json(resp).into_response()
}

/// `POST /api/v1/admin/notification-settings/test-mail` — send a test email to
/// the given recipient using the saved configuration.
pub async fn test_mail(
    State(state): State<AppState>,
    headers: HeaderMap,
    _admin: SuperadminUser,
    body: Result<Json<TestMailRequest>, JsonRejection>,
) -> Response {
    let rid = request_id(&headers);
    let auth = state.auth();
    let req = match parse_json(body, &rid) {
        Ok(v) => v,
        Err(r) => return r,
    };
    if req.validate().is_err() {
        return invalid_settings(&rid);
    }
    let Ok(client) = auth.db.pool.get().await else {
        return internal(&rid);
    };
    let Ok(settings) = notification_settings::get(&client).await else {
        return internal(&rid);
    };
    let result = crate::notify::send_email(
        &settings,
        &req.to,
        "IntelliPilot test notification",
        "<html><body><b>Test message</b> from IntelliPilot.</body></html>",
    )
    .await;
    test_outcome(result)
}

/// `POST /api/v1/admin/notification-settings/test-matrix`
pub async fn test_matrix(
    State(state): State<AppState>,
    headers: HeaderMap,
    _admin: SuperadminUser,
) -> Response {
    let rid = request_id(&headers);
    let auth = state.auth();
    let Ok(client) = auth.db.pool.get().await else {
        return internal(&rid);
    };
    let Ok(settings) = notification_settings::get(&client).await else {
        return internal(&rid);
    };
    let result = crate::notify::send_matrix(&settings, "IntelliPilot test notification").await;
    test_outcome(result)
}

/// `POST /api/v1/admin/notification-settings/test-telegram`
pub async fn test_telegram(
    State(state): State<AppState>,
    headers: HeaderMap,
    _admin: SuperadminUser,
) -> Response {
    let rid = request_id(&headers);
    let auth = state.auth();
    let Ok(client) = auth.db.pool.get().await else {
        return internal(&rid);
    };
    let Ok(settings) = notification_settings::get(&client).await else {
        return internal(&rid);
    };
    let result = crate::notify::send_telegram(&settings, "IntelliPilot test notification").await;
    test_outcome(result)
}

#[allow(unused_imports)]
pub use {
    create_invitation as create_invitation_handler, create_user as create_user_handler,
    delete_user as delete_user_handler, get_settings as get_settings_handler,
    list_invitations as list_invitations_handler, list_users as list_users_handler,
    reset_password as reset_password_handler, revoke_invitation as revoke_invitation_handler,
    update_settings as update_settings_handler, update_user as update_user_handler,
};
