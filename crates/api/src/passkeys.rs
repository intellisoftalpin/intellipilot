//! Passkey (WebAuthn) registration, management, and passwordless login.
#![allow(clippy::arithmetic_side_effects)]

use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum_extra::extract::CookieJar;
use garde::Validate;
use intellipilot_db::{audit, users, webauthn as wdb};
use serde_json::json;
use time::{Duration as TimeDuration, OffsetDateTime};
use uuid::Uuid;
use webauthn_rs::prelude::{
    Passkey, PasskeyAuthentication, PasskeyRegistration, PublicKeyCredential,
    RegisterPublicKeyCredential,
};

use crate::auth::handlers::issue_session;
use crate::auth::{AuthUser, client_ip, request_id, user_agent};
use crate::dto::{PasskeyAuthStartRequest, PasskeyFinishRequest};
use crate::problem::Problem;
use crate::state::AppState;

const STATE_TTL_SECS: i64 = 5 * 60;

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
fn unauthorized(rid: &str) -> Response {
    problem(
        StatusCode::UNAUTHORIZED,
        "unauthorized",
        "Unauthorized",
        None,
        rid,
    )
}
fn bad_request(rid: &str, detail: &str) -> Response {
    problem(
        StatusCode::BAD_REQUEST,
        "invalid_request",
        "Bad Request",
        Some(detail.to_owned()),
        rid,
    )
}

fn state_expiry() -> OffsetDateTime {
    OffsetDateTime::now_utc() + TimeDuration::seconds(STATE_TTL_SECS)
}

// --- registration (authenticated) ----------------------------------------

/// `POST /api/v1/me/passkeys/register/start`
#[utoipa::path(post, path = "/api/v1/me/passkeys/register/start",
    responses((status = 200), (status = 401)))]
pub async fn register_start(
    State(state): State<AppState>,
    headers: HeaderMap,
    user: AuthUser,
) -> Response {
    let rid = request_id(&headers);
    let auth = state.auth();
    let Ok(client) = auth.db.pool.get().await else {
        return internal(&rid);
    };
    let Ok(Some(u)) = users::find_by_id(&client, user.user_id).await else {
        return internal(&rid);
    };
    let display = if u.full_name.is_empty() {
        &u.username
    } else {
        &u.full_name
    };

    let (ccr, reg_state) =
        match auth
            .webauthn
            .start_passkey_registration(user.user_id, &u.username, display, None)
        {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "passkey registration start failed");
                return internal(&rid);
            }
        };

    let Ok(state_val) = serde_json::to_value(&reg_state) else {
        return internal(&rid);
    };
    let Ok(state_id) = wdb::save_state(
        &client,
        Some(user.user_id),
        "register",
        &state_val,
        state_expiry(),
    )
    .await
    else {
        return internal(&rid);
    };

    Json(json!({ "state_id": state_id, "creation_options": ccr })).into_response()
}

/// `POST /api/v1/me/passkeys/register/finish`
#[utoipa::path(post, path = "/api/v1/me/passkeys/register/finish",
    request_body = PasskeyFinishRequest, responses((status = 201), (status = 401)))]
pub async fn register_finish(
    State(state): State<AppState>,
    headers: HeaderMap,
    user: AuthUser,
    body: Result<Json<PasskeyFinishRequest>, JsonRejection>,
) -> Response {
    let rid = request_id(&headers);
    let auth = state.auth();
    let Ok(Json(req)) = body else {
        return bad_request(&rid, "invalid body");
    };
    let Ok(client) = auth.db.pool.get().await else {
        return internal(&rid);
    };

    let Ok(Some((owner, state_val))) = wdb::take_state(&client, req.state_id, "register").await
    else {
        return bad_request(&rid, "unknown or expired ceremony state");
    };
    if owner != Some(user.user_id) {
        return unauthorized(&rid);
    }

    let (Ok(reg_state), Ok(reg_cred)) = (
        serde_json::from_value::<PasskeyRegistration>(state_val),
        serde_json::from_value::<RegisterPublicKeyCredential>(req.credential),
    ) else {
        return bad_request(&rid, "malformed credential");
    };

    let passkey = match auth
        .webauthn
        .finish_passkey_registration(&reg_cred, &reg_state)
    {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(error = %e, "passkey registration finish failed");
            return bad_request(&rid, "credential verification failed");
        }
    };

    let cred_id = passkey.cred_id().as_ref().to_vec();
    let Ok(passkey_val) = serde_json::to_value(&passkey) else {
        return internal(&rid);
    };
    let nickname = req.nickname.unwrap_or_default();
    if wdb::insert_credential(&client, user.user_id, &cred_id, &passkey_val, &nickname, 0)
        .await
        .is_err()
    {
        return internal(&rid);
    }
    audit::record(
        &client,
        Some(user.user_id),
        "passkey_registered",
        Some(client_ip(&headers)),
        Some(&user_agent(&headers)),
        &json!({}),
    )
    .await;
    StatusCode::CREATED.into_response()
}

/// `GET /api/v1/me/passkeys`
#[utoipa::path(get, path = "/api/v1/me/passkeys", responses((status = 200), (status = 401)))]
pub async fn list(State(state): State<AppState>, headers: HeaderMap, user: AuthUser) -> Response {
    let rid = request_id(&headers);
    let auth = state.auth();
    let Ok(client) = auth.db.pool.get().await else {
        return internal(&rid);
    };
    let Ok(creds) = wdb::list_for_user(&client, user.user_id).await else {
        return internal(&rid);
    };
    let items: Vec<_> = creds
        .iter()
        .map(|c| {
            json!({
                "id": c.id,
                "nickname": c.nickname,
                "created_at": c.created_at.format(&time::format_description::well_known::Rfc3339).unwrap_or_default(),
                "last_used_at": c.last_used_at.map(|t| t.format(&time::format_description::well_known::Rfc3339).unwrap_or_default()),
            })
        })
        .collect();
    Json(json!({ "passkeys": items })).into_response()
}

/// `DELETE /api/v1/me/passkeys/{id}`
#[utoipa::path(delete, path = "/api/v1/me/passkeys/{id}", responses((status = 204), (status = 401), (status = 404)))]
pub async fn delete(
    State(state): State<AppState>,
    headers: HeaderMap,
    user: AuthUser,
    Path(id): Path<Uuid>,
) -> Response {
    let rid = request_id(&headers);
    let auth = state.auth();
    let Ok(client) = auth.db.pool.get().await else {
        return internal(&rid);
    };
    match wdb::delete_credential(&client, user.user_id, id).await {
        Ok(true) => {
            audit::record(
                &client,
                Some(user.user_id),
                "passkey_deleted",
                Some(client_ip(&headers)),
                Some(&user_agent(&headers)),
                &json!({ "credential": id.to_string() }),
            )
            .await;
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => problem(StatusCode::NOT_FOUND, "not_found", "Not Found", None, &rid),
        Err(_) => internal(&rid),
    }
}

// --- passwordless authentication ------------------------------------------

/// `POST /api/v1/auth/passkeys/authenticate/start`
#[utoipa::path(post, path = "/api/v1/auth/passkeys/authenticate/start",
    request_body = PasskeyAuthStartRequest, responses((status = 200), (status = 401)))]
pub async fn authenticate_start(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Result<Json<PasskeyAuthStartRequest>, JsonRejection>,
) -> Response {
    let rid = request_id(&headers);
    let auth = state.auth();
    let Ok(Json(req)) = body else {
        return bad_request(&rid, "invalid body");
    };
    if req.validate().is_err() {
        return bad_request(&rid, "invalid email");
    }
    let Ok(client) = auth.db.pool.get().await else {
        return internal(&rid);
    };

    let Ok(Some(found)) = users::find_by_email_with_secret(&client, &req.email).await else {
        return unauthorized(&rid);
    };
    let Ok(creds) = wdb::list_for_user(&client, found.user.id).await else {
        return internal(&rid);
    };
    let passkeys = match parse_passkeys(&creds) {
        Some(p) if !p.is_empty() => p,
        _ => return unauthorized(&rid),
    };

    let (rcr, auth_state) = match auth.webauthn.start_passkey_authentication(&passkeys) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(error = %e, "passkey auth start failed");
            return internal(&rid);
        }
    };
    let Ok(state_val) = serde_json::to_value(&auth_state) else {
        return internal(&rid);
    };
    let Ok(state_id) = wdb::save_state(
        &client,
        Some(found.user.id),
        "authenticate",
        &state_val,
        state_expiry(),
    )
    .await
    else {
        return internal(&rid);
    };

    Json(json!({ "state_id": state_id, "request_options": rcr })).into_response()
}

/// `POST /api/v1/auth/passkeys/authenticate/finish`
#[utoipa::path(post, path = "/api/v1/auth/passkeys/authenticate/finish",
    request_body = PasskeyFinishRequest, responses((status = 200), (status = 401)))]
pub async fn authenticate_finish(
    State(state): State<AppState>,
    headers: HeaderMap,
    jar: CookieJar,
    body: Result<Json<PasskeyFinishRequest>, JsonRejection>,
) -> Response {
    let rid = request_id(&headers);
    let auth = state.auth();
    let Ok(Json(req)) = body else {
        return bad_request(&rid, "invalid body");
    };
    let Ok(client) = auth.db.pool.get().await else {
        return internal(&rid);
    };

    let Ok(Some((owner, state_val))) = wdb::take_state(&client, req.state_id, "authenticate").await
    else {
        return unauthorized(&rid);
    };
    let Some(user_id) = owner else {
        return unauthorized(&rid);
    };

    let (Ok(auth_state), Ok(pub_cred)) = (
        serde_json::from_value::<PasskeyAuthentication>(state_val),
        serde_json::from_value::<PublicKeyCredential>(req.credential),
    ) else {
        return bad_request(&rid, "malformed credential");
    };

    // finish_passkey_authentication enforces signature counter monotonicity;
    // a regression (cloned authenticator) yields an error here.
    let result = match auth
        .webauthn
        .finish_passkey_authentication(&pub_cred, &auth_state)
    {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "passkey auth finish failed (possible counter regression)");
            return unauthorized(&rid);
        }
    };

    // Persist the updated counter for the matching credential.
    if result.needs_update() {
        update_stored_passkey(&client, user_id, &result).await;
    }

    issue_session(
        auth,
        &state.geoip,
        &client,
        user_id,
        &headers,
        jar,
        "login_passkey_success",
    )
    .await
}

fn parse_passkeys(creds: &[wdb::StoredCredential]) -> Option<Vec<Passkey>> {
    creds
        .iter()
        .map(|c| serde_json::from_value::<Passkey>(c.passkey.clone()).ok())
        .collect()
}

async fn update_stored_passkey(
    client: &deadpool_postgres::Client,
    user_id: Uuid,
    result: &webauthn_rs::prelude::AuthenticationResult,
) {
    let Ok(creds) = wdb::list_for_user(client, user_id).await else {
        return;
    };
    for c in creds {
        let Ok(mut pk) = serde_json::from_value::<Passkey>(c.passkey.clone()) else {
            continue;
        };
        if pk.cred_id().as_ref() == result.cred_id().as_ref() {
            if pk.update_credential(result).is_some()
                && let Ok(updated) = serde_json::to_value(&pk)
            {
                let counter = i64::from(result.counter());
                if let Err(e) =
                    wdb::update_after_auth(client, &c.credential_id, &updated, counter).await
                {
                    tracing::warn!(error = %e, "failed to persist passkey counter");
                }
            }
            return;
        }
    }
}
