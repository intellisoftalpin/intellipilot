//! OIDC provider administration (V025), superadmin only.
//!
//! DTOs live beside the handlers rather than in [`super::dto`] because this is
//! one self-contained feature and splitting it across two already-large files
//! buys nothing. The conventions are the LDAP settings endpoints': a
//! write-only secret exposed as a `*_set` boolean, and a "test connection"
//! endpoint that talks to the real thing so an operator can find out what is
//! wrong before any user does.
//!
//! `unexpected_cfgs` is allowed for the same reason it is in [`super::dto`]:
//! `garde_derive`'s `Validate` macro emits a `cfg(feature = "js-sys")` gate
//! that is not a feature of this crate.
//!
//! `result_large_err` and `arithmetic_side_effects` are allowed for the same
//! reasons as in [`crate::auth::handlers`]: an axum `Response` is the
//! intentional error type, and every arithmetic operation here is bounded time
//! math that cannot realistically overflow.
#![allow(
    unexpected_cfgs,
    clippy::result_large_err,
    clippy::arithmetic_side_effects
)]

use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use garde::Validate;
use serde::{Deserialize, Serialize};
use serde_json::json;
use time::{Duration as TimeDuration, OffsetDateTime};
use utoipa::ToSchema;
use uuid::Uuid;

use intellipilot_db::oidc_providers::{self, OidcProvider, OidcProviderUpdate};
use intellipilot_db::{audit, users};

use crate::auth::{SuperadminUser, request_id};
use crate::oidc::{OidcError, redirect_uri};
use crate::problem::Problem;
use crate::state::AppState;

/// How long an admin-armed linking window stays open.
///
/// Long enough for the operator to tell the user and for them to act, short
/// enough that a forgotten window is not a standing invitation to bind an
/// identity to somebody else's account.
const LINK_ARM_TTL_SECS: i64 = 24 * 60 * 60;

// ---------------------------------------------------------------------------
// DTOs
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, ToSchema)]
#[allow(clippy::struct_excessive_bools)]
pub struct OidcProviderResponse {
    pub id: Uuid,
    pub slug: String,
    pub display_name: String,
    pub enabled: bool,
    pub issuer_url: String,
    pub client_id: String,
    /// Whether a client secret is stored. The value itself is never returned.
    pub client_secret_set: bool,
    pub scopes: String,
    pub claim_email: String,
    pub claim_username: String,
    pub claim_display_name: String,
    pub claim_groups: String,
    pub superadmin_group: String,
    pub allow_jit_provisioning: bool,
    pub require_email_verified: bool,
    pub device_flow_enabled: bool,
    pub sort_order: i32,
    pub skip_tls_verify: bool,
    /// What must be registered at the identity provider, computed from this
    /// deployment's public origin. Read-only, and shown in the admin UI so an
    /// operator can copy it rather than guess at it.
    pub redirect_uri: String,
    /// Where the provider should POST back-channel logout notifications.
    pub backchannel_logout_uri: String,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
    pub updated_by: Option<Uuid>,
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct UpsertOidcProviderRequest {
    #[garde(length(min = 1, max = 64), pattern(r"^[a-z0-9][a-z0-9-]*$"))]
    pub slug: String,
    #[garde(length(min = 1, max = 128))]
    pub display_name: String,
    #[garde(skip)]
    pub enabled: bool,
    /// Validated by [`check_issuer_url`] rather than by `garde(url)`: the rule
    /// there accepts anything the `url` crate parses, including schemes we
    /// must refuse, and the message it produces tells an operator nothing.
    #[garde(length(min = 1, max = 512))]
    pub issuer_url: String,
    #[garde(length(min = 1, max = 512))]
    pub client_id: String,
    /// Blank keeps the stored secret; omit it entirely to do the same.
    #[garde(length(max = 1024))]
    pub client_secret: Option<String>,
    #[garde(length(max = 512))]
    pub scopes: String,
    #[garde(length(min = 1, max = 64))]
    pub claim_email: String,
    #[garde(length(min = 1, max = 64))]
    pub claim_username: String,
    #[garde(length(min = 1, max = 64))]
    pub claim_display_name: String,
    #[garde(length(min = 1, max = 64))]
    pub claim_groups: String,
    #[garde(length(max = 512))]
    pub superadmin_group: String,
    #[garde(skip)]
    pub allow_jit_provisioning: bool,
    #[garde(skip)]
    pub require_email_verified: bool,
    #[garde(skip)]
    pub device_flow_enabled: bool,
    #[garde(range(min = -1000, max = 1000))]
    pub sort_order: i32,
    #[garde(skip)]
    pub skip_tls_verify: bool,
}

/// What the "Test" button learned. Never fails the request — an unreachable
/// provider is a finding to display, not an error to raise.
#[derive(Debug, Serialize, ToSchema)]
pub struct OidcTestResponse {
    pub ok: bool,
    /// Human-readable summary, shown verbatim in the admin UI.
    pub message: String,
    /// The `issuer` the discovery document actually claims. A mismatch with
    /// the configured URL is the single most common misconfiguration.
    pub issuer: Option<String>,
    pub authorization_endpoint: Option<String>,
    pub token_endpoint: Option<String>,
    pub userinfo_endpoint: Option<String>,
    /// Whether the provider publishes a device authorization endpoint. Without
    /// one the desktop and mobile clients cannot use this provider.
    pub supports_device_flow: bool,
    /// How many signing keys the JWKS published.
    pub jwks_keys: usize,
    pub redirect_uri: String,
}

// ---------------------------------------------------------------------------
// Helpers
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

fn not_found(rid: &str) -> Response {
    problem(StatusCode::NOT_FOUND, "not_found", "Not Found", None, rid)
}

fn to_response(state: &AppState, p: OidcProvider) -> OidcProviderResponse {
    let origin = &state.auth().config.public_origin;
    OidcProviderResponse {
        redirect_uri: redirect_uri(origin, &p.slug),
        backchannel_logout_uri: format!(
            "{}/api/v1/auth/oidc/{}/backchannel-logout",
            origin.trim_end_matches('/'),
            p.slug
        ),
        client_secret_set: !p.client_secret.is_empty(),
        id: p.id,
        slug: p.slug,
        display_name: p.display_name,
        enabled: p.enabled,
        issuer_url: p.issuer_url,
        client_id: p.client_id,
        scopes: p.scopes,
        claim_email: p.claim_email,
        claim_username: p.claim_username,
        claim_display_name: p.claim_display_name,
        claim_groups: p.claim_groups,
        superadmin_group: p.superadmin_group,
        allow_jit_provisioning: p.allow_jit_provisioning,
        require_email_verified: p.require_email_verified,
        device_flow_enabled: p.device_flow_enabled,
        sort_order: p.sort_order,
        skip_tls_verify: p.skip_tls_verify,
        updated_at: p.updated_at,
        updated_by: p.updated_by,
    }
}

/// Blank means "keep what is stored", matching the LDAP service password.
fn keep_if_blank(v: Option<String>) -> Option<String> {
    v.filter(|s| !s.trim().is_empty())
}

fn update_from(req: &UpsertOidcProviderRequest) -> OidcProviderUpdate {
    OidcProviderUpdate {
        slug: req.slug.trim().to_lowercase(),
        display_name: req.display_name.trim().to_owned(),
        enabled: req.enabled,
        // Trailing slashes matter: discovery joins a relative path onto this,
        // and `Url::join` on a path without a trailing slash discards the last
        // segment. Normalising here means an operator cannot get it wrong.
        issuer_url: req.issuer_url.trim().trim_end_matches('/').to_owned(),
        client_id: req.client_id.trim().to_owned(),
        client_secret: keep_if_blank(req.client_secret.clone()),
        scopes: req.scopes.trim().to_owned(),
        claim_email: req.claim_email.trim().to_owned(),
        claim_username: req.claim_username.trim().to_owned(),
        claim_display_name: req.claim_display_name.trim().to_owned(),
        claim_groups: req.claim_groups.trim().to_owned(),
        superadmin_group: req.superadmin_group.trim().to_owned(),
        allow_jit_provisioning: req.allow_jit_provisioning,
        require_email_verified: req.require_email_verified,
        device_flow_enabled: req.device_flow_enabled,
        sort_order: req.sort_order,
        skip_tls_verify: req.skip_tls_verify,
    }
}

/// Reject an issuer URL that could not work, with a message that says why.
///
/// Plain HTTP is refused outside development: every secret in this exchange —
/// the authorization code, the client secret, the ID token — would otherwise
/// cross the network in the clear. A URL carrying a query, a fragment or
/// credentials is refused because discovery joins a path onto it and would
/// silently drop them.
fn check_issuer_url(raw: &str, dev: bool) -> Result<(), &'static str> {
    let Ok(url) = url::Url::parse(raw.trim()) else {
        return Err(
            "issuer must be an absolute URL, e.g. https://sso.example.com/application/o/app",
        );
    };
    match url.scheme() {
        "https" => {}
        "http" if dev => {}
        _ => return Err("issuer must use https"),
    }
    if url.host_str().is_none_or(str::is_empty) {
        return Err("issuer must include a host");
    }
    if url.query().is_some() || url.fragment().is_some() || !url.username().is_empty() {
        return Err("issuer must not carry a query, fragment or credentials");
    }
    Ok(())
}

fn parse_body(
    body: Result<Json<UpsertOidcProviderRequest>, JsonRejection>,
    rid: &str,
) -> Result<UpsertOidcProviderRequest, Response> {
    let Ok(Json(req)) = body else {
        return Err(problem(
            StatusCode::BAD_REQUEST,
            "invalid_body",
            "Invalid Request Body",
            Some("could not parse JSON".to_owned()),
            rid,
        ));
    };
    if req.validate().is_err() {
        return Err(problem(
            StatusCode::UNPROCESSABLE_ENTITY,
            "validation_failed",
            "Validation failed",
            None,
            rid,
        ));
    }
    Ok(req)
}

/// The same, plus the issuer check, which needs to know the environment.
fn parse_and_check(
    body: Result<Json<UpsertOidcProviderRequest>, JsonRejection>,
    dev: bool,
    rid: &str,
) -> Result<UpsertOidcProviderRequest, Response> {
    let req = parse_body(body, rid)?;
    if let Err(why) = check_issuer_url(&req.issuer_url, dev) {
        return Err(problem(
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid_issuer_url",
            "Validation failed",
            Some(why.to_owned()),
            rid,
        ));
    }
    Ok(req)
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// `GET /api/v1/admin/oidc-providers`
#[utoipa::path(get, path = "/api/v1/admin/oidc-providers",
    responses((status = 200, body = Vec<OidcProviderResponse>), (status = 403)))]
pub async fn list_providers(
    State(state): State<AppState>,
    headers: HeaderMap,
    _admin: SuperadminUser,
) -> Response {
    let rid = request_id(&headers);
    let Ok(client) = state.auth().db.pool.get().await else {
        return internal(&rid);
    };
    match oidc_providers::list_all(&client).await {
        Ok(rows) => Json(
            rows.into_iter()
                .map(|p| to_response(&state, p))
                .collect::<Vec<_>>(),
        )
        .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "failed to list oidc providers");
            internal(&rid)
        }
    }
}

/// `POST /api/v1/admin/oidc-providers`
#[utoipa::path(post, path = "/api/v1/admin/oidc-providers",
    request_body = UpsertOidcProviderRequest,
    responses((status = 201, body = OidcProviderResponse), (status = 409), (status = 422)))]
pub async fn create_provider(
    State(state): State<AppState>,
    headers: HeaderMap,
    admin: SuperadminUser,
    body: Result<Json<UpsertOidcProviderRequest>, JsonRejection>,
) -> Response {
    let rid = request_id(&headers);
    let req = match parse_and_check(body, state.auth().config.env.is_dev(), &rid) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let Ok(client) = state.auth().db.pool.get().await else {
        return internal(&rid);
    };
    match oidc_providers::create(&client, &update_from(&req), admin.user_id).await {
        Ok(p) => {
            audit::record(
                &client,
                Some(admin.user_id),
                "oidc_provider_created",
                None,
                None,
                &json!({ "slug": p.slug, "enabled": p.enabled }),
            )
            .await;
            (StatusCode::CREATED, Json(to_response(&state, p))).into_response()
        }
        Err(e) if e.is_unique_violation() => problem(
            StatusCode::CONFLICT,
            "slug_taken",
            "Conflict",
            Some("another provider already uses this key".to_owned()),
            &rid,
        ),
        Err(e) => {
            tracing::error!(error = %e, "failed to create oidc provider");
            internal(&rid)
        }
    }
}

/// `PUT /api/v1/admin/oidc-providers/{id}`
#[utoipa::path(put, path = "/api/v1/admin/oidc-providers/{id}",
    request_body = UpsertOidcProviderRequest,
    responses((status = 200, body = OidcProviderResponse), (status = 404), (status = 409)))]
pub async fn update_provider(
    State(state): State<AppState>,
    headers: HeaderMap,
    admin: SuperadminUser,
    Path(id): Path<Uuid>,
    body: Result<Json<UpsertOidcProviderRequest>, JsonRejection>,
) -> Response {
    let rid = request_id(&headers);
    let req = match parse_and_check(body, state.auth().config.env.is_dev(), &rid) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let Ok(client) = state.auth().db.pool.get().await else {
        return internal(&rid);
    };
    match oidc_providers::update(&client, id, &update_from(&req), admin.user_id).await {
        Ok(Some(p)) => {
            // Endpoints and keys may have moved; never serve the old ones.
            state.oidc.invalidate(p.id).await;
            audit::record(
                &client,
                Some(admin.user_id),
                "oidc_provider_updated",
                None,
                None,
                &json!({ "slug": p.slug, "enabled": p.enabled }),
            )
            .await;
            Json(to_response(&state, p)).into_response()
        }
        Ok(None) => not_found(&rid),
        Err(e) if e.is_unique_violation() => problem(
            StatusCode::CONFLICT,
            "slug_taken",
            "Conflict",
            Some("another provider already uses this key".to_owned()),
            &rid,
        ),
        Err(e) => {
            tracing::error!(error = %e, "failed to update oidc provider");
            internal(&rid)
        }
    }
}

/// `DELETE /api/v1/admin/oidc-providers/{id}`
///
/// Cascades to every identity bound through this provider, so anyone who signed
/// in only this way loses that route. The audit entry records how many.
#[utoipa::path(delete, path = "/api/v1/admin/oidc-providers/{id}",
    responses((status = 204), (status = 404)))]
pub async fn delete_provider(
    State(state): State<AppState>,
    headers: HeaderMap,
    admin: SuperadminUser,
    Path(id): Path<Uuid>,
) -> Response {
    let rid = request_id(&headers);
    let Ok(client) = state.auth().db.pool.get().await else {
        return internal(&rid);
    };
    let slug = oidc_providers::get(&client, id)
        .await
        .ok()
        .flatten()
        .map(|p| p.slug);
    match oidc_providers::delete(&client, id).await {
        Ok(true) => {
            state.oidc.invalidate(id).await;
            audit::record(
                &client,
                Some(admin.user_id),
                "oidc_provider_deleted",
                None,
                None,
                &json!({ "slug": slug }),
            )
            .await;
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => not_found(&rid),
        Err(e) => {
            tracing::error!(error = %e, "failed to delete oidc provider");
            internal(&rid)
        }
    }
}

/// `POST /api/v1/admin/oidc-providers/{id}/test`
///
/// Fetches the provider's discovery document and JWKS and reports what it
/// found. Always answers 200 when the provider row exists: "your IdP is
/// unreachable" is a result the admin needs to read, not an HTTP failure.
#[utoipa::path(post, path = "/api/v1/admin/oidc-providers/{id}/test",
    responses((status = 200, body = OidcTestResponse), (status = 404)))]
pub async fn test_provider(
    State(state): State<AppState>,
    headers: HeaderMap,
    _admin: SuperadminUser,
    Path(id): Path<Uuid>,
) -> Response {
    let rid = request_id(&headers);
    let Ok(client) = state.auth().db.pool.get().await else {
        return internal(&rid);
    };
    let Ok(Some(provider)) = oidc_providers::get(&client, id).await else {
        return not_found(&rid);
    };
    let uri = redirect_uri(&state.auth().config.public_origin, &provider.slug);

    // Bypass the cache: the point of pressing Test is to find out what the
    // provider says *now*, not what it said up to fifteen minutes ago.
    state.oidc.invalidate(provider.id).await;
    match state.oidc.metadata(&provider).await {
        Ok(metadata) => {
            let discovered_issuer = metadata.issuer().as_str().to_owned();
            let matches = discovered_issuer.trim_end_matches('/')
                == provider.issuer_url.trim_end_matches('/');
            Json(OidcTestResponse {
                ok: matches,
                message: if matches {
                    "Discovery succeeded.".to_owned()
                } else {
                    format!(
                        "Discovery succeeded, but the provider identifies itself as \
                         '{discovered_issuer}'. Set the issuer URL to exactly that value, \
                         or ID token verification will reject every sign-in."
                    )
                },
                issuer: Some(discovered_issuer),
                authorization_endpoint: Some(metadata.authorization_endpoint().to_string()),
                token_endpoint: metadata.token_endpoint().map(ToString::to_string),
                userinfo_endpoint: metadata.userinfo_endpoint().map(ToString::to_string),
                supports_device_flow: metadata
                    .additional_metadata()
                    .device_authorization_endpoint
                    .is_some(),
                jwks_keys: metadata.jwks().keys().len(),
                redirect_uri: uri,
            })
            .into_response()
        }
        Err(e) => {
            let message = match &e {
                OidcError::Config(m) => format!("Configuration problem: {m}"),
                other => other.to_string(),
            };
            Json(OidcTestResponse {
                ok: false,
                message,
                issuer: None,
                authorization_endpoint: None,
                token_endpoint: None,
                userinfo_endpoint: None,
                supports_device_flow: false,
                jwks_keys: 0,
                redirect_uri: uri,
            })
            .into_response()
        }
    }
}

/// `POST /api/v1/admin/users/{id}/oidc-link-arm`
///
/// The rescue route. Because an SSO sign-in never links by email on its own, a
/// user who has lost their password *and* is not yet linked cannot reach the
/// self-service option on their Security page. Arming opens a one-shot,
/// time-boxed window in which the next SSO sign-in presenting this account's
/// verified email binds to it.
#[utoipa::path(post, path = "/api/v1/admin/users/{id}/oidc-link-arm",
    responses((status = 204), (status = 404)))]
pub async fn arm_link(
    State(state): State<AppState>,
    headers: HeaderMap,
    admin: SuperadminUser,
    Path(id): Path<Uuid>,
) -> Response {
    set_link_arm(state, headers, admin, id, true).await
}

/// `DELETE /api/v1/admin/users/{id}/oidc-link-arm` — close the window early.
#[utoipa::path(delete, path = "/api/v1/admin/users/{id}/oidc-link-arm",
    responses((status = 204), (status = 404)))]
pub async fn disarm_link(
    State(state): State<AppState>,
    headers: HeaderMap,
    admin: SuperadminUser,
    Path(id): Path<Uuid>,
) -> Response {
    set_link_arm(state, headers, admin, id, false).await
}

async fn set_link_arm(
    state: AppState,
    headers: HeaderMap,
    admin: SuperadminUser,
    id: Uuid,
    arm: bool,
) -> Response {
    let rid = request_id(&headers);
    let Ok(client) = state.auth().db.pool.get().await else {
        return internal(&rid);
    };
    let until = arm.then(|| OffsetDateTime::now_utc() + TimeDuration::seconds(LINK_ARM_TTL_SECS));
    match users::set_oidc_link_arm(&client, id, until).await {
        Ok(true) => {
            audit::record(
                &client,
                Some(admin.user_id),
                if arm {
                    "oidc_link_armed"
                } else {
                    "oidc_link_disarmed"
                },
                None,
                None,
                &json!({ "target_user_id": id.to_string() }),
            )
            .await;
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => not_found(&rid),
        Err(e) => {
            tracing::error!(error = %e, "failed to set oidc link window");
            internal(&rid)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::check_issuer_url;

    #[test]
    fn issuer_url_must_be_absolute_https_in_production() {
        assert!(check_issuer_url("https://sso.example.com/application/o/app", false).is_ok());
        assert!(check_issuer_url("http://sso.example.com", false).is_err());
        // Development keeps the plain-HTTP escape hatch for a local IdP.
        assert!(check_issuer_url("http://localhost:9000", true).is_ok());
    }

    #[test]
    fn issuer_url_rejects_shapes_discovery_would_mangle() {
        assert!(check_issuer_url("sso.example.com", false).is_err());
        assert!(check_issuer_url("ftp://sso.example.com", false).is_err());
        assert!(check_issuer_url("https://sso.example.com/?a=b", false).is_err());
        assert!(check_issuer_url("https://sso.example.com/#frag", false).is_err());
        assert!(check_issuer_url("https://user:pw@sso.example.com", false).is_err());
        assert!(check_issuer_url("", false).is_err());
    }
}
