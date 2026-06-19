//! Per-project git integration endpoints: the SSH credential vault,
//! repositories, remote branch discovery, and component↔repository links.
//!
//! Viewing needs `project.view`; mutating needs `project.modify` (consistent
//! with the rest of project configuration). SSH keys are generated server-side
//! (Ed25519); the private key is encrypted at rest and never returned. Adding
//! or re-keying a repository checks SSH reachability best-effort (storing the
//! host fingerprint / default branch when reachable), while the explicit
//! preview/branches endpoints surface connection errors for the UI.
#![allow(
    clippy::result_large_err,
    clippy::implicit_hasher,
    clippy::too_many_lines
)]

use std::collections::HashMap;

use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use garde::Validate;
use intellipilot_core::perms::Permission;
use intellipilot_core::repo::RemoteBranches;
use intellipilot_db::{
    audit, component_repositories as crdb, components as compdb, repositories as repodb,
    ssh_keys as keydb,
};
use intellipilot_git::GitError;
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use crate::auth::{client_ip, user_agent};
use crate::problem::Problem;
use crate::projects::ProjectContext;
use crate::state::{AppState, AuthContext};

/// Per-project sanity caps to bound growth / abuse.
const MAX_SSH_KEYS_PER_PROJECT: i64 = 100;
const MAX_REPOS_PER_PROJECT: i64 = 200;

// --- DTOs ------------------------------------------------------------------

/// Accept only SSH transports: `git@host:path` (scp-like) or `ssh://…`.
/// HTTP(S)/git:// URLs can never authenticate with an SSH key.
// Signature (`&T, &Context`) is mandated by garde's custom validator.
#[allow(clippy::trivially_copy_pass_by_ref)]
fn validate_ssh_url(value: &str, _ctx: &()) -> garde::Result {
    let v = value.trim();
    if v.is_empty() {
        return Err(garde::Error::new("must not be empty"));
    }
    let lower = v.to_lowercase();
    for bad in ["http://", "https://", "git://", "ftp://"] {
        if lower.starts_with(bad) {
            return Err(garde::Error::new(
                "must be an SSH URL (git@host:path or ssh://…)",
            ));
        }
    }
    if lower.starts_with("ssh://") {
        return Ok(());
    }
    // scp-like form: must carry a user@host and a ':' path separator.
    if v.contains('@') && v.contains(':') {
        return Ok(());
    }
    Err(garde::Error::new(
        "must be an SSH URL (git@host:path or ssh://…)",
    ))
}

#[derive(Debug, Deserialize, Validate, utoipa::ToSchema)]
pub struct CreateSshKeyRequest {
    #[garde(length(min = 1, max = 64))]
    pub name: String,
    /// `true` = read-only deploy key; `false` = read/write. Defaults to true.
    #[garde(skip)]
    #[serde(default = "default_true")]
    pub read_only: bool,
}

const fn default_true() -> bool {
    true
}

#[derive(Debug, Deserialize, Validate, utoipa::ToSchema)]
pub struct UpdateSshKeyRequest {
    #[garde(length(min = 1, max = 64))]
    #[serde(default)]
    pub name: Option<String>,
    #[garde(skip)]
    #[serde(default)]
    pub read_only: Option<bool>,
}

#[derive(Debug, Deserialize, Validate, utoipa::ToSchema)]
pub struct CreateRepositoryRequest {
    #[garde(length(min = 1, max = 128))]
    pub name: String,
    #[garde(custom(validate_ssh_url))]
    pub ssh_url: String,
    /// Use an existing key by id.
    #[garde(skip)]
    #[serde(default)]
    pub ssh_key_id: Option<Uuid>,
    /// Or create a new key inline (mutually exclusive with `ssh_key_id`).
    #[garde(dive)]
    #[serde(default)]
    pub new_key: Option<CreateSshKeyRequest>,
    #[garde(length(max = 255))]
    #[serde(default)]
    pub default_branch: Option<String>,
}

#[derive(Debug, Deserialize, Validate, utoipa::ToSchema)]
pub struct UpdateRepositoryRequest {
    #[garde(length(min = 1, max = 128))]
    #[serde(default)]
    pub name: Option<String>,
    #[garde(inner(custom(validate_ssh_url)))]
    #[serde(default)]
    pub ssh_url: Option<String>,
    /// `null` clears the key link; absent leaves it unchanged.
    #[garde(skip)]
    #[serde(default, with = "serde_with::rust::double_option")]
    pub ssh_key_id: Option<Option<Uuid>>,
    /// `null` clears; absent leaves unchanged.
    #[garde(skip)]
    #[serde(default, with = "serde_with::rust::double_option")]
    pub default_branch: Option<Option<String>>,
}

#[derive(Debug, Deserialize, Validate, utoipa::ToSchema)]
pub struct PreviewBranchesRequest {
    #[garde(custom(validate_ssh_url))]
    pub ssh_url: String,
    #[garde(skip)]
    pub ssh_key_id: Uuid,
}

#[derive(Debug, Deserialize, Validate, utoipa::ToSchema)]
pub struct LinkRepositoryRequest {
    #[garde(skip)]
    pub repository_id: Uuid,
    #[garde(length(min = 1, max = 255))]
    pub branch: String,
}

#[derive(Debug, Deserialize, Validate, utoipa::ToSchema)]
pub struct UpdateLinkRequest {
    #[garde(length(min = 1, max = 255))]
    pub branch: String,
}

// --- problem helpers -------------------------------------------------------

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
fn conflict(rid: &str, detail: &str) -> Response {
    problem(
        StatusCode::CONFLICT,
        "already_exists",
        "Already Exists",
        Some(detail.to_owned()),
        rid,
    )
}
fn unprocessable(rid: &str, detail: &str) -> Response {
    problem(
        StatusCode::UNPROCESSABLE_ENTITY,
        "validation_failed",
        "Validation failed",
        Some(detail.to_owned()),
        rid,
    )
}
fn cap_reached(rid: &str, detail: &str) -> Response {
    problem(
        StatusCode::CONFLICT,
        "limit_reached",
        "Limit Reached",
        Some(detail.to_owned()),
        rid,
    )
}

/// Map a git error onto a problem response.
fn git_problem(err: GitError, rid: &str) -> Response {
    let (status, title) = match err {
        GitError::AuthFailed => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "Git authentication failed",
        ),
        GitError::NotFound => (StatusCode::UNPROCESSABLE_ENTITY, "Repository not found"),
        GitError::Unreachable => (StatusCode::BAD_GATEWAY, "Git host unreachable"),
        GitError::Timeout => (StatusCode::GATEWAY_TIMEOUT, "Git operation timed out"),
        GitError::Internal => (StatusCode::BAD_GATEWAY, "Git error"),
    };
    problem(status, err.code(), title, Some(err.to_string()), rid)
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

fn item_id(params: &HashMap<String, String>, key: &str) -> Option<Uuid> {
    params.get(key).and_then(|s| Uuid::parse_str(s).ok())
}

fn require_pepper<'a>(auth: &'a AuthContext, rid: &str) -> Result<&'a [u8], Response> {
    auth.pepper_bytes().ok_or_else(|| {
        problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "encryption_unavailable",
            "Encryption unavailable",
            Some("server is not configured with a pepper for secret encryption".to_owned()),
            rid,
        )
    })
}

// --- SSH keys --------------------------------------------------------------

/// `GET /api/v1/projects/{project_id}/ssh-keys`
pub async fn list_ssh_keys(State(state): State<AppState>, ctx: ProjectContext) -> Response {
    if let Err(r) = ctx.require(Permission::ProjectView) {
        return r;
    }
    let auth = state.auth();
    let Ok(client) = auth.db.pool.get().await else {
        return internal(&ctx.rid);
    };
    match keydb::list(&client, ctx.project.id).await {
        Ok(items) => Json(json!({ "ssh_keys": items })).into_response(),
        Err(_) => internal(&ctx.rid),
    }
}

/// `POST /api/v1/projects/{project_id}/ssh-keys`
pub async fn create_ssh_key(
    State(state): State<AppState>,
    ctx: ProjectContext,
    headers: HeaderMap,
    body: Result<Json<CreateSshKeyRequest>, JsonRejection>,
) -> Response {
    if let Err(r) = ctx.require(Permission::ProjectModify) {
        return r;
    }
    let req = match parse_body(body, &ctx.rid) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let auth = state.auth();
    let pepper = match require_pepper(auth, &ctx.rid) {
        Ok(p) => p,
        Err(r) => return r,
    };
    let Ok(client) = auth.db.pool.get().await else {
        return internal(&ctx.rid);
    };
    match keydb::count(&client, ctx.project.id).await {
        Ok(n) if n >= MAX_SSH_KEYS_PER_PROJECT => {
            return cap_reached(
                &ctx.rid,
                "maximum number of SSH keys reached for this project",
            );
        }
        Ok(_) => {}
        Err(_) => return internal(&ctx.rid),
    }
    let key = match create_key_inner(&client, &ctx, pepper, &req.name, req.read_only).await {
        Ok(k) => k,
        Err(r) => return r,
    };
    audit::record(
        &client,
        Some(ctx.actor_id),
        "ssh_key.create",
        Some(client_ip(&headers)),
        Some(&user_agent(&headers)),
        &json!({ "project_id": ctx.project.id, "ssh_key_id": key.id, "name": key.name }),
    )
    .await;
    (StatusCode::CREATED, Json(key)).into_response()
}

/// Generate, encrypt, and persist a new key. Shared by the standalone endpoint
/// and the inline-on-repo-create path.
async fn create_key_inner(
    client: &deadpool_postgres::Client,
    ctx: &ProjectContext,
    pepper: &[u8],
    name: &str,
    read_only: bool,
) -> Result<intellipilot_core::repo::SshKey, Response> {
    let generated =
        intellipilot_auth::sshkey::generate_ed25519().map_err(|_| internal(&ctx.rid))?;
    let enc =
        intellipilot_auth::secret::encrypt(Some(pepper), generated.private_openssh.as_bytes())
            .map_err(|_| internal(&ctx.rid))?;
    let new = keydb::NewSshKey {
        name,
        read_only,
        key_type: &generated.key_type,
        public_key: &generated.public_openssh,
        private_key_enc: &enc,
        fingerprint: &generated.fingerprint,
        created_by: ctx.actor_id,
    };
    match keydb::create(client, ctx.project.id, &new).await {
        Ok(k) => Ok(k),
        Err(e) if e.is_unique_violation() => Err(conflict(&ctx.rid, "key name already used")),
        Err(_) => Err(internal(&ctx.rid)),
    }
}

/// `PATCH /api/v1/projects/{project_id}/ssh-keys/{key_id}`
pub async fn update_ssh_key(
    State(state): State<AppState>,
    ctx: ProjectContext,
    Path(params): Path<HashMap<String, String>>,
    body: Result<Json<UpdateSshKeyRequest>, JsonRejection>,
) -> Response {
    if let Err(r) = ctx.require(Permission::ProjectModify) {
        return r;
    }
    let Some(id) = item_id(&params, "key_id") else {
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
    match keydb::update(
        &client,
        ctx.project.id,
        id,
        req.name.as_deref(),
        req.read_only,
    )
    .await
    {
        Ok(Some(k)) => Json(k).into_response(),
        Ok(None) => not_found(&ctx.rid),
        Err(e) if e.is_unique_violation() => conflict(&ctx.rid, "key name already used"),
        Err(_) => internal(&ctx.rid),
    }
}

/// `DELETE /api/v1/projects/{project_id}/ssh-keys/{key_id}`
///
/// Repositories using the key are detached (left without a key), not deleted.
pub async fn delete_ssh_key(
    State(state): State<AppState>,
    ctx: ProjectContext,
    headers: HeaderMap,
    Path(params): Path<HashMap<String, String>>,
) -> Response {
    if let Err(r) = ctx.require(Permission::ProjectModify) {
        return r;
    }
    let Some(id) = item_id(&params, "key_id") else {
        return not_found(&ctx.rid);
    };
    let auth = state.auth();
    let Ok(client) = auth.db.pool.get().await else {
        return internal(&ctx.rid);
    };
    match keydb::delete(&client, ctx.project.id, id).await {
        Ok(true) => {
            audit::record(
                &client,
                Some(ctx.actor_id),
                "ssh_key.delete",
                Some(client_ip(&headers)),
                Some(&user_agent(&headers)),
                &json!({ "project_id": ctx.project.id, "ssh_key_id": id }),
            )
            .await;
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => not_found(&ctx.rid),
        Err(_) => internal(&ctx.rid),
    }
}

// --- repositories ----------------------------------------------------------

/// `GET /api/v1/projects/{project_id}/repositories`
pub async fn list_repositories(State(state): State<AppState>, ctx: ProjectContext) -> Response {
    if let Err(r) = ctx.require(Permission::ProjectView) {
        return r;
    }
    let auth = state.auth();
    let Ok(client) = auth.db.pool.get().await else {
        return internal(&ctx.rid);
    };
    match repodb::list(&client, ctx.project.id).await {
        Ok(items) => Json(json!({ "repositories": items })).into_response(),
        Err(_) => internal(&ctx.rid),
    }
}

/// `POST /api/v1/projects/{project_id}/repositories`
pub async fn create_repository(
    State(state): State<AppState>,
    ctx: ProjectContext,
    headers: HeaderMap,
    body: Result<Json<CreateRepositoryRequest>, JsonRejection>,
) -> Response {
    if let Err(r) = ctx.require(Permission::ProjectModify) {
        return r;
    }
    let req = match parse_body(body, &ctx.rid) {
        Ok(v) => v,
        Err(r) => return r,
    };
    if req.ssh_key_id.is_some() && req.new_key.is_some() {
        return unprocessable(&ctx.rid, "provide either ssh_key_id or new_key, not both");
    }
    let auth = state.auth();
    let Ok(client) = auth.db.pool.get().await else {
        return internal(&ctx.rid);
    };
    match repodb::count(&client, ctx.project.id).await {
        Ok(n) if n >= MAX_REPOS_PER_PROJECT => {
            return cap_reached(
                &ctx.rid,
                "maximum number of repositories reached for this project",
            );
        }
        Ok(_) => {}
        Err(_) => return internal(&ctx.rid),
    }

    // Resolve the key: inline-create, existing, or none.
    let key_id =
        match resolve_key_for_repo(&client, &ctx, auth, req.ssh_key_id, req.new_key.as_ref()).await
        {
            Ok(k) => k,
            Err(r) => return r,
        };

    // Best-effort reachability check + connection metadata when a key is
    // present. A freshly generated key may not be registered on the host yet,
    // so a failed check must NOT block creation — the interactive
    // preview/branches endpoints surface connection errors explicitly.
    let mut host_fp: Option<String> = None;
    let mut default_branch = req.default_branch.clone();
    if let Some(kid) = key_id
        && let Ok(info) = remote_info_for_key(&client, &ctx, auth, kid, &req.ssh_url).await
    {
        host_fp = info.host_fingerprint;
        if default_branch.is_none() {
            default_branch = info.default_branch;
        }
    }

    let new = repodb::NewRepository {
        name: &req.name,
        ssh_url: &req.ssh_url,
        ssh_key_id: key_id,
        default_branch: default_branch.as_deref(),
        host_fingerprint: host_fp.as_deref(),
        created_by: ctx.actor_id,
    };
    match repodb::create(&client, ctx.project.id, &new).await {
        Ok(repo) => {
            audit::record(
                &client,
                Some(ctx.actor_id),
                "repository.create",
                Some(client_ip(&headers)),
                Some(&user_agent(&headers)),
                &json!({ "project_id": ctx.project.id, "repository_id": repo.id }),
            )
            .await;
            (StatusCode::CREATED, Json(repo)).into_response()
        }
        Err(e) if e.is_unique_violation() => conflict(&ctx.rid, "repository URL already added"),
        Err(_) => internal(&ctx.rid),
    }
}

/// Resolve the key id for a repository create request, generating an inline key
/// if requested and validating an existing id belongs to the project.
async fn resolve_key_for_repo(
    client: &deadpool_postgres::Client,
    ctx: &ProjectContext,
    auth: &AuthContext,
    ssh_key_id: Option<Uuid>,
    new_key: Option<&CreateSshKeyRequest>,
) -> Result<Option<Uuid>, Response> {
    if let Some(nk) = new_key {
        let pepper = require_pepper(auth, &ctx.rid)?;
        let key = create_key_inner(client, ctx, pepper, &nk.name, nk.read_only).await?;
        return Ok(Some(key.id));
    }
    if let Some(kid) = ssh_key_id {
        match keydb::get(client, ctx.project.id, kid).await {
            Ok(Some(_)) => Ok(Some(kid)),
            Ok(None) => Err(unprocessable(
                &ctx.rid,
                "ssh_key_id not found in this project",
            )),
            Err(_) => Err(internal(&ctx.rid)),
        }
    } else {
        Ok(None)
    }
}

/// Decrypt a key and inspect a remote.
async fn remote_info_for_key(
    client: &deadpool_postgres::Client,
    ctx: &ProjectContext,
    auth: &AuthContext,
    key_id: Uuid,
    ssh_url: &str,
) -> Result<intellipilot_core::repo::RemoteBranches, Response> {
    let pepper = require_pepper(auth, &ctx.rid)?;
    let enc = keydb::private_key_enc(client, ctx.project.id, key_id)
        .await
        .map_err(|_| internal(&ctx.rid))?
        .ok_or_else(|| unprocessable(&ctx.rid, "ssh key not found"))?;
    let pem =
        intellipilot_auth::secret::decrypt(Some(pepper), &enc).map_err(|_| internal(&ctx.rid))?;
    let pem = String::from_utf8(pem).map_err(|_| internal(&ctx.rid))?;
    let info = intellipilot_git::list_remote_branches(ssh_url.to_owned(), pem)
        .await
        .map_err(|e| git_problem(e, &ctx.rid))?;
    Ok(RemoteBranches {
        branches: info.branches,
        default_branch: info.default_branch,
        host_fingerprint: info.host_fingerprint,
    })
}

/// `PATCH /api/v1/projects/{project_id}/repositories/{repository_id}`
pub async fn update_repository(
    State(state): State<AppState>,
    ctx: ProjectContext,
    Path(params): Path<HashMap<String, String>>,
    body: Result<Json<UpdateRepositoryRequest>, JsonRejection>,
) -> Response {
    if let Err(r) = ctx.require(Permission::ProjectModify) {
        return r;
    }
    let Some(id) = item_id(&params, "repository_id") else {
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
    let Ok(Some(existing)) = repodb::get(&client, ctx.project.id, id).await else {
        return not_found(&ctx.rid);
    };

    // Validate a newly-assigned key exists in the project.
    if let Some(Some(kid)) = req.ssh_key_id {
        match keydb::get(&client, ctx.project.id, kid).await {
            Ok(Some(_)) => {}
            Ok(None) => return unprocessable(&ctx.rid, "ssh_key_id not found in this project"),
            Err(_) => return internal(&ctx.rid),
        }
    }

    // Re-check reachability when the URL or key changed and a key is in effect.
    let effective_key = match req.ssh_key_id {
        Some(opt) => opt,
        None => existing.ssh_key_id,
    };
    let effective_url = req
        .ssh_url
        .clone()
        .unwrap_or_else(|| existing.ssh_url.clone());
    let url_or_key_changed = req.ssh_url.is_some() || req.ssh_key_id.is_some();
    let mut host_fp_update: Option<Option<String>> = None;
    if url_or_key_changed {
        if let Some(kid) = effective_key {
            // Best-effort (see create_repository): refresh the fingerprint when
            // reachable, but don't block on a connection failure.
            if let Ok(info) = remote_info_for_key(&client, &ctx, auth, kid, &effective_url).await {
                host_fp_update = Some(info.host_fingerprint);
            }
        } else {
            // No key in effect: clear any stale captured fingerprint.
            host_fp_update = Some(None);
        }
    }

    let upd = repodb::RepoUpdate {
        name: req.name.as_deref(),
        ssh_url: req.ssh_url.as_deref(),
        ssh_key_id: req.ssh_key_id,
        default_branch: req.default_branch.as_ref().map(|o| o.as_deref()),
        host_fingerprint: host_fp_update.as_ref().map(|o| o.as_deref()),
    };
    match repodb::update(&client, ctx.project.id, id, &upd).await {
        Ok(Some(repo)) => Json(repo).into_response(),
        Ok(None) => not_found(&ctx.rid),
        Err(e) if e.is_unique_violation() => conflict(&ctx.rid, "repository URL already added"),
        Err(_) => internal(&ctx.rid),
    }
}

/// `DELETE /api/v1/projects/{project_id}/repositories/{repository_id}`
pub async fn delete_repository(
    State(state): State<AppState>,
    ctx: ProjectContext,
    headers: HeaderMap,
    Path(params): Path<HashMap<String, String>>,
) -> Response {
    if let Err(r) = ctx.require(Permission::ProjectModify) {
        return r;
    }
    let Some(id) = item_id(&params, "repository_id") else {
        return not_found(&ctx.rid);
    };
    let auth = state.auth();
    let Ok(client) = auth.db.pool.get().await else {
        return internal(&ctx.rid);
    };
    match repodb::delete(&client, ctx.project.id, id).await {
        Ok(true) => {
            audit::record(
                &client,
                Some(ctx.actor_id),
                "repository.delete",
                Some(client_ip(&headers)),
                Some(&user_agent(&headers)),
                &json!({ "project_id": ctx.project.id, "repository_id": id }),
            )
            .await;
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => not_found(&ctx.rid),
        Err(_) => internal(&ctx.rid),
    }
}

/// `POST /api/v1/projects/{project_id}/repositories/branches`
///
/// Preview the branches of a not-yet-saved repository (drives the
/// default-branch picker during creation).
pub async fn preview_branches(
    State(state): State<AppState>,
    ctx: ProjectContext,
    body: Result<Json<PreviewBranchesRequest>, JsonRejection>,
) -> Response {
    if let Err(r) = ctx.require(Permission::ProjectModify) {
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
    match remote_info_for_key(&client, &ctx, auth, req.ssh_key_id, &req.ssh_url).await {
        Ok(info) => Json(info).into_response(),
        Err(r) => r,
    }
}

/// `GET /api/v1/projects/{project_id}/repositories/{repository_id}/branches`
pub async fn repository_branches(
    State(state): State<AppState>,
    ctx: ProjectContext,
    Path(params): Path<HashMap<String, String>>,
) -> Response {
    if let Err(r) = ctx.require(Permission::ProjectView) {
        return r;
    }
    let Some(id) = item_id(&params, "repository_id") else {
        return not_found(&ctx.rid);
    };
    let auth = state.auth();
    let Ok(client) = auth.db.pool.get().await else {
        return internal(&ctx.rid);
    };
    let Ok(Some(repo)) = repodb::get(&client, ctx.project.id, id).await else {
        return not_found(&ctx.rid);
    };
    let Some(key_id) = repo.ssh_key_id else {
        return unprocessable(&ctx.rid, "repository has no SSH key assigned");
    };
    match remote_info_for_key(&client, &ctx, auth, key_id, &repo.ssh_url).await {
        Ok(info) => Json(info).into_response(),
        Err(r) => r,
    }
}

// --- component <-> repository links ----------------------------------------

/// `GET /api/v1/projects/{project_id}/components/{component_id}/repositories`
pub async fn list_component_repositories(
    State(state): State<AppState>,
    ctx: ProjectContext,
    Path(params): Path<HashMap<String, String>>,
) -> Response {
    if let Err(r) = ctx.require(Permission::ProjectView) {
        return r;
    }
    let Some(component_id) = item_id(&params, "component_id") else {
        return not_found(&ctx.rid);
    };
    let auth = state.auth();
    let Ok(client) = auth.db.pool.get().await else {
        return internal(&ctx.rid);
    };
    // Ensure the component belongs to the project.
    if !component_in_project(&client, &ctx, component_id).await {
        return not_found(&ctx.rid);
    }
    match crdb::list_for_component(&client, component_id).await {
        Ok(items) => Json(json!({ "repositories": items })).into_response(),
        Err(_) => internal(&ctx.rid),
    }
}

async fn component_in_project(
    client: &deadpool_postgres::Client,
    ctx: &ProjectContext,
    component_id: Uuid,
) -> bool {
    matches!(
        compdb::list(client, ctx.project.id).await,
        Ok(items) if items.iter().any(|c| c.id == component_id)
    )
}

/// `POST /api/v1/projects/{project_id}/components/{component_id}/repositories`
pub async fn link_component_repository(
    State(state): State<AppState>,
    ctx: ProjectContext,
    Path(params): Path<HashMap<String, String>>,
    body: Result<Json<LinkRepositoryRequest>, JsonRejection>,
) -> Response {
    if let Err(r) = ctx.require(Permission::ProjectModify) {
        return r;
    }
    let Some(component_id) = item_id(&params, "component_id") else {
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
    if !component_in_project(&client, &ctx, component_id).await {
        return not_found(&ctx.rid);
    }
    // The repository must belong to the same project.
    let Ok(Some(repo)) = repodb::get(&client, ctx.project.id, req.repository_id).await else {
        return unprocessable(&ctx.rid, "repository not found in this project");
    };
    // Validate the branch against the live remote when a key is available.
    if let Err(r) = validate_branch(&client, &ctx, auth, &repo, &req.branch).await {
        return r;
    }
    match crdb::link(&client, component_id, req.repository_id, &req.branch).await {
        Ok(link) => (StatusCode::CREATED, Json(link)).into_response(),
        Err(e) if e.is_unique_violation() => {
            conflict(&ctx.rid, "repository already linked to this component")
        }
        Err(e) if e.is_foreign_key_violation() => not_found(&ctx.rid),
        Err(_) => internal(&ctx.rid),
    }
}

/// Check `branch` exists on the repo's remote. Best-effort: when the repo has
/// no key (cannot be reached) the link is allowed; reachable-but-missing is a
/// hard error, and connection failures surface as git problems.
async fn validate_branch(
    client: &deadpool_postgres::Client,
    ctx: &ProjectContext,
    auth: &AuthContext,
    repo: &intellipilot_core::repo::Repository,
    branch: &str,
) -> Result<(), Response> {
    let Some(key_id) = repo.ssh_key_id else {
        return Ok(());
    };
    match remote_info_for_key(client, ctx, auth, key_id, &repo.ssh_url).await {
        Ok(info) if info.branches.iter().any(|b| b == branch) => Ok(()),
        Ok(_) => Err(unprocessable(&ctx.rid, "branch not found on the remote")),
        // Could not reach the remote to validate — allow (best-effort).
        Err(_) => Ok(()),
    }
}

/// `PATCH /api/v1/projects/{project_id}/components/{component_id}/repositories/{repository_id}`
pub async fn update_component_repository(
    State(state): State<AppState>,
    ctx: ProjectContext,
    Path(params): Path<HashMap<String, String>>,
    body: Result<Json<UpdateLinkRequest>, JsonRejection>,
) -> Response {
    if let Err(r) = ctx.require(Permission::ProjectModify) {
        return r;
    }
    let (Some(component_id), Some(repository_id)) = (
        item_id(&params, "component_id"),
        item_id(&params, "repository_id"),
    ) else {
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
    if !component_in_project(&client, &ctx, component_id).await {
        return not_found(&ctx.rid);
    }
    let Ok(Some(repo)) = repodb::get(&client, ctx.project.id, repository_id).await else {
        return not_found(&ctx.rid);
    };
    if let Err(r) = validate_branch(&client, &ctx, auth, &repo, &req.branch).await {
        return r;
    }
    match crdb::update_branch(&client, component_id, repository_id, &req.branch).await {
        Ok(Some(link)) => Json(link).into_response(),
        Ok(None) => not_found(&ctx.rid),
        Err(_) => internal(&ctx.rid),
    }
}

/// `DELETE /api/v1/projects/{project_id}/components/{component_id}/repositories/{repository_id}`
pub async fn unlink_component_repository(
    State(state): State<AppState>,
    ctx: ProjectContext,
    Path(params): Path<HashMap<String, String>>,
) -> Response {
    if let Err(r) = ctx.require(Permission::ProjectModify) {
        return r;
    }
    let (Some(component_id), Some(repository_id)) = (
        item_id(&params, "component_id"),
        item_id(&params, "repository_id"),
    ) else {
        return not_found(&ctx.rid);
    };
    let auth = state.auth();
    let Ok(client) = auth.db.pool.get().await else {
        return internal(&ctx.rid);
    };
    match crdb::unlink(&client, component_id, repository_id).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => not_found(&ctx.rid),
        Err(_) => internal(&ctx.rid),
    }
}
