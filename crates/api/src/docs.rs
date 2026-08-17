//! External documentation sources: registration, browsing and editing.
//!
//! Two kinds. A **git** source is cloned and served from here, jailed to its
//! `doc_path`. A **web** source is just a URL the client embeds in a frame —
//! nothing is fetched or stored server-side, so every endpoint below that
//! reads content refuses one, and it is read-only by construction.
//!
//! A source can also be **hidden**: withdrawn from navigation while keeping
//! its configuration. Hidden sources reach only callers holding
//! `doc_source.modify`, and read as absent (404) to everyone else.
//!
//! # Containment
//!
//! Everything served for a git source comes out of a cached bare clone,
//! restricted to its `doc_path`. Three independent things keep it there:
//!
//! 1. every client-supplied path goes through
//!    [`intellipilot_core::docs::path::resolve`], which honours `..` and then
//!    *refuses* anything landing above the jail rather than clamping it;
//! 2. content is read from git tree objects, so there is no filesystem path a
//!    request could walk even if (1) were wrong;
//! 3. the git layer skips symlink and submodule entries, so a repository
//!    cannot name anything it does not itself contain.
//!
//! # Editing
//!
//! A save needs three independent things to be true: the caller holds
//! `doc_source.modify`, the source is not flagged `read_only`, and the caller
//! has registered a personal write key. The commit is authored as the caller
//! and pushed with *their* key, so git history attributes it to a person
//! rather than to IntelliPilot.

#![allow(
    clippy::result_large_err,
    clippy::implicit_hasher,
    clippy::too_many_lines
)]

use std::collections::HashMap;
use std::path::PathBuf;

use axum::Json;
use axum::body::Body;
use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use garde::Validate;
use intellipilot_core::docs::{
    DocContent, DocEntry, DocEntryKind, DocSource, DocSourceKind, DocTree, path as jail,
};
use intellipilot_core::perms::Permission;
use intellipilot_db::backlog::UpdateOutcome;
use intellipilot_db::{
    audit, doc_sources as srcdb, doc_user_keys as keysdb, ssh_keys as vaultdb, users as userdb,
};
use intellipilot_git::GitError;
use intellipilot_git::docs as gitdocs;
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use crate::auth::{client_ip, user_agent};
use crate::backlog::{check_if_match, with_etag};
use crate::problem::Problem;
use crate::projects::ProjectContext;
use crate::state::{AppState, AuthContext, DocsConfig};

/// Hard cap on documentation sources per project, as specified.
const MAX_SOURCES_PER_PROJECT: i64 = 10;

/// File extensions listed in the tree and openable as documents.
fn doc_extensions() -> Vec<String> {
    vec!["md".to_owned(), "markdown".to_owned(), "txt".to_owned()]
}

// --- DTOs ------------------------------------------------------------------

/// Accept only SSH transports. An HTTP(S) URL can never authenticate with the
/// deploy key we hold, so taking one would only fail later and confusingly.
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
    if lower.starts_with("ssh://") || (v.contains('@') && v.contains(':')) {
        return Ok(());
    }
    Err(garde::Error::new(
        "must be an SSH URL (git@host:path or ssh://…)",
    ))
}

/// The web URL is rendered as a link and is the destination for anything the
/// jail hides, so it must be a plain http(s) address.
#[allow(clippy::trivially_copy_pass_by_ref)]
fn validate_web_url(value: &str, _ctx: &()) -> garde::Result {
    let lower = value.trim().to_lowercase();
    if lower.starts_with("http://") || lower.starts_with("https://") {
        Ok(())
    } else {
        Err(garde::Error::new("must be an http(s) URL"))
    }
}

#[allow(clippy::trivially_copy_pass_by_ref)]
fn validate_branch(value: &str, _ctx: &()) -> garde::Result {
    if gitdocs::valid_branch_name(value) {
        Ok(())
    } else {
        Err(garde::Error::new("not a valid branch name"))
    }
}

/// Validated at the edge as well as by [`jail::normalize`], so a bad path is
/// reported as a field error rather than a generic failure.
#[allow(clippy::trivially_copy_pass_by_ref)]
fn validate_doc_path(value: &str, _ctx: &()) -> garde::Result {
    jail::normalize(value)
        .map(|_| ())
        .map_err(|_| garde::Error::new("must be a relative path without `..`"))
}

/// Which kind of source is being registered. Defaults to `git`, so a client
/// written before web links existed keeps working unchanged.
#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum DocSourceKindInput {
    #[default]
    Git,
    Web,
}

impl From<DocSourceKindInput> for DocSourceKind {
    fn from(v: DocSourceKindInput) -> Self {
        match v {
            DocSourceKindInput::Git => Self::Git,
            DocSourceKindInput::Web => Self::Web,
        }
    }
}

/// Registration request.
///
/// The kind decides which fields are required: `git` needs an SSH URL, a
/// branch and a key; `web` needs only a name and the page URL. Fields
/// belonging to the other kind are rejected rather than ignored, so a
/// mistyped request fails loudly instead of silently registering something
/// different from what was asked for.
#[derive(Debug, Deserialize, Validate, utoipa::ToSchema)]
pub struct CreateDocSourceRequest {
    #[garde(length(min = 1, max = 128))]
    pub name: String,
    #[garde(skip)]
    #[serde(default)]
    pub kind: DocSourceKindInput,
    /// Git sources only.
    #[garde(inner(custom(validate_ssh_url)))]
    #[serde(default)]
    pub ssh_url: Option<String>,
    /// For a git source, where to send links that escape the shared folder.
    /// For a web source, the page to embed.
    #[garde(custom(validate_web_url), length(max = 1024))]
    pub web_url: String,
    /// Git sources only.
    #[garde(inner(custom(validate_branch)))]
    #[serde(default)]
    pub branch: Option<String>,
    /// Subtree to expose. Empty (the default) means the whole repository.
    /// Git sources only.
    #[garde(custom(validate_doc_path), length(max = 1024))]
    #[serde(default)]
    pub doc_path: String,
    /// Use an existing project deploy key.
    #[garde(skip)]
    #[serde(default)]
    pub ssh_key_id: Option<Uuid>,
    /// Or generate one inline while adding the source.
    #[garde(dive)]
    #[serde(default)]
    pub new_key: Option<crate::repositories::CreateSshKeyRequest>,
    /// Pin the source as never-editable regardless of who holds a write key.
    #[garde(skip)]
    #[serde(default)]
    pub read_only: bool,
    #[garde(length(max = 16))]
    #[serde(default)]
    pub color: String,
    #[garde(length(max = 16))]
    #[serde(default)]
    pub emoji: String,
}

#[derive(Debug, Deserialize, Validate, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct UpdateDocSourceRequest {
    #[garde(length(min = 1, max = 128))]
    #[serde(default)]
    pub name: Option<String>,
    #[garde(inner(custom(validate_web_url), length(max = 1024)))]
    #[serde(default)]
    pub web_url: Option<String>,
    #[garde(inner(custom(validate_branch)))]
    #[serde(default)]
    pub branch: Option<String>,
    #[garde(inner(custom(validate_doc_path), length(max = 1024)))]
    #[serde(default)]
    pub doc_path: Option<String>,
    #[garde(skip)]
    #[serde(default)]
    pub ssh_key_id: Option<Uuid>,
    #[garde(skip)]
    #[serde(default)]
    pub read_only: Option<bool>,
    /// Withdraw the source from navigation without discarding its config.
    #[garde(skip)]
    #[serde(default)]
    pub hidden: Option<bool>,
    #[garde(skip)]
    #[serde(default)]
    pub order: Option<f64>,
    #[garde(length(max = 16))]
    #[serde(default)]
    pub color: Option<String>,
    #[garde(length(max = 16))]
    #[serde(default)]
    pub emoji: Option<String>,
}

#[derive(Debug, Deserialize, Validate, utoipa::ToSchema)]
pub struct SaveDocRequest {
    /// Full new file content.
    #[garde(skip)]
    pub content: String,
    /// Commit message. A default is used when absent.
    #[garde(length(max = 512))]
    #[serde(default)]
    pub message: Option<String>,
}

#[derive(Debug, Deserialize, Validate, utoipa::ToSchema)]
pub struct RegisterDocKeyRequest {
    /// An existing OpenSSH private key to import. Absent means "generate one".
    #[garde(length(max = 16384))]
    #[serde(default)]
    pub private_key: Option<String>,
}

/// `?path=` on the document and blob endpoints.
#[derive(Debug, Deserialize)]
pub struct PathQuery {
    #[serde(default)]
    pub path: String,
}

// --- helpers ---------------------------------------------------------------

fn problem(
    status: StatusCode,
    code: &'static str,
    title: &'static str,
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
fn conflict(rid: &str, code: &'static str, detail: &str) -> Response {
    problem(
        StatusCode::CONFLICT,
        code,
        "Conflict",
        Some(detail.to_owned()),
        rid,
    )
}
fn unprocessable(rid: &str, code: &'static str, detail: &str) -> Response {
    problem(
        StatusCode::UNPROCESSABLE_ENTITY,
        code,
        "Unprocessable",
        Some(detail.to_owned()),
        rid,
    )
}

/// The cache holds nothing usable yet. Retryable, so 503 rather than 404 —
/// the document may well exist, we just cannot read it this instant.
fn not_ready(rid: &str) -> Response {
    problem(
        StatusCode::SERVICE_UNAVAILABLE,
        "doc_source_not_ready",
        "Documentation not ready",
        Some("this source has not finished its first synchronisation".to_owned()),
        rid,
    )
}

fn git_problem(err: GitError, rid: &str) -> Response {
    let (status, title) = match err {
        GitError::AuthFailed => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "Git authentication failed",
        ),
        GitError::NotFound => (StatusCode::UNPROCESSABLE_ENTITY, "Repository not found"),
        GitError::InvalidBranch => (StatusCode::UNPROCESSABLE_ENTITY, "Invalid branch name"),
        GitError::TooLarge => (StatusCode::UNPROCESSABLE_ENTITY, "Repository too large"),
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

/// Reject a registration whose fields do not match its declared kind.
///
/// Fields belonging to the other kind are refused rather than ignored: a
/// request that names a branch on a web link is a mistake, and silently
/// dropping it would register something other than what was asked for.
fn check_kind_fields(
    req: &CreateDocSourceRequest,
    kind: DocSourceKind,
    rid: &str,
) -> Result<(), Response> {
    if kind.is_git() {
        if req.ssh_url.as_deref().unwrap_or("").trim().is_empty() {
            return Err(unprocessable(
                rid,
                "ssh_url_required",
                "a git documentation source needs a repository SSH URL",
            ));
        }
        if req.branch.as_deref().unwrap_or("").trim().is_empty() {
            return Err(unprocessable(
                rid,
                "branch_required",
                "a git documentation source needs a branch",
            ));
        }
        return Ok(());
    }
    // Web link: everything repository-shaped must be absent.
    if req.ssh_url.is_some()
        || req.branch.is_some()
        || req.ssh_key_id.is_some()
        || req.new_key.is_some()
        || !req.doc_path.is_empty()
    {
        return Err(unprocessable(
            rid,
            "web_source_fields",
            "a web documentation source takes only a name and a URL",
        ));
    }
    Ok(())
}

/// Refuse an operation that only makes sense for a cloned repository.
fn require_git_source(source: &DocSource, rid: &str) -> Result<(), Response> {
    if source.kind.is_git() {
        return Ok(());
    }
    Err(unprocessable(
        rid,
        "doc_source_is_web",
        "this documentation source is a web link, not a repository",
    ))
}

/// A hidden source reads as **absent** to anyone who cannot manage it — 404
/// rather than 403, so a bookmark cannot confirm it is merely switched off.
/// Managers still reach it, so they can check a source before unhiding it.
fn visible_to(source: &DocSource, ctx: &ProjectContext) -> bool {
    !source.hidden || ctx.has(Permission::DocSourceModify)
}

fn source_id(params: &HashMap<String, String>, rid: &str) -> Result<Uuid, Response> {
    params
        .get("source_id")
        .and_then(|s| Uuid::parse_str(s).ok())
        .ok_or_else(|| not_found(rid))
}

/// ETag for a source row, matching the `"id:version"` convention used by
/// issues, epics and milestones.
fn source_etag(s: &DocSource) -> String {
    format!("\"{}:{}\"", s.id, s.version)
}

/// Load a source, or produce the 404. A hidden source is invisible to anyone
/// who cannot manage it, which is indistinguishable from not existing.
async fn load_source(
    client: &deadpool_postgres::Client,
    ctx: &ProjectContext,
    id: Uuid,
) -> Result<DocSource, Response> {
    match srcdb::get(client, ctx.project.id, id).await {
        Ok(Some(s)) if visible_to(&s, ctx) => Ok(s),
        Ok(_) => Err(not_found(&ctx.rid)),
        Err(_) => Err(internal(&ctx.rid)),
    }
}

fn decrypt_key(enc: &[u8], pepper: &[u8], rid: &str) -> Result<String, Response> {
    let plain = intellipilot_auth::secret::decrypt(Some(pepper), enc).map_err(|_| internal(rid))?;
    String::from_utf8(plain).map_err(|_| internal(rid))
}

// --- synchronisation -------------------------------------------------------

/// Clone or fetch a source, updating its cache bookkeeping.
///
/// Returns `Ok(false)` when the claim was refused because a sync ran too
/// recently — the caller treats that as success, since the cache is by
/// definition fresh.
///
/// The per-source lock is held for the whole operation so a fetch can never
/// interleave with an edit's push on the same repository.
pub async fn sync_source(
    state: &AppState,
    project_id: Uuid,
    source: &DocSource,
    force: bool,
) -> Result<bool, GitError> {
    // A web link has no repository behind it, so "refreshing" it is a no-op
    // rather than an error — the page is fetched by the browser, live.
    if !source.kind.is_git() {
        return Ok(false);
    }
    let docs = &state.docs;
    let lock = docs.lock_for(source.id);
    let _guard = lock.lock().await;

    let auth = state.auth();
    let Ok(client) = auth.db.pool.get().await else {
        return Err(GitError::Internal);
    };

    let gap = if force {
        0.0
    } else {
        docs.min_sync_gap.as_secs_f64()
    };
    match srcdb::claim_for_sync(&client, source.id, gap).await {
        Ok(true) => {}
        Ok(false) => return Ok(false),
        Err(_) => return Err(GitError::Internal),
    }

    let outcome = sync_inner(&client, auth, docs, project_id, source).await;
    match &outcome {
        Ok(o) => {
            let bytes = i64::try_from(o.received_bytes).unwrap_or(i64::MAX);
            drop(
                srcdb::mark_synced(
                    &client,
                    source.id,
                    &o.head_commit,
                    bytes,
                    o.host_fingerprint.as_deref(),
                )
                .await,
            );
        }
        Err(e) => {
            drop(srcdb::mark_failed(&client, source.id, &e.to_string()).await);
        }
    }
    outcome.map(|_| true)
}

async fn sync_inner(
    client: &deadpool_postgres::Client,
    auth: &AuthContext,
    docs: &DocsConfig,
    project_id: Uuid,
    source: &DocSource,
) -> Result<gitdocs::SyncOutcome, GitError> {
    let Some(key_id) = source.ssh_key_id else {
        return Err(GitError::AuthFailed);
    };
    let pepper = auth.pepper_bytes().ok_or(GitError::Internal)?;
    let enc = vaultdb::private_key_enc(client, project_id, key_id)
        .await
        .map_err(|_| GitError::Internal)?
        .ok_or(GitError::AuthFailed)?;
    let key = intellipilot_auth::secret::decrypt(Some(pepper), &enc)
        .ok()
        .and_then(|b| String::from_utf8(b).ok())
        .ok_or(GitError::Internal)?;

    gitdocs::sync(
        docs.dir_for(project_id, source.id),
        source.ssh_url_or_empty(),
        source.branch_or_empty(),
        key,
        docs.max_source_bytes,
    )
    .await
}

/// Kick off a first clone without making the caller wait for it. Registration
/// already verified the remote is reachable, so the common failure modes are
/// reported synchronously; this only covers the transfer itself.
fn spawn_initial_sync(state: &AppState, project_id: Uuid, source: DocSource) {
    if !source.kind.is_git() {
        return;
    }
    let state = state.clone();
    tokio::spawn(async move {
        if let Err(e) = sync_source(&state, project_id, &source, true).await {
            tracing::warn!(
                source_id = %source.id,
                error = %e,
                "initial documentation sync failed"
            );
        }
    });
}

// --- source CRUD -----------------------------------------------------------

/// `GET /api/v1/projects/{project_id}/doc-sources`
pub async fn list_sources(State(state): State<AppState>, ctx: ProjectContext) -> Response {
    if let Err(r) = ctx.require(Permission::DocSourceView) {
        return r;
    }
    let Ok(client) = state.auth().db.pool.get().await else {
        return internal(&ctx.rid);
    };
    match srcdb::list(&client, ctx.project.id).await {
        // Hidden sources reach only the people who can unhide them, so the
        // settings tab sees everything while navigation sees what is live.
        Ok(items) => {
            let visible: Vec<_> = items.into_iter().filter(|s| visible_to(s, &ctx)).collect();
            Json(json!({ "doc_sources": visible })).into_response()
        }
        Err(_) => internal(&ctx.rid),
    }
}

/// `GET /api/v1/projects/{project_id}/doc-sources/{source_id}`
pub async fn get_source(
    State(state): State<AppState>,
    ctx: ProjectContext,
    Path(params): Path<HashMap<String, String>>,
) -> Response {
    if let Err(r) = ctx.require(Permission::DocSourceView) {
        return r;
    }
    let id = match source_id(&params, &ctx.rid) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let Ok(client) = state.auth().db.pool.get().await else {
        return internal(&ctx.rid);
    };
    match load_source(&client, &ctx, id).await {
        Ok(s) => with_etag(StatusCode::OK, s.id, s.version, &s),
        Err(r) => r,
    }
}

/// `POST /api/v1/projects/{project_id}/doc-sources`
pub async fn create_source(
    State(state): State<AppState>,
    ctx: ProjectContext,
    headers: HeaderMap,
    body: Result<Json<CreateDocSourceRequest>, JsonRejection>,
) -> Response {
    if let Err(r) = ctx.require(Permission::DocSourceCreate) {
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

    match srcdb::count(&client, ctx.project.id).await {
        Ok(n) if n >= MAX_SOURCES_PER_PROJECT => {
            return conflict(
                &ctx.rid,
                "limit_reached",
                "a project may have at most 10 documentation sources",
            );
        }
        Ok(_) => {}
        Err(_) => return internal(&ctx.rid),
    }

    let kind: DocSourceKind = req.kind.into();
    if let Err(r) = check_kind_fields(&req, kind, &ctx.rid) {
        return r;
    }

    // A web link is registered as-is: there is nothing to clone, no key to
    // resolve and no remote to probe.
    let (key_id, branch, doc_path) = if kind.is_git() {
        // Resolve the key first: either an existing one or a freshly
        // generated deploy key, mirroring how repositories are registered.
        let key_id =
            match resolve_key(&client, &ctx, auth, req.ssh_key_id, req.new_key.as_ref()).await {
                Ok(v) => v,
                Err(r) => return r,
            };

        // Verify the remote answers *before* storing anything, so a typo in
        // the URL or an unregistered deploy key is reported immediately
        // rather than as a silent background failure.
        let key_pem = match load_key_pem(&client, auth, ctx.project.id, key_id, &ctx.rid).await {
            Ok(v) => v,
            Err(r) => return r,
        };
        let ssh_url = req.ssh_url.clone().unwrap_or_default();
        let branch = req.branch.clone().unwrap_or_default();
        let info = match intellipilot_git::list_remote_branches(ssh_url, key_pem).await {
            Ok(v) => v,
            Err(e) => return git_problem(e, &ctx.rid),
        };
        if !info.branches.contains(&branch) {
            return unprocessable(
                &ctx.rid,
                "branch_not_found",
                "the repository has no branch by that name",
            );
        }
        let Ok(doc_path) = jail::normalize(&req.doc_path) else {
            return unprocessable(
                &ctx.rid,
                "doc_path_illegal",
                "the documentation path must be relative and must not contain `..`",
            );
        };
        (Some(key_id), Some(branch), doc_path)
    } else {
        (None, None, String::new())
    };

    let new = srcdb::DocSourceNew {
        name: req.name.trim(),
        kind,
        ssh_url: req.ssh_url.as_deref().map(str::trim),
        // A git source's web URL is a browse base, so a trailing slash is
        // noise; a web source's IS the page, and trimming could change it.
        web_url: if kind.is_git() {
            req.web_url.trim().trim_end_matches('/')
        } else {
            req.web_url.trim()
        },
        branch: branch.as_deref(),
        doc_path: &doc_path,
        ssh_key_id: key_id,
        // A web link can never be edited: there is nowhere to push to.
        read_only: !kind.is_git() || req.read_only,
        color: &req.color,
        emoji: &req.emoji,
        created_by: ctx.actor_id,
    };
    let source = match srcdb::create(&client, ctx.project.id, &new).await {
        Ok(s) => s,
        Err(e) if e.is_unique_violation() => {
            return conflict(
                &ctx.rid,
                "already_exists",
                "a documentation source with that name already exists",
            );
        }
        Err(_) => return internal(&ctx.rid),
    };

    audit::record(
        &client,
        Some(ctx.actor_id),
        "doc_source.create",
        Some(client_ip(&headers)),
        Some(&user_agent(&headers)),
        &json!({
            "project_id": ctx.project.id,
            "doc_source_id": source.id,
            "name": source.name,
            "ssh_url": source.ssh_url,
            "doc_path": source.doc_path,
        }),
    )
    .await;

    spawn_initial_sync(&state, ctx.project.id, source.clone());
    with_etag(StatusCode::CREATED, source.id, source.version, &source)
}

/// Pick an existing key or generate one inline.
async fn resolve_key(
    client: &deadpool_postgres::Client,
    ctx: &ProjectContext,
    auth: &AuthContext,
    existing: Option<Uuid>,
    new_key: Option<&crate::repositories::CreateSshKeyRequest>,
) -> Result<Uuid, Response> {
    if let Some(id) = existing {
        return match vaultdb::get(client, ctx.project.id, id).await {
            Ok(Some(_)) => Ok(id),
            Ok(None) => Err(unprocessable(
                &ctx.rid,
                "ssh_key_not_found",
                "no such SSH key in this project",
            )),
            Err(_) => Err(internal(&ctx.rid)),
        };
    }
    let Some(spec) = new_key else {
        return Err(unprocessable(
            &ctx.rid,
            "ssh_key_required",
            "either ssh_key_id or new_key must be supplied",
        ));
    };
    let pepper = require_pepper(auth, &ctx.rid)?;
    let generated =
        intellipilot_auth::sshkey::generate_ed25519().map_err(|_| internal(&ctx.rid))?;
    let enc =
        intellipilot_auth::secret::encrypt(Some(pepper), generated.private_openssh.as_bytes())
            .map_err(|_| internal(&ctx.rid))?;
    let created = vaultdb::create(
        client,
        ctx.project.id,
        &vaultdb::NewSshKey {
            name: &spec.name,
            // Documentation deploy keys only ever read; writes use the
            // editor's own key.
            read_only: true,
            key_type: &generated.key_type,
            public_key: &generated.public_openssh,
            private_key_enc: &enc,
            fingerprint: &generated.fingerprint,
            created_by: ctx.actor_id,
        },
    )
    .await
    .map_err(|_| internal(&ctx.rid))?;
    Ok(created.id)
}

async fn load_key_pem(
    client: &deadpool_postgres::Client,
    auth: &AuthContext,
    project_id: Uuid,
    key_id: Uuid,
    rid: &str,
) -> Result<String, Response> {
    let pepper = require_pepper(auth, rid)?;
    let Ok(Some(enc)) = vaultdb::private_key_enc(client, project_id, key_id).await else {
        return Err(internal(rid));
    };
    decrypt_key(&enc, pepper, rid)
}

/// `PATCH /api/v1/projects/{project_id}/doc-sources/{source_id}`
pub async fn update_source(
    State(state): State<AppState>,
    ctx: ProjectContext,
    Path(params): Path<HashMap<String, String>>,
    headers: HeaderMap,
    body: Result<Json<UpdateDocSourceRequest>, JsonRejection>,
) -> Response {
    if let Err(r) = ctx.require(Permission::DocSourceModify) {
        return r;
    }
    let id = match source_id(&params, &ctx.rid) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let req = match parse_body(body, &ctx.rid) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let Ok(client) = state.auth().db.pool.get().await else {
        return internal(&ctx.rid);
    };
    let current = match load_source(&client, &ctx, id).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    if let Err(r) = check_if_match(&headers, &source_etag(&current), &ctx.rid) {
        return r;
    }
    // A web link has no branch, folder or key to change. Refuse rather than
    // let the CHECK constraint turn a client mistake into a 500.
    if !current.kind.is_git()
        && (req.branch.is_some() || req.doc_path.is_some() || req.ssh_key_id.is_some())
    {
        return unprocessable(
            &ctx.rid,
            "web_source_fields",
            "a web documentation source has no branch, folder or key",
        );
    }
    // Likewise, a web link can never become editable.
    if !current.kind.is_git() && req.read_only == Some(false) {
        return unprocessable(
            &ctx.rid,
            "web_source_read_only",
            "a web documentation source is always read-only",
        );
    }

    let doc_path = match req.doc_path.as_deref().map(jail::normalize) {
        Some(Ok(p)) => Some(p),
        Some(Err(_)) => {
            return unprocessable(
                &ctx.rid,
                "doc_path_illegal",
                "the documentation path must be relative and must not contain `..`",
            );
        }
        None => None,
    };
    let web_url = req
        .web_url
        .as_deref()
        .map(|u| u.trim().trim_end_matches('/').to_owned());

    let patch = srcdb::DocSourcePatch {
        name: req.name.as_deref().map(str::trim),
        web_url: web_url.as_deref(),
        branch: req.branch.as_deref(),
        doc_path: doc_path.as_deref(),
        ssh_key_id: req.ssh_key_id.map(Some),
        read_only: req.read_only,
        hidden: req.hidden,
        order: req.order,
        color: req.color.as_deref(),
        emoji: req.emoji.as_deref(),
    };
    let resync = patch.invalidates_cache();

    match srcdb::update(&client, ctx.project.id, id, current.version, &patch).await {
        Ok(UpdateOutcome::Updated(s)) => {
            if resync {
                spawn_initial_sync(&state, ctx.project.id, s.clone());
            }
            with_etag(StatusCode::OK, s.id, s.version, &s)
        }
        Ok(UpdateOutcome::NotFound) => not_found(&ctx.rid),
        Ok(UpdateOutcome::Conflict) => problem(
            StatusCode::PRECONDITION_FAILED,
            "precondition_failed",
            "Precondition Failed",
            Some("this documentation source changed since you loaded it".to_owned()),
            &ctx.rid,
        ),
        Err(e) if e.is_unique_violation() => conflict(
            &ctx.rid,
            "already_exists",
            "a documentation source with that name already exists",
        ),
        Err(_) => internal(&ctx.rid),
    }
}

/// `DELETE /api/v1/projects/{project_id}/doc-sources/{source_id}`
pub async fn delete_source(
    State(state): State<AppState>,
    ctx: ProjectContext,
    Path(params): Path<HashMap<String, String>>,
    headers: HeaderMap,
) -> Response {
    if let Err(r) = ctx.require(Permission::DocSourceDelete) {
        return r;
    }
    let id = match source_id(&params, &ctx.rid) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let Ok(client) = state.auth().db.pool.get().await else {
        return internal(&ctx.rid);
    };
    match srcdb::delete(&client, ctx.project.id, id).await {
        Ok(true) => {}
        Ok(false) => return not_found(&ctx.rid),
        Err(_) => return internal(&ctx.rid),
    }

    // Reclaim the disk. Failure here is logged, never surfaced: the source is
    // gone as far as the user is concerned, and a stale directory is only
    // wasted space.
    let dir = state.docs.dir_for(ctx.project.id, id);
    if let Err(e) = gitdocs::remove_cache(&dir) {
        tracing::warn!(source_id = %id, error = %e, "could not remove documentation cache");
    }
    state.docs.forget_lock(id);

    audit::record(
        &client,
        Some(ctx.actor_id),
        "doc_source.delete",
        Some(client_ip(&headers)),
        Some(&user_agent(&headers)),
        &json!({ "project_id": ctx.project.id, "doc_source_id": id }),
    )
    .await;
    StatusCode::NO_CONTENT.into_response()
}

/// `POST /api/v1/projects/{project_id}/doc-sources/{source_id}/sync`
///
/// Anyone who can read the docs may ask for a refresh; the rate limit lives in
/// `claim_for_sync`, so a burst of clicks costs one fetch.
pub async fn sync_now(
    State(state): State<AppState>,
    ctx: ProjectContext,
    Path(params): Path<HashMap<String, String>>,
) -> Response {
    if let Err(r) = ctx.require(Permission::DocSourceView) {
        return r;
    }
    let id = match source_id(&params, &ctx.rid) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let Ok(client) = state.auth().db.pool.get().await else {
        return internal(&ctx.rid);
    };
    let source = match load_source(&client, &ctx, id).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    drop(client);

    if let Err(e) = sync_source(&state, ctx.project.id, &source, false).await {
        return git_problem(e, &ctx.rid);
    }
    let Ok(client) = state.auth().db.pool.get().await else {
        return internal(&ctx.rid);
    };
    match load_source(&client, &ctx, id).await {
        Ok(s) => with_etag(StatusCode::OK, s.id, s.version, &s),
        Err(r) => r,
    }
}

// --- browsing --------------------------------------------------------------

/// The cache directory for a ready git source, or the response explaining why
/// there isn't one.
fn ready_dir(
    state: &AppState,
    project_id: Uuid,
    s: &DocSource,
    rid: &str,
) -> Result<PathBuf, Response> {
    require_git_source(s, rid)?;
    if s.head_commit.is_none() {
        return Err(not_ready(rid));
    }
    Ok(state.docs.dir_for(project_id, s.id))
}

/// `GET /api/v1/projects/{project_id}/doc-sources/{source_id}/tree`
pub async fn tree(
    State(state): State<AppState>,
    ctx: ProjectContext,
    Path(params): Path<HashMap<String, String>>,
) -> Response {
    if let Err(r) = ctx.require(Permission::DocSourceView) {
        return r;
    }
    let id = match source_id(&params, &ctx.rid) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let Ok(client) = state.auth().db.pool.get().await else {
        return internal(&ctx.rid);
    };
    let source = match load_source(&client, &ctx, id).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    let dir = match ready_dir(&state, ctx.project.id, &source, &ctx.rid) {
        Ok(d) => d,
        Err(r) => return r,
    };

    let read = gitdocs::read_tree(
        dir,
        source.branch_or_empty(),
        source.doc_path.clone(),
        doc_extensions(),
    )
    .await;
    match read {
        Ok(Some((raw, commit))) => {
            let entries = nest(&raw);
            let entry_path = pick_entry(&entries);
            Json(DocTree {
                source_id: source.id,
                commit,
                entries,
                entry_path,
            })
            .into_response()
        }
        // The configured subtree is not in the repository: a misconfiguration,
        // reported as such rather than as an empty documentation set.
        Ok(None) => unprocessable(
            &ctx.rid,
            "doc_path_missing",
            "the configured documentation path does not exist in this repository",
        ),
        Err(e) => git_problem(e, &ctx.rid),
    }
}

/// Parent path of a jail-relative path (`""` for a top-level entry).
fn parent_of(path: &str) -> &str {
    path.rsplit_once('/').map_or("", |(p, _)| p)
}

/// Assemble the flat walk output into the nested shape the sidebar renders.
/// Linear in the number of entries: children are indexed by parent path once,
/// then the tree is built by descent.
fn nest(raw: &[gitdocs::RawEntry]) -> Vec<DocEntry> {
    let mut by_parent: HashMap<&str, Vec<usize>> = HashMap::new();
    for (i, e) in raw.iter().enumerate() {
        by_parent.entry(parent_of(&e.path)).or_default().push(i);
    }
    build_level(raw, &by_parent, "", 0)
}

fn build_level(
    raw: &[gitdocs::RawEntry],
    by_parent: &HashMap<&str, Vec<usize>>,
    prefix: &str,
    depth: usize,
) -> Vec<DocEntry> {
    // The walk already bounds depth; this is belt-and-braces against a cycle
    // that could only exist if the input were malformed.
    if depth > 64 {
        return Vec::new();
    }
    let Some(indices) = by_parent.get(prefix) else {
        return Vec::new();
    };
    let mut level: Vec<DocEntry> = indices
        .iter()
        .filter_map(|i| raw.get(*i))
        .map(|e| DocEntry {
            path: e.path.clone(),
            name: e.name.clone(),
            kind: if e.is_dir {
                DocEntryKind::Dir
            } else {
                DocEntryKind::Doc
            },
            size: (!e.is_dir).then(|| i64::try_from(e.size).unwrap_or(i64::MAX)),
            children: if e.is_dir {
                build_level(raw, by_parent, &e.path, depth.saturating_add(1))
            } else {
                Vec::new()
            },
        })
        .collect();
    // Directories first, then case-insensitive by name — the ordering every
    // file browser uses.
    level.sort_by(|a, b| {
        let dir = (b.kind == DocEntryKind::Dir).cmp(&(a.kind == DocEntryKind::Dir));
        dir.then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
    });
    level
}

/// Homepage of a source: the first of README / index / home present at the
/// jail root, case-insensitively.
fn pick_entry(entries: &[DocEntry]) -> Option<String> {
    for candidate in jail::ENTRY_CANDIDATES {
        if let Some(found) = entries
            .iter()
            .find(|e| e.kind == DocEntryKind::Doc && e.name.eq_ignore_ascii_case(candidate))
        {
            return Some(found.path.clone());
        }
    }
    None
}

/// Resolve a client path inside the jail, or produce the refusal.
fn resolve_path(source: &DocSource, raw: &str, rid: &str) -> Result<(String, String), Response> {
    let resolved = jail::resolve(raw).map_err(|e| {
        // An escape is not an error the user can fix by retrying — it means
        // the link pointed outside what this source shares.
        unprocessable(
            rid,
            e.code(),
            "that path is outside the shared documentation folder",
        )
    })?;
    if resolved.is_empty() {
        return Err(not_found(rid));
    }
    let in_repo = jail::in_repo(&source.doc_path, &resolved);
    Ok((resolved, in_repo))
}

/// `GET /api/v1/projects/{project_id}/doc-sources/{source_id}/doc?path=…`
pub async fn get_doc(
    State(state): State<AppState>,
    ctx: ProjectContext,
    Path(params): Path<HashMap<String, String>>,
    Query(q): Query<PathQuery>,
) -> Response {
    if let Err(r) = ctx.require(Permission::DocSourceView) {
        return r;
    }
    let id = match source_id(&params, &ctx.rid) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let Ok(client) = state.auth().db.pool.get().await else {
        return internal(&ctx.rid);
    };
    let source = match load_source(&client, &ctx, id).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    let dir = match ready_dir(&state, ctx.project.id, &source, &ctx.rid) {
        Ok(d) => d,
        Err(r) => return r,
    };
    let (rel, in_repo) = match resolve_path(&source, &q.path, &ctx.rid) {
        Ok(v) => v,
        Err(r) => return r,
    };
    if !jail::is_doc(&rel) {
        return not_found(&ctx.rid);
    }

    let blob = match gitdocs::read_blob(
        dir.clone(),
        source.branch_or_empty(),
        in_repo.clone(),
        state.docs.max_file_bytes,
    )
    .await
    {
        Ok(Some(b)) => b,
        Ok(None) => return not_found(&ctx.rid),
        Err(e) => return git_problem(e, &ctx.rid),
    };
    let Ok(body) = String::from_utf8(blob.bytes) else {
        return unprocessable(
            &ctx.rid,
            "doc_not_text",
            "this file is not valid UTF-8 text",
        );
    };

    // Editable only if all three conditions hold. Checked here so the client
    // never has to guess, and re-checked on save.
    let has_key = keysdb::exists(&client, ctx.project.id, ctx.actor_id)
        .await
        .unwrap_or(false);
    let can_edit = !source.read_only && ctx.has(Permission::DocSourceModify) && has_key;

    let last_commit = gitdocs::last_commit_for(dir, source.branch_or_empty(), in_repo)
        .await
        .ok()
        .flatten()
        .and_then(|c| {
            Some(intellipilot_core::docs::DocCommitInfo {
                sha: c.sha,
                author_name: c.author_name,
                message: c.message,
                committed_at: time::OffsetDateTime::from_unix_timestamp(c.committed_at).ok()?,
            })
        });

    let content = DocContent {
        source_id: source.id,
        path: rel,
        body,
        blob_oid: blob.oid.clone(),
        commit: source.head_commit.clone().unwrap_or_default(),
        can_edit,
        last_commit,
    };
    let mut resp = Json(content).into_response();
    if let Ok(v) = HeaderValue::from_str(&format!("\"{}\"", blob.oid)) {
        resp.headers_mut().insert(header::ETAG, v);
    }
    resp
}

/// `GET /api/v1/projects/{project_id}/doc-sources/{source_id}/blob?path=…`
///
/// Images referenced by a document. Restricted to a mime allowlist and to the
/// jail; SVG is sanitized before it leaves the server, since it is the one
/// image format that can carry script.
pub async fn get_blob(
    State(state): State<AppState>,
    ctx: ProjectContext,
    Path(params): Path<HashMap<String, String>>,
    Query(q): Query<PathQuery>,
) -> Response {
    if let Err(r) = ctx.require(Permission::DocSourceView) {
        return r;
    }
    let id = match source_id(&params, &ctx.rid) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let Ok(client) = state.auth().db.pool.get().await else {
        return internal(&ctx.rid);
    };
    let source = match load_source(&client, &ctx, id).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    let dir = match ready_dir(&state, ctx.project.id, &source, &ctx.rid) {
        Ok(d) => d,
        Err(r) => return r,
    };
    let (rel, in_repo) = match resolve_path(&source, &q.path, &ctx.rid) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let Some(mime) = jail::image_mime(&rel) else {
        return not_found(&ctx.rid);
    };

    let blob = match gitdocs::read_blob(
        dir,
        source.branch_or_empty(),
        in_repo,
        state.docs.max_file_bytes,
    )
    .await
    {
        Ok(Some(b)) => b,
        Ok(None) => return not_found(&ctx.rid),
        Err(e) => return git_problem(e, &ctx.rid),
    };

    let bytes = if jail::is_svg(&rel) {
        match String::from_utf8(blob.bytes) {
            Ok(svg) => ammonia::clean(&svg).into_bytes(),
            // Not text, so not an SVG we can vouch for.
            Err(_) => return not_found(&ctx.rid),
        }
    } else {
        blob.bytes
    };

    let mut resp = Response::new(Body::from(bytes));
    let h = resp.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static(mime));
    // Blobs are content-addressed, so a long private cache is safe.
    h.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, max-age=3600"),
    );
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    // Belt and braces for the SVG case: never let one render as a document.
    h.insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_static("inline"),
    );
    if let Ok(v) = HeaderValue::from_str(&format!("\"{}\"", blob.oid)) {
        h.insert(header::ETAG, v);
    }
    resp
}

// --- editing ---------------------------------------------------------------

/// `PUT /api/v1/projects/{project_id}/doc-sources/{source_id}/doc?path=…`
pub async fn save_doc(
    State(state): State<AppState>,
    ctx: ProjectContext,
    Path(params): Path<HashMap<String, String>>,
    Query(q): Query<PathQuery>,
    headers: HeaderMap,
    body: Result<Json<SaveDocRequest>, JsonRejection>,
) -> Response {
    if let Err(r) = ctx.require(Permission::DocSourceModify) {
        return r;
    }
    let id = match source_id(&params, &ctx.rid) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let req = match parse_body(body, &ctx.rid) {
        Ok(v) => v,
        Err(r) => return r,
    };
    if req.content.len() as u64 > state.docs.max_file_bytes {
        return unprocessable(
            &ctx.rid,
            "doc_too_large",
            "this document is too large to save",
        );
    }

    let auth = state.auth();
    let Ok(client) = auth.db.pool.get().await else {
        return internal(&ctx.rid);
    };
    let source = match load_source(&client, &ctx, id).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    if let Err(r) = require_git_source(&source, &ctx.rid) {
        return r;
    }
    if source.read_only {
        return conflict(
            &ctx.rid,
            "doc_source_read_only",
            "this documentation source is marked read-only",
        );
    }
    let (rel, in_repo) = match resolve_path(&source, &q.path, &ctx.rid) {
        Ok(v) => v,
        Err(r) => return r,
    };
    if !jail::is_doc(&rel) {
        return not_found(&ctx.rid);
    }

    // The push authenticates as the editor, using the key they registered.
    let pepper = match require_pepper(auth, &ctx.rid) {
        Ok(p) => p,
        Err(r) => return r,
    };
    let Ok(Some(enc)) = keysdb::private_key_enc(&client, ctx.project.id, ctx.actor_id).await else {
        return conflict(
            &ctx.rid,
            "doc_write_key_missing",
            "you have not configured a write-capable SSH key for this project",
        );
    };
    let key_pem = match decrypt_key(&enc, pepper, &ctx.rid) {
        Ok(v) => v,
        Err(r) => return r,
    };

    let Ok(Some(user)) = userdb::find_by_id(&client, ctx.actor_id).await else {
        return internal(&ctx.rid);
    };

    // `If-Match` carries the blob OID the editor loaded. `*` means "create or
    // overwrite blindly", which we deliberately do not support: an edit must
    // always name what it is replacing.
    let expected = headers
        .get(header::IF_MATCH)
        .and_then(|v| v.to_str().ok())
        .map(|v| {
            v.trim()
                .trim_start_matches("W/")
                .trim_matches('"')
                .to_owned()
        });
    let Some(expected_raw) = expected else {
        return problem(
            StatusCode::PRECONDITION_REQUIRED,
            "precondition_required",
            "Precondition Required",
            Some("If-Match header is required for updates".to_owned()),
            &ctx.rid,
        );
    };
    // The sentinel for "this file does not exist yet".
    let expected_blob_oid = (expected_raw != "new").then_some(expected_raw);

    // Refresh before writing so the commit lands on the current tip; without
    // this every edit after the first would be a guaranteed non-fast-forward.
    if let Err(e) = sync_source(&state, ctx.project.id, &source, true).await {
        return git_problem(e, &ctx.rid);
    }

    let lock = state.docs.lock_for(source.id);
    let _guard = lock.lock().await;

    let message = req.message.unwrap_or_else(|| format!("Update {rel}"));
    let outcome = gitdocs::edit_and_push(gitdocs::EditRequest {
        repo_dir: state.docs.dir_for(ctx.project.id, source.id),
        ssh_url: source.ssh_url_or_empty(),
        branch: source.branch_or_empty(),
        private_key_pem: key_pem,
        repo_path: in_repo,
        content: req.content.into_bytes(),
        expected_blob_oid,
        author_name: user.full_name.clone(),
        author_email: user.email.clone(),
        message,
    })
    .await;

    match outcome {
        Ok(gitdocs::PushOutcome::Pushed { commit, blob_oid }) => {
            drop(
                srcdb::mark_synced(
                    &client,
                    source.id,
                    &commit,
                    source.cache_bytes,
                    source.host_fingerprint.as_deref(),
                )
                .await,
            );
            audit::record(
                &client,
                Some(ctx.actor_id),
                "doc_source.edit",
                Some(client_ip(&headers)),
                Some(&user_agent(&headers)),
                &json!({
                    "project_id": ctx.project.id,
                    "doc_source_id": source.id,
                    "path": rel,
                    "commit": commit,
                }),
            )
            .await;
            let mut resp = Json(json!({
                "path": rel,
                "commit": commit,
                "blob_oid": blob_oid,
            }))
            .into_response();
            if let Ok(v) = HeaderValue::from_str(&format!("\"{blob_oid}\"")) {
                resp.headers_mut().insert(header::ETAG, v);
            }
            resp
        }
        Ok(gitdocs::PushOutcome::Conflict) => problem(
            StatusCode::PRECONDITION_FAILED,
            "precondition_failed",
            "Precondition Failed",
            Some("this document changed since you opened it".to_owned()),
            &ctx.rid,
        ),
        Ok(gitdocs::PushOutcome::Rejected(msg)) => conflict(
            &ctx.rid,
            "doc_push_rejected",
            &format!("the git host refused the change: {msg}"),
        ),
        Err(e) => git_problem(e, &ctx.rid),
    }
}

// --- personal write keys ---------------------------------------------------

/// `GET /api/v1/projects/{project_id}/doc-keys/me`
pub async fn get_my_key(State(state): State<AppState>, ctx: ProjectContext) -> Response {
    if let Err(r) = ctx.require(Permission::DocSourceView) {
        return r;
    }
    let Ok(client) = state.auth().db.pool.get().await else {
        return internal(&ctx.rid);
    };
    match keysdb::get(&client, ctx.project.id, ctx.actor_id).await {
        Ok(Some(k)) => Json(k).into_response(),
        Ok(None) => Json(json!({ "doc_key": null })).into_response(),
        Err(_) => internal(&ctx.rid),
    }
}

/// `PUT /api/v1/projects/{project_id}/doc-keys/me`
///
/// Generates a keypair, or imports one the caller supplies. Only the caller
/// can register their own key — there is no endpoint to set someone else's,
/// because the key is what makes a commit attributable to them.
pub async fn put_my_key(
    State(state): State<AppState>,
    ctx: ProjectContext,
    headers: HeaderMap,
    body: Result<Json<RegisterDocKeyRequest>, JsonRejection>,
) -> Response {
    if let Err(r) = ctx.require(Permission::DocSourceModify) {
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

    let (key, origin) = match req.private_key.as_deref().map(str::trim) {
        None | Some("") => match intellipilot_auth::sshkey::generate_ed25519() {
            Ok(g) => (g, "generated"),
            Err(_) => return internal(&ctx.rid),
        },
        Some(pem) => match intellipilot_auth::sshkey::import_openssh(pem) {
            Ok(k) => (k, "imported"),
            Err(e) => return unprocessable(&ctx.rid, "invalid_private_key", &e.to_string()),
        },
    };

    let Ok(enc) = intellipilot_auth::secret::encrypt(Some(pepper), key.private_openssh.as_bytes())
    else {
        return internal(&ctx.rid);
    };
    let stored = keysdb::upsert(
        &client,
        ctx.project.id,
        ctx.actor_id,
        &keysdb::NewDocUserKey {
            key_type: &key.key_type,
            public_key: &key.public_openssh,
            private_key_enc: &enc,
            fingerprint: &key.fingerprint,
            origin,
        },
    )
    .await;

    match stored {
        Ok(k) => {
            audit::record(
                &client,
                Some(ctx.actor_id),
                "doc_user_key.register",
                Some(client_ip(&headers)),
                Some(&user_agent(&headers)),
                &json!({
                    "project_id": ctx.project.id,
                    "fingerprint": k.fingerprint,
                    "origin": k.origin,
                }),
            )
            .await;
            (StatusCode::OK, Json(k)).into_response()
        }
        Err(_) => internal(&ctx.rid),
    }
}

/// `DELETE /api/v1/projects/{project_id}/doc-keys/me`
pub async fn delete_my_key(State(state): State<AppState>, ctx: ProjectContext) -> Response {
    if let Err(r) = ctx.require(Permission::DocSourceView) {
        return r;
    }
    let Ok(client) = state.auth().db.pool.get().await else {
        return internal(&ctx.rid);
    };
    match keysdb::delete(&client, ctx.project.id, ctx.actor_id).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => not_found(&ctx.rid),
        Err(_) => internal(&ctx.rid),
    }
}

// --- background refresher --------------------------------------------------

/// Refresh every source whose last attempt is older than the configured
/// interval. Called on a ticker from the binary.
pub async fn refresh_due(state: &AppState) {
    let docs = state.docs.clone();
    let Some(auth) = state.auth.as_ref() else {
        return;
    };
    let Ok(client) = auth.db.pool.get().await else {
        return;
    };
    let cutoff = time::OffsetDateTime::now_utc()
        .checked_sub(
            docs.sync_interval
                .try_into()
                .unwrap_or(time::Duration::ZERO),
        )
        .unwrap_or(time::OffsetDateTime::UNIX_EPOCH);
    let Ok(due) = srcdb::due_for_sync(&client, cutoff, 50).await else {
        return;
    };
    drop(client);

    for source in due {
        // Sequential on purpose: the git layer's own semaphore already bounds
        // concurrency, and a refresher has no reason to compete with users.
        if let Err(e) = sync_source(state, source.project_id, &source, false).await {
            tracing::debug!(
                source_id = %source.id,
                error = %e,
                "scheduled documentation sync failed"
            );
        }
    }
}

/// Clear `syncing` rows left behind by a process that died mid-fetch.
pub async fn release_stale_claims(state: &AppState) {
    let Some(auth) = state.auth.as_ref() else {
        return;
    };
    let Ok(client) = auth.db.pool.get().await else {
        return;
    };
    match srcdb::release_stale_claims(&client).await {
        Ok(n) if n > 0 => tracing::info!(count = n, "released stale documentation sync claims"),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::indexing_slicing, clippy::unwrap_used)]
    use super::*;

    fn raw(path: &str, is_dir: bool) -> gitdocs::RawEntry {
        gitdocs::RawEntry {
            name: path.rsplit('/').next().unwrap_or(path).to_owned(),
            path: path.to_owned(),
            is_dir,
            size: if is_dir { 0 } else { 7 },
        }
    }

    #[test]
    fn nesting_builds_the_hierarchy_with_directories_first() {
        let flat = vec![
            raw("zeta.md", false),
            raw("guides", true),
            raw("guides/intro.md", false),
            raw("guides/deep", true),
            raw("guides/deep/more.md", false),
            raw("README.md", false),
        ];
        let tree = nest(&flat);
        // Directories sort ahead of documents, then case-insensitive by name.
        assert_eq!(tree.len(), 3);
        assert_eq!(tree[0].name, "guides");
        assert_eq!(tree[0].kind, DocEntryKind::Dir);
        assert_eq!(tree[1].name, "README.md");
        assert_eq!(tree[2].name, "zeta.md");

        let guides = &tree[0].children;
        assert_eq!(guides.len(), 2);
        assert_eq!(guides[0].name, "deep");
        assert_eq!(guides[1].name, "intro.md");
        assert_eq!(guides[0].children[0].path, "guides/deep/more.md");
        // Files carry a size; directories do not.
        assert_eq!(guides[1].size, Some(7));
        assert_eq!(guides[0].size, None);
    }

    #[test]
    fn entry_picks_readme_then_index_case_insensitively() {
        let with_readme = nest(&[raw("index.md", false), raw("Readme.md", false)]);
        assert_eq!(pick_entry(&with_readme).as_deref(), Some("Readme.md"));

        let with_index = nest(&[raw("index.md", false), raw("other.md", false)]);
        assert_eq!(pick_entry(&with_index).as_deref(), Some("index.md"));

        // A README nested one level down is not the source's homepage.
        let nested = nest(&[raw("guides", true), raw("guides/README.md", false)]);
        assert_eq!(pick_entry(&nested), None);
    }

    #[test]
    fn parent_of_handles_top_level() {
        assert_eq!(parent_of("a.md"), "");
        assert_eq!(parent_of("d/a.md"), "d");
        assert_eq!(parent_of("d/e/a.md"), "d/e");
    }

    #[test]
    fn ssh_and_web_url_validation() {
        assert!(validate_ssh_url("git@github.com:acme/docs.git", &()).is_ok());
        assert!(validate_ssh_url("ssh://git@host:22/acme/docs.git", &()).is_ok());
        assert!(validate_ssh_url("https://github.com/acme/docs.git", &()).is_err());
        assert!(validate_ssh_url("", &()).is_err());

        assert!(validate_web_url("https://github.com/acme/docs", &()).is_ok());
        assert!(validate_web_url("http://git.internal/acme/docs", &()).is_ok());
        assert!(validate_web_url("git@github.com:acme/docs.git", &()).is_err());
        assert!(validate_web_url("javascript:alert(1)", &()).is_err());
    }

    #[test]
    fn doc_path_validation_refuses_traversal() {
        assert!(validate_doc_path("", &()).is_ok());
        assert!(validate_doc_path("/docs/public/", &()).is_ok());
        assert!(validate_doc_path("../etc", &()).is_err());
        assert!(validate_doc_path("docs/../..", &()).is_err());
    }
}
