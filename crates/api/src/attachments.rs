//! Attachment endpoints: multipart upload, signed download, list, delete, and
//! a background GC entry point.
//!
//! Security posture: client MIME is ignored (re-derived from magic bytes);
//! filenames are sanitized; downloads carry `nosniff` + a locked-down CSP.
//! Only audio and video are served `inline` (so a recording plays in a tab);
//! everything else is an opaque attachment.
//!
//! Uploads are streamed to a spool file while being hashed, then adopted into
//! content-addressed storage, so a multi-gigabyte recording never sits in
//! memory. Downloads stream from storage and honour single byte ranges
//! (`206`/`416`), which media players need for seeking.
#![allow(
    clippy::result_large_err,
    clippy::implicit_hasher,
    clippy::manual_let_else,
    clippy::arithmetic_side_effects,
    clippy::expect_used,
    clippy::too_many_lines,
    clippy::single_match_else,
    clippy::collapsible_if
)]

use std::collections::HashMap;
use std::path::PathBuf;

use axum::body::Body;
use axum::extract::multipart::Field;
use axum::extract::{Multipart, Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use hmac::{Hmac, Mac};
use intellipilot_core::perms::Permission;
use intellipilot_db::attachments as adb;
use intellipilot_storage::{Storage, sanitize_filename, shard_key};
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use time::{Duration as TimeDuration, OffsetDateTime};
use tokio::io::AsyncWriteExt;
use tokio_util::io::ReaderStream;
use uuid::Uuid;

use crate::problem::Problem;
use crate::projects::ProjectContext;
use crate::state::AppState;

type HmacSha256 = Hmac<Sha256>;

/// Download URLs are valid for 15 minutes.
const DOWNLOAD_TTL_SECS: i64 = 15 * 60;
/// Audio/video URLs live for 6 hours: a player keeps re-requesting ranges of
/// the same URL for as long as a long recording is being watched.
const MEDIA_DOWNLOAD_TTL_SECS: i64 = 6 * 60 * 60;
/// How many leading bytes of an upload are kept for MIME sniffing.
const SNIFF_BYTES: usize = 8192;

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

/// Map the `{entity}` path segment to a stored `target_type` string.
fn entity_target(params: &HashMap<String, String>) -> Option<(&'static str, Uuid)> {
    let target_type = params.get("entity").and_then(|s| match s.as_str() {
        "epics" => Some("epic"),
        "issues" => Some("issue"),
        "wiki" => Some("wiki"),
        "comments" => Some("comment"),
        _ => None,
    })?;
    let id = params.get("id").and_then(|s| Uuid::parse_str(s).ok())?;
    Some((target_type, id))
}

pub(crate) fn view_perm(target_type: &str) -> Option<Permission> {
    Some(match target_type {
        "epic" => Permission::EpicView,
        // Comment attachments are gated like the issues they hang off.
        "issue" | "comment" => Permission::IssueView,
        "wiki" => Permission::WikiView,
        "meeting" => Permission::MeetingView,
        _ => return None,
    })
}

/// Audio and video play inline and get a long-lived download URL.
fn is_media(content_type: &str) -> bool {
    content_type.starts_with("audio/") || content_type.starts_with("video/")
}

// --------------------------------------------------------------------------
// signing
// --------------------------------------------------------------------------

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from_digit(u32::from(b >> 4), 16).unwrap_or('0'));
        s.push(char::from_digit(u32::from(b & 0x0f), 16).unwrap_or('0'));
    }
    s
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

fn sign(key: &[u8; 32], id: Uuid, exp: i64) -> String {
    let mut mac = HmacSha256::new_from_slice(key).expect("hmac accepts any key length");
    mac.update(id.as_bytes());
    mac.update(&exp.to_le_bytes());
    hex_encode(&mac.finalize().into_bytes())
}

fn verify(key: &[u8; 32], id: Uuid, exp: i64, sig_hex: &str) -> bool {
    let Some(sig) = hex_decode(sig_hex) else {
        return false;
    };
    let mut mac = HmacSha256::new_from_slice(key).expect("hmac accepts any key length");
    mac.update(id.as_bytes());
    mac.update(&exp.to_le_bytes());
    mac.verify_slice(&sig).is_ok()
}

// --------------------------------------------------------------------------
// upload
// --------------------------------------------------------------------------

// --------------------------------------------------------------------------
// streaming receive (shared with meeting files)
// --------------------------------------------------------------------------

/// A file field spooled to disk, hashed, and ready to be adopted.
pub(crate) struct Received {
    /// Sanitized client filename.
    pub filename: String,
    pub size: u64,
    pub sha256: String,
    /// The first bytes, for MIME sniffing.
    pub head: Vec<u8>,
    spool: Spool,
}

impl Received {
    /// The spool file holding the bytes until they are adopted.
    pub(crate) fn path(&self) -> &std::path::Path {
        &self.spool.path
    }
}

/// Why a multipart upload could not be received.
pub(crate) enum ReceiveError {
    /// Larger than the per-file limit (or the route's body limit).
    TooLarge,
    /// Not a readable multipart body.
    Invalid,
    /// No field carried a filename.
    NoFile,
    /// The spool file could not be written.
    Io,
}

impl ReceiveError {
    pub(crate) fn into_response(self, max: u64, rid: &str) -> Response {
        match self {
            Self::TooLarge => problem(
                StatusCode::PAYLOAD_TOO_LARGE,
                "too_large",
                "Payload Too Large",
                Some(format!("file exceeds {max} bytes")),
                rid,
            ),
            Self::Invalid => problem(
                StatusCode::BAD_REQUEST,
                "invalid_multipart",
                "Invalid multipart body",
                None,
                rid,
            ),
            Self::NoFile => problem(
                StatusCode::UNPROCESSABLE_ENTITY,
                "no_file",
                "No file part",
                Some("expected a file field".to_owned()),
                rid,
            ),
            Self::Io => internal(rid),
        }
    }
}

/// A spool file that removes itself unless adopted. `Drop` cannot await, so
/// the removal is a blocking unlink — a single cheap syscall.
struct Spool {
    path: PathBuf,
    armed: bool,
}

impl Spool {
    const fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for Spool {
    fn drop(&mut self) {
        if self.armed {
            drop(std::fs::remove_file(&self.path));
        }
    }
}

/// Read the first file field of `multipart` into a spool file under the
/// storage's staging directory, hashing as it goes and refusing anything over
/// `max` bytes as soon as it crosses the line. Returns the text fields seen
/// before the file (e.g. a `kind`) alongside it.
pub(crate) async fn receive_file(
    multipart: &mut Multipart,
    storage: &dyn Storage,
    max: u64,
) -> Result<(Received, HashMap<String, String>), ReceiveError> {
    let mut fields = HashMap::new();
    loop {
        let field = match multipart.next_field().await {
            Ok(Some(f)) => f,
            Ok(None) => return Err(ReceiveError::NoFile),
            Err(e) => return Err(multipart_error(e.status())),
        };
        let Some(raw_name) = field.file_name().map(str::to_owned) else {
            // A plain form field: remember small ones, skip the rest.
            let name = field.name().unwrap_or_default().to_owned();
            if let Ok(text) = field.text().await
                && text.len() <= 256
                && fields.len() < 16
            {
                fields.insert(name, text);
            }
            continue;
        };
        let received = spool_field(field, storage, max, sanitize_filename(&raw_name)).await?;
        return Ok((received, fields));
    }
}

fn multipart_error(status: StatusCode) -> ReceiveError {
    if status == StatusCode::PAYLOAD_TOO_LARGE {
        ReceiveError::TooLarge
    } else {
        ReceiveError::Invalid
    }
}

async fn spool_field(
    mut field: Field<'_>,
    storage: &dyn Storage,
    max: u64,
    filename: String,
) -> Result<Received, ReceiveError> {
    let dir = storage.staging_dir();
    if tokio::fs::create_dir_all(&dir).await.is_err() {
        return Err(ReceiveError::Io);
    }
    let path = dir.join(format!("{}.part", Uuid::now_v7()));
    let Ok(mut file) = tokio::fs::File::create(&path).await else {
        return Err(ReceiveError::Io);
    };
    let spool = Spool { path, armed: true };
    let mut hasher = Sha256::new();
    let mut head: Vec<u8> = Vec::with_capacity(SNIFF_BYTES);
    let mut size: u64 = 0;
    loop {
        let chunk = match field.chunk().await {
            Ok(Some(c)) => c,
            Ok(None) => break,
            Err(e) => return Err(multipart_error(e.status())),
        };
        size = size.saturating_add(chunk.len() as u64);
        if size > max {
            return Err(ReceiveError::TooLarge);
        }
        if head.len() < SNIFF_BYTES {
            let take = (SNIFF_BYTES - head.len()).min(chunk.len());
            head.extend_from_slice(chunk.get(..take).unwrap_or_default());
        }
        hasher.update(&chunk);
        if file.write_all(&chunk).await.is_err() {
            return Err(ReceiveError::Io);
        }
    }
    if file.flush().await.is_err() || file.sync_all().await.is_err() {
        return Err(ReceiveError::Io);
    }
    drop(file);
    Ok(Received {
        filename,
        size,
        sha256: hex_encode(&hasher.finalize()),
        head,
        spool,
    })
}

/// Adopt a received file into content-addressed storage (the key is the
/// SHA-256 of the bytes, so identical uploads converge on one object).
/// Returns the storage key.
pub(crate) async fn adopt(
    storage: &dyn Storage,
    mut received: Received,
    content_type: &str,
) -> Result<String, ()> {
    let key = shard_key(&received.sha256);
    match storage
        .put_file(&key, &received.spool.path, content_type)
        .await
    {
        Ok(_) => {
            received.spool.disarm();
            Ok(key)
        }
        Err(e) => {
            tracing::warn!(error = %e, "failed to store uploaded file");
            Err(())
        }
    }
}

/// Reject a sniffed type that contradicts the filename (422).
pub(crate) fn mime_mismatch(detail: String, rid: &str) -> Response {
    problem(
        StatusCode::UNPROCESSABLE_ENTITY,
        "mime_mismatch",
        "MIME mismatch",
        Some(detail),
        rid,
    )
}

// --------------------------------------------------------------------------
// upload
// --------------------------------------------------------------------------

/// `POST /api/v1/projects/{project_id}/{entity}/{id}/attachments`
pub async fn upload(
    State(state): State<AppState>,
    ctx: ProjectContext,
    Path(params): Path<HashMap<String, String>>,
    mut multipart: Multipart,
) -> Response {
    if let Err(r) = ctx.require(Permission::AttachmentCreate) {
        return r;
    }
    let Some((target_type, target_id)) = entity_target(&params) else {
        return not_found(&ctx.rid);
    };
    let auth = state.auth();
    let max = auth.attachments.max_bytes;
    let storage = auth.attachments.storage.as_ref();

    let received = match receive_file(&mut multipart, storage, max).await {
        Ok((r, _)) => r,
        Err(e) => return e.into_response(max, &ctx.rid),
    };

    // Re-derive MIME from magic bytes; the client-declared type is ignored.
    let content_type = match content_type_for(&received.head, &received.filename) {
        Ok(ct) => ct,
        Err(detail) => return mime_mismatch(detail, &ctx.rid),
    };
    store_and_record(
        &state,
        &ctx,
        received,
        &content_type,
        target_type,
        target_id,
        None,
    )
    .await
}

/// Adopt a received file and insert its attachment row; `201` with the row.
pub(crate) async fn store_and_record(
    state: &AppState,
    ctx: &ProjectContext,
    received: Received,
    content_type: &str,
    target_type: &str,
    target_id: Uuid,
    kind: Option<&str>,
) -> Response {
    let auth = state.auth();
    let storage = auth.attachments.storage.as_ref();
    let filename = received.filename.clone();
    let sha = received.sha256.clone();
    let size = i64::try_from(received.size).unwrap_or(i64::MAX);
    let Ok(key) = adopt(storage, received, content_type).await else {
        return internal(&ctx.rid);
    };

    let Ok(client) = auth.db.pool.get().await else {
        return internal(&ctx.rid);
    };
    // On failure the object may already be shared with another row
    // (content-addressed), so it is left for GC rather than deleted here.
    adb::create(
        &client,
        ctx.project.id,
        target_type,
        target_id,
        ctx.actor_id,
        &filename,
        content_type,
        size,
        &sha,
        &key,
        kind,
    )
    .await
    .map_or_else(
        |_| internal(&ctx.rid),
        |att| (StatusCode::CREATED, axum::Json(att)).into_response(),
    )
}

/// Derive a safe content type from magic bytes. If the bytes are a recognized
/// binary type and the filename extension contradicts it, reject (422).
pub(crate) fn content_type_for(bytes: &[u8], filename: &str) -> Result<String, String> {
    let ext = filename
        .rsplit('.')
        .next()
        .filter(|e| *e != filename)
        .map(str::to_ascii_lowercase);
    match infer::get(bytes) {
        Some(t) => {
            if let Some(ext) = ext.as_deref() {
                if !ext_matches(ext, t.extension()) {
                    return Err(format!(
                        "file content is {} but extension is .{ext}",
                        t.mime_type()
                    ));
                }
            }
            Ok(t.mime_type().to_owned())
        }
        // Not a recognizable binary signature (e.g. plain text) — store as a
        // generic, non-executable type.
        None => Ok("application/octet-stream".to_owned()),
    }
}

fn ext_matches(file_ext: &str, inferred_ext: &str) -> bool {
    if file_ext == inferred_ext {
        return true;
    }
    // Common equivalent extensions.
    matches!(
        (file_ext, inferred_ext),
        ("jpeg", "jpg") | ("jpg", "jpeg") | ("tif", "tiff") | ("tiff", "tif")
    )
}

// --------------------------------------------------------------------------
// list / sign / download / delete
// --------------------------------------------------------------------------

/// `GET /api/v1/projects/{project_id}/{entity}/{id}/attachments`
pub async fn list(
    State(state): State<AppState>,
    ctx: ProjectContext,
    Path(params): Path<HashMap<String, String>>,
) -> Response {
    let Some((target_type, target_id)) = entity_target(&params) else {
        return not_found(&ctx.rid);
    };
    if let Some(perm) = view_perm(target_type) {
        if let Err(r) = ctx.require(perm) {
            return r;
        }
    }
    let auth = state.auth();
    let Ok(client) = auth.db.pool.get().await else {
        return internal(&ctx.rid);
    };
    match adb::list(&client, target_type, target_id).await {
        Ok(items) => axum::Json(json!({ "attachments": items })).into_response(),
        Err(_) => internal(&ctx.rid),
    }
}

/// `GET /api/v1/projects/{project_id}/attachments/{attachment_id}` — returns a
/// short-lived signed download URL.
pub async fn sign_url(
    State(state): State<AppState>,
    ctx: ProjectContext,
    Path(params): Path<HashMap<String, String>>,
) -> Response {
    let Some(id) = params
        .get("attachment_id")
        .and_then(|s| Uuid::parse_str(s).ok())
    else {
        return not_found(&ctx.rid);
    };
    let auth = state.auth();
    let Ok(client) = auth.db.pool.get().await else {
        return internal(&ctx.rid);
    };
    let Ok(Some(att)) = adb::get(&client, ctx.project.id, id).await else {
        return not_found(&ctx.rid);
    };
    // Permission depends on what the attachment is attached to.
    match view_perm(&att.target_type) {
        Some(perm) => {
            if let Err(r) = ctx.require(perm) {
                return r;
            }
        }
        None => return not_found(&ctx.rid),
    }

    let ttl = if is_media(&att.content_type) {
        MEDIA_DOWNLOAD_TTL_SECS
    } else {
        DOWNLOAD_TTL_SECS
    };
    let exp = (OffsetDateTime::now_utc() + TimeDuration::seconds(ttl)).unix_timestamp();
    let sig = sign(&auth.attachments.signing_key, id, exp);
    let url = format!(
        "/api/v1/projects/{}/attachments/{id}/download?exp={exp}&sig={sig}",
        ctx.project.id
    );
    axum::Json(json!({ "url": url, "expires_at": exp, "filename": att.filename })).into_response()
}

#[derive(Debug, Deserialize)]
pub struct DownloadParams {
    exp: i64,
    sig: String,
}

/// `GET /api/v1/projects/{project_id}/attachments/{attachment_id}/download`
///
/// Authorized by the short-lived HMAC **signature** alone (no Bearer token),
/// because `sign_url` already checked the caller's view permission before
/// issuing the URL. This lets a browser open the URL in a new tab (which drops
/// the `Authorization` header) and lets the SPA render authenticated image/video
/// previews from the same signed URL. Always served as an opaque attachment.
pub async fn download(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(params): Path<HashMap<String, String>>,
    Query(q): Query<DownloadParams>,
) -> Response {
    let rid = crate::auth::request_id(&headers);
    let Some(project_id) = params
        .get("project_id")
        .and_then(|s| Uuid::parse_str(s).ok())
    else {
        return not_found(&rid);
    };
    let Some(id) = params
        .get("attachment_id")
        .and_then(|s| Uuid::parse_str(s).ok())
    else {
        return not_found(&rid);
    };
    let auth = state.auth();

    // Signature + expiry authorize the download.
    if q.exp < OffsetDateTime::now_utc().unix_timestamp() {
        return problem(
            StatusCode::FORBIDDEN,
            "url_expired",
            "Download URL expired",
            None,
            &rid,
        );
    }
    if !verify(&auth.attachments.signing_key, id, q.exp, &q.sig) {
        return problem(
            StatusCode::FORBIDDEN,
            "bad_signature",
            "Invalid signature",
            None,
            &rid,
        );
    }

    let Ok(client) = auth.db.pool.get().await else {
        return internal(&rid);
    };
    // The attachment must belong to the project in the path.
    let Ok(Some(att)) = adb::get(&client, project_id, id).await else {
        return not_found(&rid);
    };
    if view_perm(&att.target_type).is_none() {
        return not_found(&rid);
    }

    let Ok(Some(key)) = adb::storage_key(&client, project_id, id).await else {
        return not_found(&rid);
    };
    drop(client);
    let storage = auth.attachments.storage.as_ref();
    let Ok(size) = storage.size(&key).await else {
        return not_found(&rid);
    };

    let range = headers
        .get(header::RANGE)
        .and_then(|v| v.to_str().ok())
        .map_or(ByteRange::Full, |h| parse_range(h, size));
    let (status, start, len) = match range {
        ByteRange::Full => (StatusCode::OK, 0, size),
        ByteRange::Partial { start, end } => (StatusCode::PARTIAL_CONTENT, start, end - start + 1),
        ByteRange::Unsatisfiable => {
            let mut resp = problem(
                StatusCode::RANGE_NOT_SATISFIABLE,
                "range_not_satisfiable",
                "Range Not Satisfiable",
                None,
                &rid,
            );
            if let Ok(v) = HeaderValue::from_str(&format!("bytes */{size}")) {
                resp.headers_mut().insert(header::CONTENT_RANGE, v);
            }
            return resp;
        }
    };
    let Ok(reader) = storage.open_range(&key, start, len).await else {
        return not_found(&rid);
    };

    let mut resp = Response::new(Body::from_stream(ReaderStream::new(reader)));
    *resp.status_mut() = status;
    let headers = resp.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(&att.content_type)
            .unwrap_or(HeaderValue::from_static("application/octet-stream")),
    );
    headers.insert(header::CONTENT_LENGTH, HeaderValue::from(len));
    headers.insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
    if status == StatusCode::PARTIAL_CONTENT
        && let Ok(v) = HeaderValue::from_str(&format!("bytes {start}-{}/{size}", start + len - 1))
    {
        headers.insert(header::CONTENT_RANGE, v);
    }
    // Media plays inline (a recording opened in a tab); everything else is
    // always a download.
    let mode = if is_media(&att.content_type) {
        "inline"
    } else {
        "attachment"
    };
    let disposition = format!(
        "{mode}; filename=\"{}\"",
        sanitize_header_value(&att.filename)
    );
    headers.insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_str(&disposition).unwrap_or(HeaderValue::from_static("attachment")),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("default-src 'none'; sandbox"),
    );
    resp
}

/// The outcome of reading a `Range` header against an object of known size.
#[derive(Debug, PartialEq, Eq)]
enum ByteRange {
    /// No usable range: serve everything with `200`.
    Full,
    /// Serve `start..=end` with `206`.
    Partial { start: u64, end: u64 },
    /// A syntactically valid range that misses the object: `416`.
    Unsatisfiable,
}

/// Parse a single `bytes=` range (RFC 9110 §14.1.2). Multi-range and
/// malformed headers fall back to the full body, which the RFC permits.
fn parse_range(header: &str, size: u64) -> ByteRange {
    let Some(spec) = header.trim().strip_prefix("bytes=") else {
        return ByteRange::Full;
    };
    if spec.contains(',') {
        return ByteRange::Full;
    }
    let Some((first, last)) = spec.trim().split_once('-') else {
        return ByteRange::Full;
    };
    let (first, last) = (first.trim(), last.trim());
    if first.is_empty() {
        // Suffix range: the last N bytes.
        let Ok(n) = last.parse::<u64>() else {
            return ByteRange::Full;
        };
        if n == 0 || size == 0 {
            return ByteRange::Unsatisfiable;
        }
        return ByteRange::Partial {
            start: size.saturating_sub(n),
            end: size - 1,
        };
    }
    let Ok(start) = first.parse::<u64>() else {
        return ByteRange::Full;
    };
    let end = if last.is_empty() {
        None
    } else {
        match last.parse::<u64>() {
            Ok(e) if e >= start => Some(e),
            _ => return ByteRange::Full,
        }
    };
    if start >= size {
        return ByteRange::Unsatisfiable;
    }
    ByteRange::Partial {
        start,
        end: end.map_or(size - 1, |e| e.min(size - 1)),
    }
}

/// `DELETE /api/v1/projects/{project_id}/attachments/{attachment_id}`
pub async fn delete(
    State(state): State<AppState>,
    ctx: ProjectContext,
    Path(params): Path<HashMap<String, String>>,
) -> Response {
    let Some(id) = params
        .get("attachment_id")
        .and_then(|s| Uuid::parse_str(s).ok())
    else {
        return not_found(&ctx.rid);
    };
    let auth = state.auth();
    let Ok(client) = auth.db.pool.get().await else {
        return internal(&ctx.rid);
    };
    // A meeting's files are part of the meeting: removing one is editing the
    // meeting, and must not be possible for someone who cannot even see it.
    let is_meeting_file = matches!(
        adb::get(&client, ctx.project.id, id).await,
        Ok(Some(ref att)) if att.target_type == "meeting"
    );
    let needed = if is_meeting_file {
        Permission::MeetingModify
    } else {
        Permission::AttachmentDelete
    };
    if let Err(r) = ctx.require(needed) {
        return r;
    }
    match adb::soft_delete(&client, ctx.project.id, id).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => not_found(&ctx.rid),
        Err(_) => internal(&ctx.rid),
    }
}

/// Strip characters that could break the `Content-Disposition` header.
fn sanitize_header_value(name: &str) -> String {
    name.chars()
        .filter(|c| !matches!(c, '"' | '\\' | '\r' | '\n'))
        .collect()
}

/// Background GC for soft-deleted attachments.
///
/// Purges storage objects for attachments soft-deleted before `cutoff`, then
/// hard-deletes their rows. `cutoff` is injectable for tests. Returns the
/// number of objects purged. Scheduled by [`spawn_gc`].
pub async fn run_gc(
    client: &deadpool_postgres::Client,
    storage: &dyn Storage,
    cutoff: OffsetDateTime,
) -> usize {
    let keys = match adb::gc(client, cutoff).await {
        Ok(k) => k,
        Err(e) => {
            tracing::warn!(error = %e, "attachment GC query failed");
            return 0;
        }
    };
    let mut purged = 0;
    for key in &keys {
        if storage.delete(key).await.is_ok() {
            purged += 1;
        }
    }
    purged
}

/// How the periodic attachment GC runs.
#[derive(Debug, Clone, Copy)]
pub struct GcSchedule {
    /// Time between runs.
    pub interval: std::time::Duration,
    /// How long a soft-deleted file is kept before it is purged.
    pub grace: std::time::Duration,
}

/// Run attachment GC forever on `schedule`: purge files soft-deleted longer
/// ago than the grace period, and sweep abandoned upload spools.
pub fn spawn_gc(
    pool: deadpool_postgres::Pool,
    storage: std::sync::Arc<dyn Storage>,
    schedule: GcSchedule,
) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(schedule.interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            let grace = TimeDuration::try_from(schedule.grace).unwrap_or(TimeDuration::days(7));
            let cutoff = OffsetDateTime::now_utc() - grace;
            match pool.get().await {
                Ok(client) => {
                    let purged = run_gc(&client, storage.as_ref(), cutoff).await;
                    if purged > 0 {
                        tracing::info!(purged, "attachment GC removed deleted files");
                    }
                }
                Err(e) => tracing::warn!(error = %e, "attachment GC could not get a connection"),
            }
            // An upload is spooled for as long as it streams in; a day is far
            // beyond any real upload, so anything older was abandoned.
            let swept = storage
                .sweep_staging(std::time::Duration::from_secs(24 * 60 * 60))
                .await;
            if swept > 0 {
                tracing::info!(swept, "removed abandoned upload spools");
            }
        }
    });
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn parses_single_ranges() {
        assert_eq!(
            parse_range("bytes=0-3", 10),
            ByteRange::Partial { start: 0, end: 3 }
        );
        assert_eq!(
            parse_range("bytes=5-", 10),
            ByteRange::Partial { start: 5, end: 9 }
        );
        assert_eq!(
            parse_range("bytes=-4", 10),
            ByteRange::Partial { start: 6, end: 9 }
        );
        assert_eq!(
            parse_range("bytes=-40", 10),
            ByteRange::Partial { start: 0, end: 9 }
        );
        assert_eq!(
            parse_range("bytes=8-100", 10),
            ByteRange::Partial { start: 8, end: 9 }
        );
    }

    #[test]
    fn unsatisfiable_and_ignored_ranges() {
        assert_eq!(parse_range("bytes=10-", 10), ByteRange::Unsatisfiable);
        assert_eq!(parse_range("bytes=-0", 10), ByteRange::Unsatisfiable);
        assert_eq!(parse_range("bytes=0-1,4-5", 10), ByteRange::Full);
        assert_eq!(parse_range("items=0-1", 10), ByteRange::Full);
        assert_eq!(parse_range("bytes=5-2", 10), ByteRange::Full);
        assert_eq!(parse_range("bytes=x-2", 10), ByteRange::Full);
    }

    #[test]
    fn media_types() {
        assert!(is_media("video/mp4"));
        assert!(is_media("audio/mpeg"));
        assert!(!is_media("image/png"));
        assert!(!is_media("application/octet-stream"));
    }
}
