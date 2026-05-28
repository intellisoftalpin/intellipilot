//! Attachment endpoints: multipart upload, signed download, list, delete, and
//! a background GC entry point.
//!
//! Security posture: client MIME is ignored (re-derived from magic bytes);
//! filenames are sanitized; downloads are always served as opaque attachments
//! with `nosniff` + a locked-down CSP so nothing is ever rendered inline.
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

use axum::body::Body;
use axum::extract::{Multipart, Path, Query, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use hmac::{Hmac, Mac};
use intellipilot_core::perms::Permission;
use intellipilot_db::attachments as adb;
use intellipilot_storage::{Storage, sanitize_filename, shard_key};
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use time::{Duration as TimeDuration, OffsetDateTime};
use uuid::Uuid;

use crate::problem::Problem;
use crate::projects::ProjectContext;
use crate::state::AppState;

type HmacSha256 = Hmac<Sha256>;

/// Download URLs are valid for 15 minutes.
const DOWNLOAD_TTL_SECS: i64 = 15 * 60;

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
        "userstories" => Some("user_story"),
        "tasks" => Some("task"),
        "issues" => Some("issue"),
        "wiki" => Some("wiki"),
        _ => None,
    })?;
    let id = params.get("id").and_then(|s| Uuid::parse_str(s).ok())?;
    Some((target_type, id))
}

fn view_perm(target_type: &str) -> Option<Permission> {
    Some(match target_type {
        "epic" => Permission::EpicView,
        "user_story" => Permission::UsView,
        "task" => Permission::TaskView,
        "issue" => Permission::IssueView,
        "wiki" => Permission::WikiView,
        _ => return None,
    })
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

    // Pull the first file field.
    let mut data: Option<(String, bytes::Bytes)> = None;
    loop {
        match multipart.next_field().await {
            Ok(Some(field)) => {
                let fname = field.file_name().map(str::to_owned);
                let Ok(bytes) = field.bytes().await else {
                    return problem(
                        StatusCode::PAYLOAD_TOO_LARGE,
                        "too_large",
                        "Payload Too Large",
                        Some(format!("file exceeds {max} bytes")),
                        &ctx.rid,
                    );
                };
                if let Some(name) = fname {
                    data = Some((name, bytes));
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
                    &ctx.rid,
                );
            }
        }
    }
    let Some((raw_name, bytes)) = data else {
        return problem(
            StatusCode::UNPROCESSABLE_ENTITY,
            "no_file",
            "No file part",
            Some("expected a file field".to_owned()),
            &ctx.rid,
        );
    };
    if bytes.len() as u64 > max {
        return problem(
            StatusCode::PAYLOAD_TOO_LARGE,
            "too_large",
            "Payload Too Large",
            Some(format!("file exceeds {max} bytes")),
            &ctx.rid,
        );
    }

    let filename = sanitize_filename(&raw_name);

    // Re-derive MIME from magic bytes; the client-declared type is ignored.
    let content_type = match content_type_for(&bytes, &filename) {
        Ok(ct) => ct,
        Err(detail) => {
            return problem(
                StatusCode::UNPROCESSABLE_ENTITY,
                "mime_mismatch",
                "MIME mismatch",
                Some(detail),
                &ctx.rid,
            );
        }
    };

    // Content-addressed storage: the object key is the SHA-256 of the bytes,
    // so identical uploads converge on a single stored object (dedup). The
    // `put` is idempotent — re-storing the same content rewrites the same key.
    let size = i64::try_from(bytes.len()).unwrap_or(i64::MAX);
    let sha = hex_encode(&Sha256::digest(&bytes));
    let key = shard_key(&sha);
    if auth
        .attachments
        .storage
        .put(&key, bytes, &content_type)
        .await
        .is_err()
    {
        return internal(&ctx.rid);
    }

    let Ok(client) = auth.db.pool.get().await else {
        return internal(&ctx.rid);
    };
    match adb::create(
        &client,
        ctx.project.id,
        target_type,
        target_id,
        ctx.actor_id,
        &filename,
        &content_type,
        size,
        &sha,
        &key,
    )
    .await
    {
        Ok(att) => (StatusCode::CREATED, axum::Json(att)).into_response(),
        Err(_) => {
            // Best-effort cleanup of the orphaned object.
            if auth.attachments.storage.delete(&key).await.is_err() {
                tracing::warn!(%key, "failed to clean up orphaned attachment object");
            }
            internal(&ctx.rid)
        }
    }
}

/// Derive a safe content type from magic bytes. If the bytes are a recognized
/// binary type and the filename extension contradicts it, reject (422).
fn content_type_for(bytes: &[u8], filename: &str) -> Result<String, String> {
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

    let exp =
        (OffsetDateTime::now_utc() + TimeDuration::seconds(DOWNLOAD_TTL_SECS)).unix_timestamp();
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
/// Requires a valid signature AND an authenticated member with view rights
/// (defense in depth for local FS). Always served as an opaque attachment.
pub async fn download(
    State(state): State<AppState>,
    ctx: ProjectContext,
    Path(params): Path<HashMap<String, String>>,
    Query(q): Query<DownloadParams>,
) -> Response {
    let Some(id) = params
        .get("attachment_id")
        .and_then(|s| Uuid::parse_str(s).ok())
    else {
        return not_found(&ctx.rid);
    };
    let auth = state.auth();

    // 1) Signature + expiry.
    if q.exp < OffsetDateTime::now_utc().unix_timestamp() {
        return problem(
            StatusCode::FORBIDDEN,
            "url_expired",
            "Download URL expired",
            None,
            &ctx.rid,
        );
    }
    if !verify(&auth.attachments.signing_key, id, q.exp, &q.sig) {
        return problem(
            StatusCode::FORBIDDEN,
            "bad_signature",
            "Invalid signature",
            None,
            &ctx.rid,
        );
    }

    let Ok(client) = auth.db.pool.get().await else {
        return internal(&ctx.rid);
    };
    let Ok(Some(att)) = adb::get(&client, ctx.project.id, id).await else {
        return not_found(&ctx.rid);
    };
    // 2) Re-check permission.
    match view_perm(&att.target_type) {
        Some(perm) => {
            if let Err(r) = ctx.require(perm) {
                return r;
            }
        }
        None => return not_found(&ctx.rid),
    }

    let Ok(Some(key)) = adb::storage_key(&client, ctx.project.id, id).await else {
        return not_found(&ctx.rid);
    };
    let Ok(bytes) = auth.attachments.storage.get(&key).await else {
        return not_found(&ctx.rid);
    };

    // Always download, never render inline.
    let mut resp = Response::new(Body::from(bytes));
    let headers = resp.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(&att.content_type)
            .unwrap_or(HeaderValue::from_static("application/octet-stream")),
    );
    let disposition = format!(
        "attachment; filename=\"{}\"",
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

/// `DELETE /api/v1/projects/{project_id}/attachments/{attachment_id}`
pub async fn delete(
    State(state): State<AppState>,
    ctx: ProjectContext,
    Path(params): Path<HashMap<String, String>>,
) -> Response {
    if let Err(r) = ctx.require(Permission::AttachmentDelete) {
        return r;
    }
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

/// Background GC: purge storage objects for attachments soft-deleted before
/// `cutoff`, then hard-delete their rows. `cutoff` is injectable for tests.
/// Returns the number of objects purged.
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
