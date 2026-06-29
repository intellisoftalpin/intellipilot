//! Project icon-image endpoints: upload an image, remove it, and serve it.
//!
//! Modelled exactly on epic covers / user avatars: the image goes to the
//! object-storage backend at a deterministic per-project key
//! (`project-icons/<sharded project id>`), so a new upload overwrites the
//! previous one and there is never more than one object per project.
//! `icon_image_kind` flips between `none` (render the prefix-initials fallback)
//! and `image`.
#![allow(
    clippy::result_large_err,
    clippy::implicit_hasher,
    clippy::too_many_lines
)]

use axum::body::Body;
use axum::extract::{Multipart, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use bytes::Bytes;
use intellipilot_core::perms::Permission;
use intellipilot_db::projects as projdb;
use intellipilot_storage::shard_key;
use uuid::Uuid;

use crate::problem::Problem;
use crate::projects::ProjectContext;
use crate::state::AppState;

/// Hard cap for icon uploads (5 MiB).
const MAX_ICON_BYTES: usize = 5 * 1024 * 1024;

const ALLOWED_MIMES: [&str; 4] = ["image/png", "image/jpeg", "image/gif", "image/webp"];

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

/// Deterministic per-project storage key for the icon object.
fn icon_key(project_id: Uuid) -> String {
    format!("project-icons/{}", shard_key(&project_id.to_string()))
}

/// `PUT /api/v1/projects/{project_id}/icon` — multipart upload.
pub async fn upload_icon(
    State(state): State<AppState>,
    ctx: ProjectContext,
    mut multipart: Multipart,
) -> Response {
    if let Err(r) = ctx.require(Permission::ProjectModify) {
        return r;
    }
    let auth = state.auth();
    let Ok(client) = auth.db.pool.get().await else {
        return internal(&ctx.rid);
    };

    // Pull the first file field.
    let mut data: Option<Bytes> = None;
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
                        &ctx.rid,
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
                    &ctx.rid,
                );
            }
        }
    }
    let Some(bytes) = data else {
        return problem(
            StatusCode::UNPROCESSABLE_ENTITY,
            "no_file",
            "No file part",
            Some("expected an image field".to_owned()),
            &ctx.rid,
        );
    };
    if bytes.len() > MAX_ICON_BYTES {
        return problem(
            StatusCode::PAYLOAD_TOO_LARGE,
            "too_large",
            "Payload Too Large",
            Some(format!("icon exceeds {MAX_ICON_BYTES} bytes")),
            &ctx.rid,
        );
    }

    // Trust the magic bytes, not the client's declared type.
    let mime = match infer::get(&bytes) {
        Some(t) if ALLOWED_MIMES.contains(&t.mime_type()) => t.mime_type().to_owned(),
        _ => {
            return problem(
                StatusCode::UNPROCESSABLE_ENTITY,
                "not_an_image",
                "Unsupported image",
                Some("icon must be a PNG, JPEG, GIF or WebP".to_owned()),
                &ctx.rid,
            );
        }
    };

    let key = icon_key(ctx.project.id);
    if let Err(e) = auth.attachments.storage.put(&key, bytes, &mime).await {
        tracing::error!(error = %e, %key, "project icon storage write failed");
        return problem(
            StatusCode::INTERNAL_SERVER_ERROR,
            "icon_storage_failed",
            "Icon storage failed",
            Some("could not write the icon image to storage".to_owned()),
            &ctx.rid,
        );
    }
    match projdb::set_icon_image(&client, ctx.project.id, &key, &mime).await {
        Ok(true) => fresh(&client, &ctx).await,
        Ok(false) => not_found(&ctx.rid),
        Err(e) => {
            tracing::error!(error = %e, "project icon db update failed");
            internal(&ctx.rid)
        }
    }
}

/// `DELETE /api/v1/projects/{project_id}/icon` — reset to the initials fallback.
pub async fn delete_icon(State(state): State<AppState>, ctx: ProjectContext) -> Response {
    if let Err(r) = ctx.require(Permission::ProjectModify) {
        return r;
    }
    let auth = state.auth();
    let Ok(client) = auth.db.pool.get().await else {
        return internal(&ctx.rid);
    };
    auth.attachments
        .storage
        .delete(&icon_key(ctx.project.id))
        .await
        .ok();
    match projdb::clear_icon_image(&client, ctx.project.id).await {
        Ok(true) => fresh(&client, &ctx).await,
        Ok(false) => not_found(&ctx.rid),
        Err(_) => internal(&ctx.rid),
    }
}

/// `GET /api/v1/projects/{project_id}/icon` — serve the image.
pub async fn serve_icon(State(state): State<AppState>, ctx: ProjectContext) -> Response {
    if !ctx.can_view() {
        return StatusCode::NOT_FOUND.into_response();
    }
    let auth = state.auth();
    let Ok(client) = auth.db.pool.get().await else {
        return internal(&ctx.rid);
    };
    let Ok(Some((key, mime))) = projdb::icon_object(&client, ctx.project.id).await else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Ok(bytes) = auth.attachments.storage.get(&key).await else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let mut resp = Response::new(Body::from(bytes));
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(&mime)
            .unwrap_or(HeaderValue::from_static("application/octet-stream")),
    );
    h.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, max-age=300"),
    );
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    resp
}

/// Re-fetch the project so the client picks up the new `icon_image_kind` /
/// `icon_image_updated_at`.
async fn fresh(client: &deadpool_postgres::Client, ctx: &ProjectContext) -> Response {
    match projdb::find_by_id(client, ctx.project.id).await {
        Ok(Some(p)) => (StatusCode::OK, axum::Json(p)).into_response(),
        Ok(None) => not_found(&ctx.rid),
        Err(_) => internal(&ctx.rid),
    }
}
