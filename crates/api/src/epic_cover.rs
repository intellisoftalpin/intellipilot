//! Epic cover-image endpoints: upload an image, remove it, and serve it.
//!
//! Modelled exactly on user avatars (`crate::avatar`): the image goes to the
//! object-storage backend at a deterministic per-epic key
//! (`epic-covers/<sharded epic id>`), so a new upload overwrites the previous
//! one and there is never more than one object per epic. `cover_image_kind`
//! flips between `none` (render the colour swatch) and `image`.
#![allow(
    clippy::result_large_err,
    clippy::implicit_hasher,
    clippy::too_many_lines
)]

use std::collections::HashMap;

use axum::body::Body;
use axum::extract::{Multipart, Path, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use bytes::Bytes;
use intellipilot_core::backlog::etag;
use intellipilot_core::perms::Permission;
use intellipilot_db::backlog as bl;
use intellipilot_db::history;
use intellipilot_storage::shard_key;
use serde_json::json;
use uuid::Uuid;

use crate::problem::Problem;
use crate::projects::ProjectContext;
use crate::state::AppState;

/// Hard cap for cover uploads (5 MiB).
const MAX_COVER_BYTES: usize = 5 * 1024 * 1024;

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

fn id_param(params: &HashMap<String, String>) -> Option<Uuid> {
    params.get("id").and_then(|s| Uuid::parse_str(s).ok())
}

/// Deterministic per-epic storage key for the cover object.
fn cover_key(epic_id: Uuid) -> String {
    format!("epic-covers/{}", shard_key(&epic_id.to_string()))
}

/// `PUT /api/v1/projects/{project_id}/epics/{id}/cover-image` — multipart upload.
pub async fn upload_cover(
    State(state): State<AppState>,
    ctx: ProjectContext,
    Path(params): Path<HashMap<String, String>>,
    mut multipart: Multipart,
) -> Response {
    if let Err(r) = ctx.require(Permission::EpicModify) {
        return r;
    }
    let Some(id) = id_param(&params) else {
        return not_found(&ctx.rid);
    };
    let auth = state.auth();
    let Ok(client) = auth.db.pool.get().await else {
        return internal(&ctx.rid);
    };
    // The epic must exist in this project.
    match bl::get_epic(&client, ctx.project.id, id).await {
        Ok(Some(_)) => {}
        Ok(None) => return not_found(&ctx.rid),
        Err(_) => return internal(&ctx.rid),
    }

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
                        Some(format!("cover exceeds {MAX_COVER_BYTES} bytes")),
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
    if bytes.len() > MAX_COVER_BYTES {
        return problem(
            StatusCode::PAYLOAD_TOO_LARGE,
            "too_large",
            "Payload Too Large",
            Some(format!("cover exceeds {MAX_COVER_BYTES} bytes")),
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
                Some("cover must be a PNG, JPEG, GIF or WebP".to_owned()),
                &ctx.rid,
            );
        }
    };

    let key = cover_key(id);
    if let Err(e) = auth.attachments.storage.put(&key, bytes, &mime).await {
        tracing::error!(error = %e, %key, "epic cover storage write failed");
        return problem(
            StatusCode::INTERNAL_SERVER_ERROR,
            "cover_storage_failed",
            "Cover storage failed",
            Some("could not write the cover image to storage".to_owned()),
            &ctx.rid,
        );
    }
    match bl::set_epic_cover_image(&client, ctx.project.id, id, &key, &mime).await {
        Ok(true) => {}
        Ok(false) => return not_found(&ctx.rid),
        Err(e) => {
            tracing::error!(error = %e, "epic cover db update failed");
            return internal(&ctx.rid);
        }
    }
    history::record(
        &client,
        ctx.project.id,
        "epic",
        id,
        Some(ctx.actor_id),
        &json!({ "cover_image": [false, true] }),
    )
    .await;
    fresh(&client, &ctx, id).await
}

/// `DELETE /api/v1/projects/{project_id}/epics/{id}/cover-image` — reset to swatch.
pub async fn delete_cover(
    State(state): State<AppState>,
    ctx: ProjectContext,
    Path(params): Path<HashMap<String, String>>,
) -> Response {
    if let Err(r) = ctx.require(Permission::EpicModify) {
        return r;
    }
    let Some(id) = id_param(&params) else {
        return not_found(&ctx.rid);
    };
    let auth = state.auth();
    let Ok(client) = auth.db.pool.get().await else {
        return internal(&ctx.rid);
    };
    auth.attachments.storage.delete(&cover_key(id)).await.ok();
    match bl::clear_epic_cover_image(&client, ctx.project.id, id).await {
        Ok(true) => {
            history::record(
                &client,
                ctx.project.id,
                "epic",
                id,
                Some(ctx.actor_id),
                &json!({ "cover_image": [true, false] }),
            )
            .await;
            fresh(&client, &ctx, id).await
        }
        Ok(false) => not_found(&ctx.rid),
        Err(_) => internal(&ctx.rid),
    }
}

/// `GET /api/v1/projects/{project_id}/epics/{id}/cover-image` — serve the image.
pub async fn serve_cover(
    State(state): State<AppState>,
    ctx: ProjectContext,
    Path(params): Path<HashMap<String, String>>,
) -> Response {
    if let Err(r) = ctx.require(Permission::EpicView) {
        return r;
    }
    let Some(id) = id_param(&params) else {
        return not_found(&ctx.rid);
    };
    let auth = state.auth();
    let Ok(client) = auth.db.pool.get().await else {
        return internal(&ctx.rid);
    };
    let Ok(Some((key, mime))) = bl::epic_cover_object(&client, ctx.project.id, id).await else {
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

/// Re-fetch the epic and return it with its ETag (so the client picks up the
/// new `cover_image_updated_at`).
async fn fresh(client: &deadpool_postgres::Client, ctx: &ProjectContext, id: Uuid) -> Response {
    match bl::get_epic(client, ctx.project.id, id).await {
        Ok(Some(e)) => {
            let mut resp = (StatusCode::OK, axum::Json(&e)).into_response();
            if let Ok(v) = HeaderValue::from_str(&etag(e.id, e.version)) {
                resp.headers_mut().insert(header::ETAG, v);
            }
            resp
        }
        Ok(None) => not_found(&ctx.rid),
        Err(_) => internal(&ctx.rid),
    }
}
