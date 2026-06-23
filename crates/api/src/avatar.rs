//! User avatar endpoints: upload an image (incl. animated GIF), pick an emoji,
//! reset to default, and serve another user's avatar image.
//!
//! Images go to the object-storage backend at a deterministic per-user key
//! (`avatars/<sharded user id>`), so a new upload overwrites the previous one
//! and there is never more than one object per user.
#![allow(clippy::result_large_err)]

use axum::Json;
use axum::body::Body;
use axum::extract::rejection::JsonRejection;
use axum::extract::{Multipart, Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use bytes::Bytes;
use garde::Validate;
use intellipilot_db::{audit, users};
use intellipilot_storage::shard_key;
use serde::Deserialize;
use serde_json::json;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::auth::{AuthUser, client_ip, request_id, user_agent};
use crate::problem::Problem;
use crate::state::AppState;

/// Hard cap for avatar uploads (2 MiB, GIFs included).
const MAX_AVATAR_BYTES: usize = 2 * 1024 * 1024;

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

/// Deterministic per-user storage key for the avatar object.
fn avatar_key(user_id: Uuid) -> String {
    format!("avatars/{}", shard_key(&user_id.to_string()))
}

/// `PUT /api/v1/me/avatar` — multipart image upload.
#[utoipa::path(put, path = "/api/v1/me/avatar",
    responses((status = 200, body = intellipilot_core::user::User), (status = 413), (status = 422)))]
pub async fn upload_avatar(
    State(state): State<AppState>,
    headers: HeaderMap,
    user: AuthUser,
    mut multipart: Multipart,
) -> Response {
    let rid = request_id(&headers);
    let auth = state.auth();

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
                        Some(format!("avatar exceeds {MAX_AVATAR_BYTES} bytes")),
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
            Some("expected an image field".to_owned()),
            &rid,
        );
    };
    if bytes.len() > MAX_AVATAR_BYTES {
        return problem(
            StatusCode::PAYLOAD_TOO_LARGE,
            "too_large",
            "Payload Too Large",
            Some(format!("avatar exceeds {MAX_AVATAR_BYTES} bytes")),
            &rid,
        );
    }

    // Trust the magic bytes, not the client's declared type. Only raster image
    // formats we can render are accepted (PNG/JPEG/GIF/WebP, animated allowed).
    let mime = match infer::get(&bytes) {
        Some(t) if ALLOWED_MIMES.contains(&t.mime_type()) => t.mime_type().to_owned(),
        _ => {
            return problem(
                StatusCode::UNPROCESSABLE_ENTITY,
                "not_an_image",
                "Unsupported image",
                Some("avatar must be a PNG, JPEG, GIF or WebP".to_owned()),
                &rid,
            );
        }
    };

    let key = avatar_key(user.user_id);
    if auth
        .attachments
        .storage
        .put(&key, bytes, &mime)
        .await
        .is_err()
    {
        return internal(&rid);
    }

    let Ok(client) = auth.db.pool.get().await else {
        return internal(&rid);
    };
    if users::set_avatar_image(&client, user.user_id, &key, &mime)
        .await
        .unwrap_or(false)
    {
        audit::record(
            &client,
            Some(user.user_id),
            "avatar_image_set",
            Some(client_ip(&headers)),
            Some(&user_agent(&headers)),
            &json!({ "mime": mime }),
        )
        .await;
        updated(&client, user.user_id, &rid).await
    } else {
        internal(&rid)
    }
}

/// Request body for setting an emoji avatar.
#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct SetEmojiAvatarRequest {
    #[garde(length(min = 1, max = 16))]
    pub emoji: String,
}

/// `PUT /api/v1/me/avatar/emoji`
#[utoipa::path(put, path = "/api/v1/me/avatar/emoji", request_body = SetEmojiAvatarRequest,
    responses((status = 200, body = intellipilot_core::user::User), (status = 422)))]
pub async fn set_emoji_avatar(
    State(state): State<AppState>,
    headers: HeaderMap,
    user: AuthUser,
    body: Result<Json<SetEmojiAvatarRequest>, JsonRejection>,
) -> Response {
    let rid = request_id(&headers);
    let auth = state.auth();
    let Ok(Json(req)) = body else {
        return problem(
            StatusCode::BAD_REQUEST,
            "invalid_body",
            "Invalid Request Body",
            None,
            &rid,
        );
    };
    if req.validate().is_err() {
        return problem(
            StatusCode::UNPROCESSABLE_ENTITY,
            "validation_failed",
            "Validation failed",
            None,
            &rid,
        );
    }
    let Ok(client) = auth.db.pool.get().await else {
        return internal(&rid);
    };
    // Drop any previously-uploaded image object.
    auth.attachments
        .storage
        .delete(&avatar_key(user.user_id))
        .await
        .ok();
    if users::set_avatar_emoji(&client, user.user_id, &req.emoji)
        .await
        .unwrap_or(false)
    {
        audit::record(
            &client,
            Some(user.user_id),
            "avatar_emoji_set",
            Some(client_ip(&headers)),
            Some(&user_agent(&headers)),
            &json!({ "emoji": req.emoji }),
        )
        .await;
        updated(&client, user.user_id, &rid).await
    } else {
        internal(&rid)
    }
}

/// `DELETE /api/v1/me/avatar` — reset to the default (initials) avatar.
#[utoipa::path(delete, path = "/api/v1/me/avatar", responses((status = 204)))]
pub async fn delete_avatar(
    State(state): State<AppState>,
    headers: HeaderMap,
    user: AuthUser,
) -> Response {
    let rid = request_id(&headers);
    let auth = state.auth();
    let Ok(client) = auth.db.pool.get().await else {
        return internal(&rid);
    };
    auth.attachments
        .storage
        .delete(&avatar_key(user.user_id))
        .await
        .ok();
    if users::clear_avatar(&client, user.user_id)
        .await
        .unwrap_or(false)
    {
        audit::record(
            &client,
            Some(user.user_id),
            "avatar_cleared",
            Some(client_ip(&headers)),
            Some(&user_agent(&headers)),
            &json!({}),
        )
        .await;
    }
    StatusCode::NO_CONTENT.into_response()
}

/// `GET /api/v1/users/{id}/avatar` — serve a user's uploaded avatar image.
/// Authenticated; 404 when the user has no image avatar.
#[utoipa::path(get, path = "/api/v1/users/{id}/avatar",
    responses((status = 200, content_type = "image/*"), (status = 404)))]
pub async fn serve_avatar(
    State(state): State<AppState>,
    headers: HeaderMap,
    _user: AuthUser,
    Path(id): Path<Uuid>,
) -> Response {
    let rid = request_id(&headers);
    let auth = state.auth();
    let Ok(client) = auth.db.pool.get().await else {
        return internal(&rid);
    };
    let Ok(Some((key, mime))) = users::avatar_object(&client, id).await else {
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

/// Re-fetch the actor with the out-of-office badge resolved and return it.
async fn updated(client: &deadpool_postgres::Client, id: Uuid, rid: &str) -> Response {
    match users::find_by_id_with_card(client, id).await {
        Ok(Some(u)) => Json(u).into_response(),
        Ok(None) => problem(StatusCode::NOT_FOUND, "not_found", "Not Found", None, rid),
        Err(_) => internal(rid),
    }
}
