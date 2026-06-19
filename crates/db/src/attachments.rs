//! Attachment persistence (metadata; bytes live in `Storage`).
#![allow(clippy::too_many_arguments)]

use intellipilot_core::attachment::Attachment;
use time::OffsetDateTime;
use tokio_postgres::Row;
use uuid::Uuid;

use crate::DbError;

const COLS: &str = "id, project_id, target_type, target_id, uploader_id, filename, \
     content_type, size_bytes, sha256, created_at";

fn row_to_attachment(r: &Row) -> Attachment {
    Attachment {
        id: r.get("id"),
        project_id: r.get("project_id"),
        target_type: r.get("target_type"),
        target_id: r.get("target_id"),
        uploader_id: r.get("uploader_id"),
        filename: r.get("filename"),
        content_type: r.get("content_type"),
        size_bytes: r.get("size_bytes"),
        sha256: r.get("sha256"),
        created_at: r.get("created_at"),
    }
}

pub async fn create(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
    target_type: &str,
    target_id: Uuid,
    uploader_id: Uuid,
    filename: &str,
    content_type: &str,
    size_bytes: i64,
    sha256: &str,
    storage_key: &str,
) -> Result<Attachment, DbError> {
    let row = client
        .query_one(
            &format!(
                "INSERT INTO attachments (project_id, target_type, target_id, uploader_id, \
                   filename, content_type, size_bytes, sha256, storage_key) \
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING {COLS}"
            ),
            &[
                &project_id,
                &target_type,
                &target_id,
                &uploader_id,
                &filename,
                &content_type,
                &size_bytes,
                &sha256,
                &storage_key,
            ],
        )
        .await?;
    Ok(row_to_attachment(&row))
}

pub async fn list(
    client: &deadpool_postgres::Client,
    target_type: &str,
    target_id: Uuid,
) -> Result<Vec<Attachment>, DbError> {
    let rows = client
        .query(
            &format!(
                "SELECT {COLS} FROM attachments \
                 WHERE target_type=$1 AND target_id=$2 AND deleted_at IS NULL ORDER BY created_at"
            ),
            &[&target_type, &target_id],
        )
        .await?;
    Ok(rows.iter().map(row_to_attachment).collect())
}

/// Fetch an attachment's public metadata (not deleted).
pub async fn get(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
    id: Uuid,
) -> Result<Option<Attachment>, DbError> {
    let row = client
        .query_opt(
            &format!("SELECT {COLS} FROM attachments WHERE id=$1 AND project_id=$2 AND deleted_at IS NULL"),
            &[&id, &project_id],
        )
        .await?;
    Ok(row.as_ref().map(row_to_attachment))
}

/// Fetch the internal storage key for a live attachment (for download).
pub async fn storage_key(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
    id: Uuid,
) -> Result<Option<String>, DbError> {
    let row = client
        .query_opt(
            "SELECT storage_key FROM attachments WHERE id=$1 AND project_id=$2 AND deleted_at IS NULL",
            &[&id, &project_id],
        )
        .await?;
    Ok(row.map(|r| r.get("storage_key")))
}

pub async fn soft_delete(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
    id: Uuid,
) -> Result<bool, DbError> {
    let n = client
        .execute(
            "UPDATE attachments SET deleted_at=now() WHERE id=$1 AND project_id=$2 AND deleted_at IS NULL",
            &[&id, &project_id],
        )
        .await?;
    Ok(n > 0)
}

/// Soft-delete every attachment hanging off a target (e.g. all of a comment's
/// attachments when the comment is deleted). Best-effort; returns the count.
pub async fn soft_delete_for_target(
    client: &deadpool_postgres::Client,
    target_type: &str,
    target_id: Uuid,
) -> Result<u64, DbError> {
    let n = client
        .execute(
            "UPDATE attachments SET deleted_at=now() \
             WHERE target_type=$1 AND target_id=$2 AND deleted_at IS NULL",
            &[&target_type, &target_id],
        )
        .await?;
    Ok(n)
}

/// Hard-delete expired soft-deleted rows; return now-orphaned storage keys.
///
/// Returns the keys that no surviving row references. Because storage is
/// content-addressed, several rows can share one object; only keys with zero
/// remaining references are safe to purge. `cutoff` is injectable for tests.
pub async fn gc(
    client: &deadpool_postgres::Client,
    cutoff: OffsetDateTime,
) -> Result<Vec<String>, DbError> {
    // Step 1: hard-delete expired rows (autocommits), collecting their keys.
    let deleted = client
        .query(
            "DELETE FROM attachments WHERE deleted_at IS NOT NULL AND deleted_at < $1 \
             RETURNING storage_key",
            &[&cutoff],
        )
        .await?;
    let mut keys: Vec<String> = deleted
        .iter()
        .map(|r| r.get::<_, String>("storage_key"))
        .collect();
    keys.sort_unstable();
    keys.dedup();
    if keys.is_empty() {
        return Ok(Vec::new());
    }

    // Step 2: a separate statement now sees post-delete state. Keys still
    // referenced by a surviving row are shared (content-addressed) and must be
    // kept; the rest are orphaned and safe to purge.
    let still = client
        .query(
            "SELECT DISTINCT storage_key FROM attachments WHERE storage_key = ANY($1)",
            &[&keys],
        )
        .await?;
    let still: Vec<String> = still
        .iter()
        .map(|r| r.get::<_, String>("storage_key"))
        .collect();
    keys.retain(|k| !still.contains(k));
    Ok(keys)
}
