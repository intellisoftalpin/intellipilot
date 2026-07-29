//! Metadata for the installed IP-geolocation database (V018).
//!
//! Only metadata lives here. The `.mmdb` itself is a file under the storage
//! directory — it reaches 62 MB for the city variant, which is far too large
//! for a `bytea` column — and is never redistributed in our image (DB-IP Lite
//! is CC BY 4.0, so the operator's own instance fetches it).

use time::OffsetDateTime;

use crate::DbError;

/// State of the installed database, or the empty row when none is installed.
#[derive(Debug, Clone)]
pub struct GeoipDatabase {
    /// `country` | `city`. May lag the configured variant until the next
    /// refresh finishes.
    pub variant: Option<String>,
    /// Publication month of the installed file, `YYYY-MM`.
    pub build_month: Option<String>,
    /// Path relative to the storage directory.
    pub file_path: Option<String>,
    pub file_size: Option<i64>,
    pub sha256: Option<String>,
    /// `download` | `upload`.
    pub source: Option<String>,
    pub downloaded_at: Option<OffsetDateTime>,
    /// Last update attempt, successful or not.
    pub checked_at: Option<OffsetDateTime>,
    /// Message from the last failed attempt, cleared on success. Surfaced in
    /// the admin card so a silently failing monthly refresh stays visible.
    pub last_error: Option<String>,
}

impl GeoipDatabase {
    /// Whether a usable database is recorded as installed.
    #[must_use]
    pub const fn is_installed(&self) -> bool {
        self.file_path.is_some() && self.build_month.is_some()
    }
}

const COLS: &str = "variant, build_month, file_path, file_size, sha256, source, \
                    downloaded_at, checked_at, last_error";

fn row_to_db(row: &tokio_postgres::Row) -> GeoipDatabase {
    GeoipDatabase {
        variant: row.get("variant"),
        build_month: row.get("build_month"),
        file_path: row.get("file_path"),
        file_size: row.get("file_size"),
        sha256: row.get("sha256"),
        source: row.get("source"),
        downloaded_at: row.get("downloaded_at"),
        checked_at: row.get("checked_at"),
        last_error: row.get("last_error"),
    }
}

/// Fetch the single metadata row. The migration guarantees it exists.
pub async fn get(client: &deadpool_postgres::Client) -> Result<GeoipDatabase, DbError> {
    let row = client
        .query_one(
            &format!("SELECT {COLS} FROM geoip_database WHERE id = 1"),
            &[],
        )
        .await?;
    Ok(row_to_db(&row))
}

/// Record a successfully installed database, clearing any previous error.
pub async fn set_installed(
    client: &deadpool_postgres::Client,
    variant: &str,
    build_month: &str,
    file_path: &str,
    file_size: i64,
    sha256: &str,
    source: &str,
) -> Result<GeoipDatabase, DbError> {
    let row = client
        .query_one(
            &format!(
                "UPDATE geoip_database \
                 SET variant = $1, build_month = $2, file_path = $3, file_size = $4, \
                     sha256 = $5, source = $6, downloaded_at = now(), checked_at = now(), \
                     last_error = NULL, updated_at = now() \
                 WHERE id = 1 RETURNING {COLS}"
            ),
            &[
                &variant,
                &build_month,
                &file_path,
                &file_size,
                &sha256,
                &source,
            ],
        )
        .await?;
    Ok(row_to_db(&row))
}

/// Record a completed check that installed nothing (already current).
pub async fn mark_checked(client: &deadpool_postgres::Client) -> Result<(), DbError> {
    client
        .execute(
            "UPDATE geoip_database SET checked_at = now(), last_error = NULL, \
                    updated_at = now() WHERE id = 1",
            &[],
        )
        .await?;
    Ok(())
}

/// Record a failed attempt. Leaves the installed database untouched — a bad
/// download must never cost the operator a working one.
pub async fn mark_error(client: &deadpool_postgres::Client, error: &str) -> Result<(), DbError> {
    // Bound the stored text: this is surfaced in a UI card, and some transport
    // errors stringify to something enormous.
    let truncated: String = error.chars().take(500).collect();
    client
        .execute(
            "UPDATE geoip_database SET checked_at = now(), last_error = $1, \
                    updated_at = now() WHERE id = 1",
            &[&truncated],
        )
        .await?;
    Ok(())
}

/// Forget the installed database (after the file is removed from disk).
pub async fn clear(client: &deadpool_postgres::Client) -> Result<(), DbError> {
    client
        .execute(
            "UPDATE geoip_database \
             SET variant = NULL, build_month = NULL, file_path = NULL, file_size = NULL, \
                 sha256 = NULL, source = NULL, downloaded_at = NULL, last_error = NULL, \
                 updated_at = now() \
             WHERE id = 1",
            &[],
        )
        .await?;
    Ok(())
}

/// Advisory-lock key for the download path.
///
/// Guards against two instances (or a scheduled refresh racing an admin's
/// "update now") both pulling the same 62 MB file.
const DOWNLOAD_LOCK: i64 = 0x6765_6F69_7000_0001_u64.cast_signed();

/// Try to claim the download lock for this session. Returns false when another
/// connection holds it, in which case the caller should skip this round.
///
/// The lock is session-scoped and released by [`unlock_download`] or when the
/// connection returns to the pool and is recycled.
pub async fn try_lock_download(client: &deadpool_postgres::Client) -> Result<bool, DbError> {
    let row = client
        .query_one("SELECT pg_try_advisory_lock($1) AS ok", &[&DOWNLOAD_LOCK])
        .await?;
    Ok(row.get("ok"))
}

/// Release the download lock.
pub async fn unlock_download(client: &deadpool_postgres::Client) {
    if let Err(e) = client
        .execute("SELECT pg_advisory_unlock($1)", &[&DOWNLOAD_LOCK])
        .await
    {
        tracing::warn!(error = %e, "failed to release geoip download lock");
    }
}
