//! Single-row platform settings (V011). Currently exposes `open_registration`.

use time::OffsetDateTime;
use uuid::Uuid;

use crate::DbError;

#[derive(Debug, Clone)]
pub struct PlatformSettings {
    pub open_registration: bool,
    pub updated_at: OffsetDateTime,
    pub updated_by: Option<Uuid>,
}

/// Fetch the single settings row. The migration guarantees the row exists,
/// so a missing row is treated as an internal error.
pub async fn get(
    client: &deadpool_postgres::Client,
) -> Result<PlatformSettings, DbError> {
    let row = client
        .query_one(
            "SELECT open_registration, updated_at, updated_by \
             FROM platform_settings WHERE id = 1",
            &[],
        )
        .await?;
    Ok(PlatformSettings {
        open_registration: row.get("open_registration"),
        updated_at: row.get("updated_at"),
        updated_by: row.get("updated_by"),
    })
}

/// Set `open_registration`. Records the actor in `updated_by` and bumps
/// `updated_at`.
pub async fn set_open_registration(
    client: &deadpool_postgres::Client,
    value: bool,
    updated_by: Uuid,
) -> Result<PlatformSettings, DbError> {
    let row = client
        .query_one(
            "UPDATE platform_settings \
             SET open_registration = $1, \
                 updated_at        = now(), \
                 updated_by        = $2 \
             WHERE id = 1 \
             RETURNING open_registration, updated_at, updated_by",
            &[&value, &updated_by],
        )
        .await?;
    Ok(PlatformSettings {
        open_registration: row.get("open_registration"),
        updated_at: row.get("updated_at"),
        updated_by: row.get("updated_by"),
    })
}
