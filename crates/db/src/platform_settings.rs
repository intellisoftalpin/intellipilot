//! Single-row platform settings (V011). Exposes `open_registration` plus the
//! white-label branding fields (custom name / message / app icon).

use time::OffsetDateTime;
use uuid::Uuid;

use crate::DbError;

#[derive(Debug, Clone)]
pub struct PlatformSettings {
    pub open_registration: bool,
    /// Custom application name. `None` means "use the bundled default".
    pub app_name: Option<String>,
    /// Optional notice shown to users on the login screen.
    pub app_message: Option<String>,
    /// MIME type of the stored custom icon, if any. Doubles as a "has custom
    /// icon" flag without loading the (potentially large) `bytea`.
    pub app_icon_mime: Option<String>,
    /// When the custom icon was last set — clients use it for cache-busting.
    pub app_icon_updated_at: Option<OffsetDateTime>,
    /// Master switch for IP geolocation (V018). Off by default: resolution is
    /// local, but the data it derives is personal, so an operator opts in.
    pub geoip_enabled: bool,
    /// `country` (~4 MB) or `city` (~62 MB). City is the default because the
    /// admin user list shows both country and city.
    pub geoip_variant: String,
    /// Refresh the database monthly without an admin asking.
    pub geoip_auto_update: bool,
    pub updated_at: OffsetDateTime,
    pub updated_by: Option<Uuid>,
}

const SELECT_COLS: &str = "open_registration, app_name, app_message, \
     app_icon_mime, app_icon_updated_at, geoip_enabled, geoip_variant, \
     geoip_auto_update, updated_at, updated_by";

fn row_to_settings(row: &tokio_postgres::Row) -> PlatformSettings {
    PlatformSettings {
        open_registration: row.get("open_registration"),
        app_name: row.get("app_name"),
        app_message: row.get("app_message"),
        app_icon_mime: row.get("app_icon_mime"),
        app_icon_updated_at: row.get("app_icon_updated_at"),
        geoip_enabled: row.get("geoip_enabled"),
        geoip_variant: row.get("geoip_variant"),
        geoip_auto_update: row.get("geoip_auto_update"),
        updated_at: row.get("updated_at"),
        updated_by: row.get("updated_by"),
    }
}

/// Fetch the single settings row.
///
/// The migration guarantees the row exists, so a missing row is treated as an
/// internal error. The icon `bytea` is not loaded here — use [`get_app_icon`]
/// to stream the bytes.
pub async fn get(client: &deadpool_postgres::Client) -> Result<PlatformSettings, DbError> {
    let row = client
        .query_one(
            &format!("SELECT {SELECT_COLS} FROM platform_settings WHERE id = 1"),
            &[],
        )
        .await?;
    Ok(row_to_settings(&row))
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
            &format!(
                "UPDATE platform_settings \
                 SET open_registration = $1, updated_at = now(), updated_by = $2 \
                 WHERE id = 1 RETURNING {SELECT_COLS}"
            ),
            &[&value, &updated_by],
        )
        .await?;
    Ok(row_to_settings(&row))
}

/// Set the white-label name and message. Passing `None` clears the field,
/// reverting to the bundled default.
pub async fn set_branding(
    client: &deadpool_postgres::Client,
    app_name: Option<&str>,
    app_message: Option<&str>,
    updated_by: Uuid,
) -> Result<PlatformSettings, DbError> {
    let row = client
        .query_one(
            &format!(
                "UPDATE platform_settings \
                 SET app_name = $1, app_message = $2, updated_at = now(), updated_by = $3 \
                 WHERE id = 1 RETURNING {SELECT_COLS}"
            ),
            &[&app_name, &app_message, &updated_by],
        )
        .await?;
    Ok(row_to_settings(&row))
}

/// Update the geolocation configuration. `None` leaves a field unchanged.
///
/// Superadmin-only, like every other write here — the gate is the
/// `SuperadminUser` extractor on `/admin/*`, not a check in this layer.
pub async fn set_geoip(
    client: &deadpool_postgres::Client,
    enabled: Option<bool>,
    variant: Option<&str>,
    auto_update: Option<bool>,
    updated_by: Uuid,
) -> Result<PlatformSettings, DbError> {
    let row = client
        .query_one(
            &format!(
                "UPDATE platform_settings \
                 SET geoip_enabled     = COALESCE($1, geoip_enabled), \
                     geoip_variant     = COALESCE($2, geoip_variant), \
                     geoip_auto_update = COALESCE($3, geoip_auto_update), \
                     updated_at = now(), updated_by = $4 \
                 WHERE id = 1 RETURNING {SELECT_COLS}"
            ),
            &[&enabled, &variant, &auto_update, &updated_by],
        )
        .await?;
    Ok(row_to_settings(&row))
}

/// Store a custom app icon (raw bytes + MIME), stamping `app_icon_updated_at`.
pub async fn set_app_icon(
    client: &deadpool_postgres::Client,
    bytes: &[u8],
    mime: &str,
    updated_by: Uuid,
) -> Result<PlatformSettings, DbError> {
    let row = client
        .query_one(
            &format!(
                "UPDATE platform_settings \
                 SET app_icon = $1, app_icon_mime = $2, app_icon_updated_at = now(), \
                     updated_at = now(), updated_by = $3 \
                 WHERE id = 1 RETURNING {SELECT_COLS}"
            ),
            &[&bytes, &mime, &updated_by],
        )
        .await?;
    Ok(row_to_settings(&row))
}

/// Remove the custom app icon, reverting to the bundled default.
pub async fn clear_app_icon(
    client: &deadpool_postgres::Client,
    updated_by: Uuid,
) -> Result<PlatformSettings, DbError> {
    let row = client
        .query_one(
            &format!(
                "UPDATE platform_settings \
                 SET app_icon = NULL, app_icon_mime = NULL, app_icon_updated_at = NULL, \
                     updated_at = now(), updated_by = $1 \
                 WHERE id = 1 RETURNING {SELECT_COLS}"
            ),
            &[&updated_by],
        )
        .await?;
    Ok(row_to_settings(&row))
}

/// Fetch the stored custom icon bytes and MIME, if one is set.
pub async fn get_app_icon(
    client: &deadpool_postgres::Client,
) -> Result<Option<(Vec<u8>, String)>, DbError> {
    let row = client
        .query_one(
            "SELECT app_icon, app_icon_mime FROM platform_settings WHERE id = 1",
            &[],
        )
        .await?;
    let bytes: Option<Vec<u8>> = row.get("app_icon");
    let mime: Option<String> = row.get("app_icon_mime");
    Ok(match (bytes, mime) {
        (Some(b), Some(m)) => Some((b, m)),
        _ => None,
    })
}
