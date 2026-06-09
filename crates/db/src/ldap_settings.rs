//! Single-row LDAP configuration (V002), edited by a superadmin via the admin
//! UI. No bind secret is stored: authentication uses a direct bind as the
//! logging-in user.

use time::OffsetDateTime;
use uuid::Uuid;

use crate::DbError;

#[derive(Debug, Clone)]
pub struct LdapSettings {
    pub enabled: bool,
    pub server_url: String,
    pub use_start_tls: bool,
    pub skip_tls_verify: bool,
    pub base_dn: String,
    pub default_domain: String,
    pub bind_dn_format: String,
    pub user_search_filter: String,
    pub superadmin_group: String,
    pub attr_email: String,
    pub attr_display_name: String,
    pub attr_username: String,
    pub connection_timeout_secs: i32,
    pub updated_at: OffsetDateTime,
    pub updated_by: Option<Uuid>,
}

/// Mutable LDAP configuration fields (everything except audit columns).
#[derive(Debug, Clone)]
pub struct LdapSettingsUpdate {
    pub enabled: bool,
    pub server_url: String,
    pub use_start_tls: bool,
    pub skip_tls_verify: bool,
    pub base_dn: String,
    pub default_domain: String,
    pub bind_dn_format: String,
    pub user_search_filter: String,
    pub superadmin_group: String,
    pub attr_email: String,
    pub attr_display_name: String,
    pub attr_username: String,
    pub connection_timeout_secs: i32,
}

const COLS: &str = "enabled, server_url, use_start_tls, skip_tls_verify, base_dn, \
                    default_domain, bind_dn_format, user_search_filter, superadmin_group, \
                    attr_email, attr_display_name, attr_username, connection_timeout_secs, \
                    updated_at, updated_by";

fn row_to_settings(row: &tokio_postgres::Row) -> LdapSettings {
    LdapSettings {
        enabled: row.get("enabled"),
        server_url: row.get("server_url"),
        use_start_tls: row.get("use_start_tls"),
        skip_tls_verify: row.get("skip_tls_verify"),
        base_dn: row.get("base_dn"),
        default_domain: row.get("default_domain"),
        bind_dn_format: row.get("bind_dn_format"),
        user_search_filter: row.get("user_search_filter"),
        superadmin_group: row.get("superadmin_group"),
        attr_email: row.get("attr_email"),
        attr_display_name: row.get("attr_display_name"),
        attr_username: row.get("attr_username"),
        connection_timeout_secs: row.get("connection_timeout_secs"),
        updated_at: row.get("updated_at"),
        updated_by: row.get("updated_by"),
    }
}

/// Fetch the single settings row. The migration guarantees it exists.
pub async fn get(client: &deadpool_postgres::Client) -> Result<LdapSettings, DbError> {
    let row = client
        .query_one(
            &format!("SELECT {COLS} FROM ldap_settings WHERE id = 1"),
            &[],
        )
        .await?;
    Ok(row_to_settings(&row))
}

/// Replace all mutable fields, recording the actor.
pub async fn set(
    client: &deadpool_postgres::Client,
    upd: &LdapSettingsUpdate,
    updated_by: Uuid,
) -> Result<LdapSettings, DbError> {
    let row = client
        .query_one(
            &format!(
                "UPDATE ldap_settings SET \
                   enabled = $1, server_url = $2, use_start_tls = $3, skip_tls_verify = $4, \
                   base_dn = $5, default_domain = $6, bind_dn_format = $7, \
                   user_search_filter = $8, superadmin_group = $9, attr_email = $10, \
                   attr_display_name = $11, attr_username = $12, connection_timeout_secs = $13, \
                   updated_at = now(), updated_by = $14 \
                 WHERE id = 1 RETURNING {COLS}"
            ),
            &[
                &upd.enabled,
                &upd.server_url,
                &upd.use_start_tls,
                &upd.skip_tls_verify,
                &upd.base_dn,
                &upd.default_domain,
                &upd.bind_dn_format,
                &upd.user_search_filter,
                &upd.superadmin_group,
                &upd.attr_email,
                &upd.attr_display_name,
                &upd.attr_username,
                &upd.connection_timeout_secs,
                &updated_by,
            ],
        )
        .await?;
    Ok(row_to_settings(&row))
}
