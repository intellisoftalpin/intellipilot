//! OIDC provider configuration (V025), edited by a superadmin via the admin UI.
//!
//! Unlike [`crate::ldap_settings`], which is a single row, several providers
//! may be configured and enabled at once — the login screen renders a button
//! per enabled provider. `slug` is the stable route key; `display_name` is what
//! an admin edits.
//!
//! `client_secret` follows the same write-only convention as the LDAP service
//! password: stored here for the token exchange, never serialized by the API,
//! which exposes only a `client_secret_set` boolean.

use time::OffsetDateTime;
use uuid::Uuid;

use crate::DbError;

// The flags are independent configuration facts, not a state machine; grouping
// them to satisfy the lint would only obscure the column-per-field mapping.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone)]
pub struct OidcProvider {
    pub id: Uuid,
    pub slug: String,
    pub display_name: String,
    pub enabled: bool,
    pub issuer_url: String,
    pub client_id: String,
    /// Write-only secret — read here for the token exchange, never returned by
    /// the API.
    pub client_secret: String,
    pub scopes: String,
    pub claim_email: String,
    pub claim_username: String,
    pub claim_display_name: String,
    pub claim_groups: String,
    pub superadmin_group: String,
    pub allow_jit_provisioning: bool,
    pub require_email_verified: bool,
    pub device_flow_enabled: bool,
    pub sort_order: i32,
    pub skip_tls_verify: bool,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
    pub updated_by: Option<Uuid>,
}

impl OidcProvider {
    /// Scopes as a list, with `openid` guaranteed present and first.
    ///
    /// An authorization request without `openid` is plain OAuth2 and yields no
    /// ID token, which would leave nothing to verify — so it is re-added rather
    /// than trusted to the stored value.
    #[must_use]
    pub fn scope_list(&self) -> Vec<String> {
        let mut out = vec!["openid".to_owned()];
        for s in self.scopes.split_whitespace() {
            if !s.eq_ignore_ascii_case("openid") && !out.iter().any(|k| k == s) {
                out.push(s.to_owned());
            }
        }
        out
    }
}

/// Mutable provider fields (everything except id and audit columns).
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone)]
pub struct OidcProviderUpdate {
    pub slug: String,
    pub display_name: String,
    pub enabled: bool,
    pub issuer_url: String,
    pub client_id: String,
    /// `None`/blank keeps the stored secret (via `COALESCE`).
    pub client_secret: Option<String>,
    pub scopes: String,
    pub claim_email: String,
    pub claim_username: String,
    pub claim_display_name: String,
    pub claim_groups: String,
    pub superadmin_group: String,
    pub allow_jit_provisioning: bool,
    pub require_email_verified: bool,
    pub device_flow_enabled: bool,
    pub sort_order: i32,
    pub skip_tls_verify: bool,
}

const COLS: &str = "id, slug, display_name, enabled, issuer_url, client_id, client_secret, \
                    scopes, claim_email, claim_username, claim_display_name, claim_groups, \
                    superadmin_group, allow_jit_provisioning, require_email_verified, \
                    device_flow_enabled, sort_order, skip_tls_verify, \
                    created_at, updated_at, updated_by";

fn row_to_provider(row: &tokio_postgres::Row) -> OidcProvider {
    OidcProvider {
        id: row.get("id"),
        slug: row.get("slug"),
        display_name: row.get("display_name"),
        enabled: row.get("enabled"),
        issuer_url: row.get("issuer_url"),
        client_id: row.get("client_id"),
        client_secret: row.get("client_secret"),
        scopes: row.get("scopes"),
        claim_email: row.get("claim_email"),
        claim_username: row.get("claim_username"),
        claim_display_name: row.get("claim_display_name"),
        claim_groups: row.get("claim_groups"),
        superadmin_group: row.get("superadmin_group"),
        allow_jit_provisioning: row.get("allow_jit_provisioning"),
        require_email_verified: row.get("require_email_verified"),
        device_flow_enabled: row.get("device_flow_enabled"),
        sort_order: row.get("sort_order"),
        skip_tls_verify: row.get("skip_tls_verify"),
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
        updated_by: row.get("updated_by"),
    }
}

/// Every provider, configured or not, for the admin list.
pub async fn list_all(client: &deadpool_postgres::Client) -> Result<Vec<OidcProvider>, DbError> {
    let rows = client
        .query(
            &format!("SELECT {COLS} FROM oidc_providers ORDER BY sort_order, display_name"),
            &[],
        )
        .await?;
    Ok(rows.iter().map(row_to_provider).collect())
}

/// Only the enabled providers, in login-button order.
pub async fn list_enabled(
    client: &deadpool_postgres::Client,
) -> Result<Vec<OidcProvider>, DbError> {
    let rows = client
        .query(
            &format!(
                "SELECT {COLS} FROM oidc_providers WHERE enabled ORDER BY sort_order, display_name"
            ),
            &[],
        )
        .await?;
    Ok(rows.iter().map(row_to_provider).collect())
}

pub async fn get(
    client: &deadpool_postgres::Client,
    id: Uuid,
) -> Result<Option<OidcProvider>, DbError> {
    let row = client
        .query_opt(
            &format!("SELECT {COLS} FROM oidc_providers WHERE id = $1"),
            &[&id],
        )
        .await?;
    Ok(row.as_ref().map(row_to_provider))
}

/// Look up by route key. Used by every public flow endpoint.
pub async fn get_by_slug(
    client: &deadpool_postgres::Client,
    slug: &str,
) -> Result<Option<OidcProvider>, DbError> {
    let row = client
        .query_opt(
            &format!("SELECT {COLS} FROM oidc_providers WHERE slug = $1"),
            &[&slug],
        )
        .await?;
    Ok(row.as_ref().map(row_to_provider))
}

pub async fn create(
    client: &deadpool_postgres::Client,
    upd: &OidcProviderUpdate,
    updated_by: Uuid,
) -> Result<OidcProvider, DbError> {
    let row = client
        .query_one(
            &format!(
                "INSERT INTO oidc_providers \
                   (slug, display_name, enabled, issuer_url, client_id, client_secret, scopes, \
                    claim_email, claim_username, claim_display_name, claim_groups, \
                    superadmin_group, allow_jit_provisioning, require_email_verified, \
                    device_flow_enabled, sort_order, skip_tls_verify, updated_by) \
                 VALUES ($1, $2, $3, $4, $5, COALESCE($6, ''), $7, $8, $9, $10, $11, $12, \
                         $13, $14, $15, $16, $17, $18) \
                 RETURNING {COLS}"
            ),
            &[
                &upd.slug,
                &upd.display_name,
                &upd.enabled,
                &upd.issuer_url,
                &upd.client_id,
                &upd.client_secret,
                &upd.scopes,
                &upd.claim_email,
                &upd.claim_username,
                &upd.claim_display_name,
                &upd.claim_groups,
                &upd.superadmin_group,
                &upd.allow_jit_provisioning,
                &upd.require_email_verified,
                &upd.device_flow_enabled,
                &upd.sort_order,
                &upd.skip_tls_verify,
                &updated_by,
            ],
        )
        .await?;
    Ok(row_to_provider(&row))
}

/// Replace all mutable fields. A blank `client_secret` keeps the stored one, so
/// an admin can edit any other field without re-entering the secret.
pub async fn update(
    client: &deadpool_postgres::Client,
    id: Uuid,
    upd: &OidcProviderUpdate,
    updated_by: Uuid,
) -> Result<Option<OidcProvider>, DbError> {
    let row = client
        .query_opt(
            &format!(
                "UPDATE oidc_providers SET \
                   slug = $2, display_name = $3, enabled = $4, issuer_url = $5, \
                   client_id = $6, client_secret = COALESCE($7, client_secret), scopes = $8, \
                   claim_email = $9, claim_username = $10, claim_display_name = $11, \
                   claim_groups = $12, superadmin_group = $13, allow_jit_provisioning = $14, \
                   require_email_verified = $15, device_flow_enabled = $16, sort_order = $17, \
                   skip_tls_verify = $18, updated_by = $19 \
                 WHERE id = $1 RETURNING {COLS}"
            ),
            &[
                &id,
                &upd.slug,
                &upd.display_name,
                &upd.enabled,
                &upd.issuer_url,
                &upd.client_id,
                &upd.client_secret,
                &upd.scopes,
                &upd.claim_email,
                &upd.claim_username,
                &upd.claim_display_name,
                &upd.claim_groups,
                &upd.superadmin_group,
                &upd.allow_jit_provisioning,
                &upd.require_email_verified,
                &upd.device_flow_enabled,
                &upd.sort_order,
                &upd.skip_tls_verify,
                &updated_by,
            ],
        )
        .await?;
    Ok(row.as_ref().map(row_to_provider))
}

/// Delete a provider. Its identities cascade, so every user bound only to it
/// loses that sign-in route — the API layer warns before calling this.
pub async fn delete(client: &deadpool_postgres::Client, id: Uuid) -> Result<bool, DbError> {
    let n = client
        .execute("DELETE FROM oidc_providers WHERE id = $1", &[&id])
        .await?;
    Ok(n > 0)
}

/// Whether any provider is enabled. Cheap guard for the login screen and for
/// the "is SSO configured at all" checks.
pub async fn any_enabled(client: &deadpool_postgres::Client) -> Result<bool, DbError> {
    let row = client
        .query_one(
            "SELECT EXISTS (SELECT 1 FROM oidc_providers WHERE enabled) AS present",
            &[],
        )
        .await?;
    Ok(row.get("present"))
}
