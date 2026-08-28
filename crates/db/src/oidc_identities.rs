//! Bindings between IntelliPilot users and external OIDC subjects (V025).
//!
//! A sign-in resolves to a user by `(provider_id, subject)` and by nothing
//! else. Email is deliberately not an authenticating fact anywhere in this
//! module: an IdP can change a user's address, reassign it, or assert one it
//! never verified, and any of those would otherwise become an account
//! takeover. Email appears here only as `email_at_link`, which exists so the
//! UI can tell two linked accounts apart.

use time::OffsetDateTime;
use uuid::Uuid;

use crate::DbError;

#[derive(Debug, Clone)]
pub struct OidcIdentity {
    pub id: Uuid,
    pub user_id: Uuid,
    pub provider_id: Uuid,
    pub issuer: String,
    pub subject: String,
    pub email_at_link: String,
    pub created_at: OffsetDateTime,
    pub last_login_at: Option<OffsetDateTime>,
}

/// An identity joined with its provider's display fields, for the "your linked
/// accounts" list on the Security page.
#[derive(Debug, Clone)]
pub struct OidcIdentityView {
    pub identity: OidcIdentity,
    pub provider_slug: String,
    pub provider_display_name: String,
}

const COLS: &str =
    "id, user_id, provider_id, issuer, subject, email_at_link, created_at, last_login_at";

fn row_to_identity(row: &tokio_postgres::Row) -> OidcIdentity {
    OidcIdentity {
        id: row.get("id"),
        user_id: row.get("user_id"),
        provider_id: row.get("provider_id"),
        issuer: row.get("issuer"),
        subject: row.get("subject"),
        email_at_link: row.get("email_at_link"),
        created_at: row.get("created_at"),
        last_login_at: row.get("last_login_at"),
    }
}

/// The authenticating lookup: which user, if any, owns this subject at this
/// provider.
pub async fn find_by_subject(
    client: &deadpool_postgres::Client,
    provider_id: Uuid,
    subject: &str,
) -> Result<Option<OidcIdentity>, DbError> {
    let row = client
        .query_opt(
            &format!("SELECT {COLS} FROM oidc_identities WHERE provider_id = $1 AND subject = $2"),
            &[&provider_id, &subject],
        )
        .await?;
    Ok(row.as_ref().map(row_to_identity))
}

/// Bind a subject to a user.
///
/// Returns a unique-violation `DbError` when the subject is already bound
/// elsewhere; the caller turns that into a clear "already linked to another
/// account" response rather than silently repointing it.
pub async fn link(
    client: &deadpool_postgres::Client,
    user_id: Uuid,
    provider_id: Uuid,
    issuer: &str,
    subject: &str,
    email_at_link: &str,
) -> Result<OidcIdentity, DbError> {
    let row = client
        .query_one(
            &format!(
                "INSERT INTO oidc_identities \
                   (user_id, provider_id, issuer, subject, email_at_link, last_login_at) \
                 VALUES ($1, $2, $3, $4, $5, now()) RETURNING {COLS}"
            ),
            &[&user_id, &provider_id, &issuer, &subject, &email_at_link],
        )
        .await?;
    Ok(row_to_identity(&row))
}

/// Stamp a successful sign-in. Cosmetic — never fail a login over it.
pub async fn stamp_login(client: &deadpool_postgres::Client, id: Uuid) {
    if let Err(e) = client
        .execute(
            "UPDATE oidc_identities SET last_login_at = now() WHERE id = $1",
            &[&id],
        )
        .await
    {
        tracing::warn!(error = %e, "failed to stamp oidc identity login");
    }
}

/// Every identity a user holds, with provider display fields for the UI.
pub async fn list_for_user(
    client: &deadpool_postgres::Client,
    user_id: Uuid,
) -> Result<Vec<OidcIdentityView>, DbError> {
    let rows = client
        .query(
            "SELECT i.id, i.user_id, i.provider_id, i.issuer, i.subject, i.email_at_link, \
                    i.created_at, i.last_login_at, \
                    p.slug AS provider_slug, p.display_name AS provider_display_name \
               FROM oidc_identities i \
               JOIN oidc_providers p ON p.id = i.provider_id \
              WHERE i.user_id = $1 \
              ORDER BY p.sort_order, p.display_name",
            &[&user_id],
        )
        .await?;
    Ok(rows
        .iter()
        .map(|r| OidcIdentityView {
            identity: row_to_identity(r),
            provider_slug: r.get("provider_slug"),
            provider_display_name: r.get("provider_display_name"),
        })
        .collect())
}

/// How many identities a user holds. Used together with the presence of a
/// local password to decide whether unlinking would lock them out.
pub async fn count_for_user(
    client: &deadpool_postgres::Client,
    user_id: Uuid,
) -> Result<i64, DbError> {
    let row = client
        .query_one(
            "SELECT count(*) AS n FROM oidc_identities WHERE user_id = $1",
            &[&user_id],
        )
        .await?;
    Ok(row.get("n"))
}

/// Remove a binding. Scoped by `user_id` so one user can never unlink another's
/// identity by guessing an id.
pub async fn unlink(
    client: &deadpool_postgres::Client,
    user_id: Uuid,
    id: Uuid,
) -> Result<bool, DbError> {
    let n = client
        .execute(
            "DELETE FROM oidc_identities WHERE id = $1 AND user_id = $2",
            &[&id, &user_id],
        )
        .await?;
    Ok(n > 0)
}

/// Users bound to this issuer/subject pair, for back-channel logout.
///
/// `sid` is not stored, so only the `sub` form of a logout token resolves to
/// anyone; one carrying only `sid` is accepted and ignored rather than
/// erroring.
pub async fn find_users_by_issuer_subject(
    client: &deadpool_postgres::Client,
    issuer: &str,
    subject: &str,
) -> Result<Vec<Uuid>, DbError> {
    let rows = client
        .query(
            "SELECT DISTINCT user_id FROM oidc_identities WHERE issuer = $1 AND subject = $2",
            &[&issuer, &subject],
        )
        .await?;
    Ok(rows.iter().map(|r| r.get("user_id")).collect())
}
