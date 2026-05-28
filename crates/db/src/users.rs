//! User persistence.

use intellipilot_core::user::{NewUser, ProfileUpdate, User};
use time::OffsetDateTime;
use tokio_postgres::Row;
use uuid::Uuid;

use crate::DbError;

/// A user row including the password hash, for authentication only.
#[derive(Debug, Clone)]
pub struct UserWithSecret {
    pub user: User,
    pub password_hash: Option<String>,
}

/// Normalize an email for storage and lookup: trim + lowercase.
#[must_use]
pub fn normalize_email(email: &str) -> String {
    email.trim().to_lowercase()
}

fn row_to_user(row: &Row) -> User {
    User {
        id: row.get("id"),
        email: row.get("email"),
        username: row.get("username"),
        full_name: row.get("full_name"),
        lang: row.get("lang"),
        timezone: row.get("timezone"),
        is_active: row.get("is_active"),
        created_at: row.get("created_at"),
    }
}

const USER_COLS: &str = "id, email, username, full_name, lang, timezone, is_active, created_at";

/// Insert a new user. Email is normalized before storage.
pub async fn create(client: &deadpool_postgres::Client, new: &NewUser) -> Result<User, DbError> {
    let email = normalize_email(&new.email);
    let row = client
        .query_one(
            &format!(
                "INSERT INTO users (email, username, full_name, password_hash) \
                 VALUES ($1, $2, $3, $4) RETURNING {USER_COLS}"
            ),
            &[&email, &new.username, &new.full_name, &new.password_hash],
        )
        .await?;
    Ok(row_to_user(&row))
}

/// Find an active (non-deleted) user by email, including the password hash.
pub async fn find_by_email_with_secret(
    client: &deadpool_postgres::Client,
    email: &str,
) -> Result<Option<UserWithSecret>, DbError> {
    let email = normalize_email(email);
    let row = client
        .query_opt(
            &format!(
                "SELECT {USER_COLS}, password_hash FROM users \
                 WHERE email = $1 AND deleted_at IS NULL"
            ),
            &[&email],
        )
        .await?;
    Ok(row.map(|r| UserWithSecret {
        password_hash: r.get("password_hash"),
        user: row_to_user(&r),
    }))
}

/// Find an active user by id.
pub async fn find_by_id(
    client: &deadpool_postgres::Client,
    id: Uuid,
) -> Result<Option<User>, DbError> {
    let row = client
        .query_opt(
            &format!("SELECT {USER_COLS} FROM users WHERE id = $1 AND deleted_at IS NULL"),
            &[&id],
        )
        .await?;
    Ok(row.as_ref().map(row_to_user))
}

/// Update mutable profile fields. Returns the updated user, or `None` if no
/// such active user.
pub async fn update_profile(
    client: &deadpool_postgres::Client,
    id: Uuid,
    upd: &ProfileUpdate,
) -> Result<Option<User>, DbError> {
    let row = client
        .query_opt(
            &format!(
                "UPDATE users SET \
                   full_name = COALESCE($2, full_name), \
                   lang      = COALESCE($3, lang), \
                   timezone  = COALESCE($4, timezone) \
                 WHERE id = $1 AND deleted_at IS NULL \
                 RETURNING {USER_COLS}"
            ),
            &[&id, &upd.full_name, &upd.lang, &upd.timezone],
        )
        .await?;
    Ok(row.as_ref().map(row_to_user))
}

/// Store (or replace) the encrypted TOTP secret, leaving it unconfirmed.
pub async fn set_totp_secret(
    client: &deadpool_postgres::Client,
    id: Uuid,
    secret_enc: &[u8],
) -> Result<(), DbError> {
    client
        .execute(
            "UPDATE users SET totp_secret_enc = $2, totp_confirmed_at = NULL \
             WHERE id = $1 AND deleted_at IS NULL",
            &[&id, &secret_enc],
        )
        .await?;
    Ok(())
}

/// Fetch the encrypted TOTP secret and whether it is confirmed.
pub async fn get_totp(
    client: &deadpool_postgres::Client,
    id: Uuid,
) -> Result<Option<(Vec<u8>, bool)>, DbError> {
    let row = client
        .query_opt(
            "SELECT totp_secret_enc, (totp_confirmed_at IS NOT NULL) AS confirmed \
             FROM users WHERE id = $1 AND deleted_at IS NULL",
            &[&id],
        )
        .await?;
    Ok(row.and_then(|r| {
        let enc: Option<Vec<u8>> = r.get("totp_secret_enc");
        enc.map(|e| (e, r.get::<_, bool>("confirmed")))
    }))
}

/// Mark TOTP confirmed (active second factor).
pub async fn confirm_totp(client: &deadpool_postgres::Client, id: Uuid) -> Result<(), DbError> {
    client
        .execute(
            "UPDATE users SET totp_confirmed_at = now() \
             WHERE id = $1 AND deleted_at IS NULL",
            &[&id],
        )
        .await?;
    Ok(())
}

/// Disable TOTP entirely.
pub async fn disable_totp(client: &deadpool_postgres::Client, id: Uuid) -> Result<(), DbError> {
    client
        .execute(
            "UPDATE users SET totp_secret_enc = NULL, totp_confirmed_at = NULL \
             WHERE id = $1 AND deleted_at IS NULL",
            &[&id],
        )
        .await?;
    Ok(())
}

/// Whether the user has any active second factor (confirmed TOTP or a passkey).
pub async fn has_active_2fa(client: &deadpool_postgres::Client, id: Uuid) -> Result<bool, DbError> {
    let row = client
        .query_one(
            "SELECT \
               (SELECT totp_confirmed_at IS NOT NULL FROM users WHERE id = $1) AS totp, \
               EXISTS(SELECT 1 FROM webauthn_credentials WHERE user_id = $1) AS passkey",
            &[&id],
        )
        .await?;
    let totp: Option<bool> = row.get("totp");
    let passkey: bool = row.get("passkey");
    Ok(totp.unwrap_or(false) || passkey)
}

/// Soft-delete a user (GDPR erase with grace period). Returns true if a row
/// was affected.
pub async fn soft_delete(
    client: &deadpool_postgres::Client,
    id: Uuid,
    grace_until: OffsetDateTime,
) -> Result<bool, DbError> {
    let affected = client
        .execute(
            "UPDATE users SET deleted_at = now(), deleted_grace_until = $2, is_active = false \
             WHERE id = $1 AND deleted_at IS NULL",
            &[&id, &grace_until],
        )
        .await?;
    Ok(affected > 0)
}
