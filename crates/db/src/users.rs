//! User persistence.

use intellipilot_core::user::{
    NewUser, NewUserWithFlags, OutToday, ProfileCard, ProfileUpdate, User,
};
use time::{Date, OffsetDateTime};
use tokio_postgres::Row;
use uuid::Uuid;

use crate::DbError;

/// Lateral join resolving each user's absence in effect today.
///
/// Computes the absence in effect *today* (UTC), expanded to its booking's full
/// date range. `user_ref` is the SQL reference to the users row (`users` or an
/// alias like `u`). Pair with [`OUT_TODAY_COLS`] in the SELECT list.
#[must_use]
pub fn out_today_join(user_ref: &str) -> String {
    format!(
        " LEFT JOIN LATERAL ( \
            SELECT te.kind, \
                   COALESCE(bk.start_date, te.entry_date) AS start_date, \
                   COALESCE(bk.end_date, te.entry_date) AS end_date \
            FROM time_entries te \
            LEFT JOIN LATERAL ( \
                SELECT min(b.entry_date) AS start_date, max(b.entry_date) AS end_date \
                FROM time_entries b WHERE b.booking_id = te.booking_id \
            ) bk ON te.booking_id IS NOT NULL \
            WHERE te.user_id = {user_ref}.id AND te.kind <> 'work' \
              AND te.entry_date = (now() AT TIME ZONE 'UTC')::date \
            ORDER BY te.created_at LIMIT 1 \
        ) ooo ON true"
    )
}

/// Columns produced by [`out_today_join`], for the SELECT list.
pub const OUT_TODAY_COLS: &str = ", ooo.kind AS out_today_kind, ooo.start_date AS out_today_start, \
       ooo.end_date AS out_today_end";

/// Avatar / motto / mood display columns. Mood auto-expires: it is blanked once
/// the UTC day it was set on has passed. Always selected (cheap, no joins).
pub const CARD_COLS: &str = ", avatar_kind, COALESCE(avatar_emoji, '') AS avatar_emoji, \
       avatar_updated_at, motto, \
       CASE WHEN mood_set_on = (now() AT TIME ZONE 'UTC')::date \
            THEN COALESCE(mood_emoji, '') ELSE '' END AS mood_emoji, \
       CASE WHEN mood_set_on = (now() AT TIME ZONE 'UTC')::date \
            THEN mood_text ELSE '' END AS mood_text";

/// Build the out-of-office descriptor from the optional lateral-join columns
/// (absent on queries that don't include [`out_today_join`] → `None`).
#[must_use]
pub fn out_today_from_row(row: &Row) -> Option<OutToday> {
    let kind = row
        .try_get::<_, Option<String>>("out_today_kind")
        .ok()
        .flatten()?;
    let start = row
        .try_get::<_, Option<Date>>("out_today_start")
        .ok()
        .flatten()?;
    let end = row
        .try_get::<_, Option<Date>>("out_today_end")
        .ok()
        .flatten()?;
    Some(OutToday {
        kind,
        start_date: start,
        end_date: end,
    })
}

/// Build the profile card (avatar + motto + mood + out-of-office) from a row
/// that selected [`CARD_COLS`] (and optionally [`OUT_TODAY_COLS`]).
#[must_use]
pub fn card_from_row(row: &Row) -> ProfileCard {
    ProfileCard {
        avatar_kind: row.get("avatar_kind"),
        avatar_emoji: row.get("avatar_emoji"),
        avatar_updated_at: row.get("avatar_updated_at"),
        motto: row.get("motto"),
        mood_emoji: row.get("mood_emoji"),
        mood_text: row.get("mood_text"),
        out_today: out_today_from_row(row),
    }
}

/// Outcome of an admin update that may be refused by a domain invariant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdminUpdateOutcome {
    /// The row was updated.
    Updated,
    /// No matching active user was found.
    NotFound,
    /// The change would have removed the last active superadmin and was
    /// refused. Surfaced to handlers as 409 Conflict.
    LastSuperadmin,
}

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
        is_superadmin: row.get("is_superadmin"),
        must_change_password: row.get("must_change_password"),
        auth_source: row.get("auth_source"),
        created_at: row.get("created_at"),
        card: card_from_row(row),
    }
}

const USER_COLS: &str = "id, email, username, full_name, lang, timezone, \
                         is_active, is_superadmin, must_change_password, \
                         auth_source, created_at\
                         , avatar_kind, COALESCE(avatar_emoji, '') AS avatar_emoji, \
                         avatar_updated_at, motto, \
                         CASE WHEN mood_set_on = (now() AT TIME ZONE 'UTC')::date \
                              THEN COALESCE(mood_emoji, '') ELSE '' END AS mood_emoji, \
                         CASE WHEN mood_set_on = (now() AT TIME ZONE 'UTC')::date \
                              THEN mood_text ELSE '' END AS mood_text";

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

/// Find an active (non-deleted) user by id, including the password hash.
/// For self-service password changes, where the caller is already
/// authenticated and must re-verify the current password.
pub async fn find_by_id_with_secret(
    client: &deadpool_postgres::Client,
    id: Uuid,
) -> Result<Option<UserWithSecret>, DbError> {
    let row = client
        .query_opt(
            &format!(
                "SELECT {USER_COLS}, password_hash FROM users \
                 WHERE id = $1 AND deleted_at IS NULL"
            ),
            &[&id],
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

/// Whether the given user is an active (non-deleted) superadmin.
pub async fn is_active_superadmin(
    client: &deadpool_postgres::Client,
    id: Uuid,
) -> Result<bool, DbError> {
    let row = client
        .query_opt(
            "SELECT 1 FROM users \
             WHERE id = $1 AND is_superadmin AND is_active AND deleted_at IS NULL",
            &[&id],
        )
        .await?;
    Ok(row.is_some())
}

/// Find an active user by exact (normalized) email or username. Used to add an
/// existing account to a project without browsing the user directory.
pub async fn find_active_by_identifier(
    client: &deadpool_postgres::Client,
    identifier: &str,
) -> Result<Option<User>, DbError> {
    let email = normalize_email(identifier);
    let uname = identifier.trim();
    let row = client
        .query_opt(
            &format!(
                "SELECT {USER_COLS} FROM users \
                 WHERE (email = $1 OR username = $2) AND deleted_at IS NULL LIMIT 1"
            ),
            &[&email, &uname],
        )
        .await?;
    Ok(row.as_ref().map(row_to_user))
}

/// Find an active user by exact (normalized) email OR username, including the
/// password hash. Used by login so users can sign in with either identifier.
pub async fn find_by_identifier_with_secret(
    client: &deadpool_postgres::Client,
    identifier: &str,
) -> Result<Option<UserWithSecret>, DbError> {
    let email = normalize_email(identifier);
    let uname = identifier.trim();
    let row = client
        .query_opt(
            &format!(
                "SELECT {USER_COLS}, password_hash FROM users \
                 WHERE (email = $1 OR username = $2) AND deleted_at IS NULL LIMIT 1"
            ),
            &[&email, &uname],
        )
        .await?;
    Ok(row.map(|r| UserWithSecret {
        password_hash: r.get("password_hash"),
        user: row_to_user(&r),
    }))
}

/// Update mutable profile fields. Returns the updated user, or `None` if no
/// such active user.
pub async fn update_profile(
    client: &deadpool_postgres::Client,
    id: Uuid,
    upd: &ProfileUpdate,
) -> Result<Option<User>, DbError> {
    // Setting either mood field replaces both and stamps today (UTC) so the
    // mood auto-expires; leaving both `None` keeps the existing mood.
    let set_mood = upd.mood_emoji.is_some() || upd.mood_text.is_some();
    let mood_emoji = upd.mood_emoji.clone().unwrap_or_default();
    let mood_text = upd.mood_text.clone().unwrap_or_default();
    let row = client
        .query_opt(
            &format!(
                "UPDATE users SET \
                   full_name = COALESCE($2, full_name), \
                   lang      = COALESCE($3, lang), \
                   timezone  = COALESCE($4, timezone), \
                   motto     = COALESCE($5, motto), \
                   mood_emoji  = CASE WHEN $7 THEN $6 ELSE mood_emoji END, \
                   mood_text   = CASE WHEN $7 THEN $8 ELSE mood_text END, \
                   mood_set_on = CASE WHEN $7 THEN (now() AT TIME ZONE 'UTC')::date \
                                      ELSE mood_set_on END \
                 WHERE id = $1 AND deleted_at IS NULL \
                 RETURNING {USER_COLS}"
            ),
            &[
                &id,
                &upd.full_name,
                &upd.lang,
                &upd.timezone,
                &upd.motto,
                &mood_emoji,
                &set_mood,
                &mood_text,
            ],
        )
        .await?;
    Ok(row.as_ref().map(row_to_user))
}

/// Fetch a user by id with the out-of-office badge resolved (for `/me`).
pub async fn find_by_id_with_card(
    client: &deadpool_postgres::Client,
    id: Uuid,
) -> Result<Option<User>, DbError> {
    let row = client
        .query_opt(
            &format!(
                "SELECT {USER_COLS}{OUT_TODAY_COLS} FROM users{join} \
                 WHERE users.id = $1 AND users.deleted_at IS NULL",
                join = out_today_join("users"),
            ),
            &[&id],
        )
        .await?;
    Ok(row.as_ref().map(row_to_user))
}

/// The stored avatar object (key + mime) when the user's avatar is an uploaded
/// image, else `None`. For the avatar-serving endpoint.
pub async fn avatar_object(
    client: &deadpool_postgres::Client,
    id: Uuid,
) -> Result<Option<(String, String)>, DbError> {
    let row = client
        .query_opt(
            "SELECT avatar_storage_key, avatar_mime FROM users \
             WHERE id = $1 AND avatar_kind = 'image' AND deleted_at IS NULL",
            &[&id],
        )
        .await?;
    Ok(row.and_then(|r| {
        let key: Option<String> = r.get("avatar_storage_key");
        let mime: Option<String> = r.get("avatar_mime");
        match (key, mime) {
            (Some(k), Some(m)) => Some((k, m)),
            _ => None,
        }
    }))
}

/// The user's current avatar storage key (any kind), for cleanup before
/// replacing or clearing it.
pub async fn current_avatar_key(
    client: &deadpool_postgres::Client,
    id: Uuid,
) -> Result<Option<String>, DbError> {
    let row = client
        .query_opt(
            "SELECT avatar_storage_key FROM users WHERE id = $1 AND deleted_at IS NULL",
            &[&id],
        )
        .await?;
    Ok(row.and_then(|r| r.get::<_, Option<String>>("avatar_storage_key")))
}

/// Point the user's avatar at an uploaded image object.
pub async fn set_avatar_image(
    client: &deadpool_postgres::Client,
    id: Uuid,
    storage_key: &str,
    mime: &str,
) -> Result<bool, DbError> {
    let n = client
        .execute(
            "UPDATE users SET avatar_kind = 'image', avatar_storage_key = $2, \
                 avatar_mime = $3, avatar_emoji = NULL, avatar_updated_at = now() \
             WHERE id = $1 AND deleted_at IS NULL",
            &[&id, &storage_key, &mime],
        )
        .await?;
    Ok(n > 0)
}

/// Set the user's avatar to an emoji.
pub async fn set_avatar_emoji(
    client: &deadpool_postgres::Client,
    id: Uuid,
    emoji: &str,
) -> Result<bool, DbError> {
    let n = client
        .execute(
            "UPDATE users SET avatar_kind = 'emoji', avatar_emoji = $2, \
                 avatar_storage_key = NULL, avatar_mime = NULL, avatar_updated_at = now() \
             WHERE id = $1 AND deleted_at IS NULL",
            &[&id, &emoji],
        )
        .await?;
    Ok(n > 0)
}

/// Reset the user's avatar to the default (initials).
pub async fn clear_avatar(client: &deadpool_postgres::Client, id: Uuid) -> Result<bool, DbError> {
    let n = client
        .execute(
            "UPDATE users SET avatar_kind = 'default', avatar_storage_key = NULL, \
                 avatar_mime = NULL, avatar_emoji = NULL, avatar_updated_at = now() \
             WHERE id = $1 AND deleted_at IS NULL",
            &[&id],
        )
        .await?;
    Ok(n > 0)
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
///
/// Used by the user's own `DELETE /api/v1/me` flow — does NOT enforce the
/// last-superadmin guard. Admin-driven deletion goes through
/// [`soft_delete_guarded`].
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

// ===========================================================================
// V011: superadmin / admin-driven user management
// ===========================================================================

/// Count active (non-deleted, active, superadmin) users.
pub async fn count_active_superadmins(client: &deadpool_postgres::Client) -> Result<i64, DbError> {
    let row = client
        .query_one(
            "SELECT COUNT(*)::bigint AS n FROM users \
             WHERE is_superadmin AND is_active AND deleted_at IS NULL",
            &[],
        )
        .await?;
    Ok(row.get::<_, i64>("n"))
}

/// Unconditional promotion. Always safe — adding a superadmin never violates
/// the "at least one" invariant. Used by the env-driven bootstrap path.
pub async fn promote_to_superadmin(
    client: &deadpool_postgres::Client,
    id: Uuid,
) -> Result<bool, DbError> {
    let affected = client
        .execute(
            "UPDATE users SET is_superadmin = true \
             WHERE id = $1 AND deleted_at IS NULL",
            &[&id],
        )
        .await?;
    Ok(affected > 0)
}

/// Update `is_superadmin`. When demoting, refuses if the user is the last
/// active superadmin (would lock everyone out of the admin area).
pub async fn set_superadmin(
    client: &mut deadpool_postgres::Client,
    id: Uuid,
    value: bool,
) -> Result<AdminUpdateOutcome, DbError> {
    let tx = client.transaction().await?;

    let target = tx
        .query_opt(
            "SELECT is_superadmin, is_active, deleted_at IS NOT NULL AS deleted \
             FROM users WHERE id = $1 FOR UPDATE",
            &[&id],
        )
        .await?;
    let Some(target) = target else {
        tx.rollback().await?;
        return Ok(AdminUpdateOutcome::NotFound);
    };
    if target.get::<_, bool>("deleted") {
        tx.rollback().await?;
        return Ok(AdminUpdateOutcome::NotFound);
    }

    // Last-admin guard: when demoting an active superadmin, ensure another
    // active superadmin exists.
    if !value && target.get::<_, bool>("is_superadmin") && target.get::<_, bool>("is_active") {
        let row = tx
            .query_one(
                "SELECT COUNT(*)::bigint AS n FROM users \
                 WHERE is_superadmin AND is_active AND deleted_at IS NULL AND id <> $1",
                &[&id],
            )
            .await?;
        if row.get::<_, i64>("n") == 0 {
            tx.rollback().await?;
            return Ok(AdminUpdateOutcome::LastSuperadmin);
        }
    }

    tx.execute(
        "UPDATE users SET is_superadmin = $2 WHERE id = $1",
        &[&id, &value],
    )
    .await?;
    tx.commit().await?;
    Ok(AdminUpdateOutcome::Updated)
}

/// Update `is_active`. Deactivating an active superadmin uses the same
/// last-admin guard as demotion.
pub async fn set_active(
    client: &mut deadpool_postgres::Client,
    id: Uuid,
    value: bool,
) -> Result<AdminUpdateOutcome, DbError> {
    let tx = client.transaction().await?;

    let target = tx
        .query_opt(
            "SELECT is_superadmin, is_active, deleted_at IS NOT NULL AS deleted \
             FROM users WHERE id = $1 FOR UPDATE",
            &[&id],
        )
        .await?;
    let Some(target) = target else {
        tx.rollback().await?;
        return Ok(AdminUpdateOutcome::NotFound);
    };
    if target.get::<_, bool>("deleted") {
        tx.rollback().await?;
        return Ok(AdminUpdateOutcome::NotFound);
    }

    if !value && target.get::<_, bool>("is_superadmin") && target.get::<_, bool>("is_active") {
        let row = tx
            .query_one(
                "SELECT COUNT(*)::bigint AS n FROM users \
                 WHERE is_superadmin AND is_active AND deleted_at IS NULL AND id <> $1",
                &[&id],
            )
            .await?;
        if row.get::<_, i64>("n") == 0 {
            tx.rollback().await?;
            return Ok(AdminUpdateOutcome::LastSuperadmin);
        }
    }

    tx.execute(
        "UPDATE users SET is_active = $2 WHERE id = $1",
        &[&id, &value],
    )
    .await?;
    tx.commit().await?;
    Ok(AdminUpdateOutcome::Updated)
}

/// Set the forced-password-change flag. Cleared by the password-change handler
/// on success.
pub async fn set_must_change_password(
    client: &deadpool_postgres::Client,
    id: Uuid,
    value: bool,
) -> Result<bool, DbError> {
    let affected = client
        .execute(
            "UPDATE users SET must_change_password = $2 \
             WHERE id = $1 AND deleted_at IS NULL",
            &[&id, &value],
        )
        .await?;
    Ok(affected > 0)
}

/// Admin-driven soft-delete with last-admin guard.
pub async fn soft_delete_guarded(
    client: &mut deadpool_postgres::Client,
    id: Uuid,
    grace_until: OffsetDateTime,
) -> Result<AdminUpdateOutcome, DbError> {
    let tx = client.transaction().await?;

    let target = tx
        .query_opt(
            "SELECT is_superadmin, is_active, deleted_at IS NOT NULL AS deleted \
             FROM users WHERE id = $1 FOR UPDATE",
            &[&id],
        )
        .await?;
    let Some(target) = target else {
        tx.rollback().await?;
        return Ok(AdminUpdateOutcome::NotFound);
    };
    if target.get::<_, bool>("deleted") {
        tx.rollback().await?;
        return Ok(AdminUpdateOutcome::NotFound);
    }

    if target.get::<_, bool>("is_superadmin") && target.get::<_, bool>("is_active") {
        let row = tx
            .query_one(
                "SELECT COUNT(*)::bigint AS n FROM users \
                 WHERE is_superadmin AND is_active AND deleted_at IS NULL AND id <> $1",
                &[&id],
            )
            .await?;
        if row.get::<_, i64>("n") == 0 {
            tx.rollback().await?;
            return Ok(AdminUpdateOutcome::LastSuperadmin);
        }
    }

    tx.execute(
        "UPDATE users SET deleted_at = now(), deleted_grace_until = $2, is_active = false \
         WHERE id = $1",
        &[&id, &grace_until],
    )
    .await?;
    tx.commit().await?;
    Ok(AdminUpdateOutcome::Updated)
}

/// Admin-driven create: same shape as [`create`] but allows the admin to mark
/// the new account as `is_superadmin` and/or `must_change_password`.
pub async fn create_with_flags(
    client: &deadpool_postgres::Client,
    new: &NewUserWithFlags,
) -> Result<User, DbError> {
    let email = normalize_email(&new.new.email);
    let row = client
        .query_one(
            &format!(
                "INSERT INTO users \
                   (email, username, full_name, password_hash, \
                    is_superadmin, must_change_password) \
                 VALUES ($1, $2, $3, $4, $5, $6) RETURNING {USER_COLS}"
            ),
            &[
                &email,
                &new.new.username,
                &new.new.full_name,
                &new.new.password_hash,
                &new.is_superadmin,
                &new.must_change_password,
            ],
        )
        .await?;
    Ok(row_to_user(&row))
}

/// Provision or link a local account for an LDAP-authenticated user.
///
/// Matches an existing active account by email and links it; otherwise creates
/// a fresh account with `auth_source = 'ldap'` and no local password.
/// `is_superadmin` reflects directory group membership and is synced on every
/// login (the reason this also updates an existing row).
pub async fn find_or_link_ldap_user(
    client: &deadpool_postgres::Client,
    email: &str,
    username_hint: &str,
    full_name: &str,
    ldap_dn: Option<&str>,
    is_superadmin: bool,
) -> Result<User, DbError> {
    let email = normalize_email(email);
    if let Some(existing) = client
        .query_opt(
            &format!("SELECT {USER_COLS} FROM users WHERE email = $1 AND deleted_at IS NULL"),
            &[&email],
        )
        .await?
    {
        let id: Uuid = existing.get("id");
        let row = client
            .query_one(
                &format!(
                    "UPDATE users SET auth_source = 'ldap', ldap_dn = $2, \
                         is_superadmin = $3, full_name = $4, \
                         must_change_password = false, is_active = true, \
                         updated_at = now() \
                     WHERE id = $1 RETURNING {USER_COLS}"
                ),
                &[&id, &ldap_dn, &is_superadmin, &full_name],
            )
            .await?;
        return Ok(row_to_user(&row));
    }

    let username = free_username(client, username_hint).await?;
    let row = client
        .query_one(
            &format!(
                "INSERT INTO users \
                   (email, username, full_name, password_hash, auth_source, \
                    ldap_dn, is_superadmin, must_change_password) \
                 VALUES ($1, $2, $3, NULL, 'ldap', $4, $5, false) \
                 RETURNING {USER_COLS}"
            ),
            &[&email, &username, &full_name, &ldap_dn, &is_superadmin],
        )
        .await?;
    Ok(row_to_user(&row))
}

/// Find a username free of collisions, derived from `hint` (suffixing `2`,
/// `3`, … as needed). Falls back to the bare base after exhausting attempts,
/// letting the unique constraint surface a clean error.
async fn free_username(client: &deadpool_postgres::Client, hint: &str) -> Result<String, DbError> {
    let base: String = {
        let cleaned: String = hint
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
            .take(60)
            .collect();
        if cleaned.is_empty() {
            "user".to_owned()
        } else {
            cleaned
        }
    };
    for n in 0u32..10_000 {
        let cand = if n == 0 {
            base.clone()
        } else {
            format!("{base}{}", n.saturating_add(1))
        };
        let taken = client
            .query_opt("SELECT 1 FROM users WHERE username = $1", &[&cand])
            .await?
            .is_some();
        if !taken {
            return Ok(cand);
        }
    }
    Ok(base)
}

/// Filter / pagination params for the admin user list.
#[derive(Debug, Clone, Default)]
pub struct ListFilter {
    /// Case-insensitive substring search across email + username + full_name.
    pub q: Option<String>,
    pub limit: u32,
    pub offset: u32,
}

/// Paginated listing for the admin UI. Returns active and inactive users but
/// excludes soft-deleted ones.
pub async fn list(
    client: &deadpool_postgres::Client,
    filter: &ListFilter,
) -> Result<(Vec<User>, i64), DbError> {
    let limit = i64::from(filter.limit.clamp(1, 200));
    let offset = i64::from(filter.offset);
    let q_pat = filter.q.as_ref().map(|s| format!("%{}%", s.to_lowercase()));

    let rows = client
        .query(
            &format!(
                "SELECT {USER_COLS}{OUT_TODAY_COLS} FROM users{join} \
                 WHERE users.deleted_at IS NULL AND ( \
                   $1::text IS NULL OR \
                   lower(users.email)     LIKE $1 OR \
                   lower(users.username)  LIKE $1 OR \
                   lower(users.full_name) LIKE $1 \
                 ) \
                 ORDER BY users.created_at DESC \
                 LIMIT $2 OFFSET $3",
                join = out_today_join("users"),
            ),
            &[&q_pat, &limit, &offset],
        )
        .await?;
    let users = rows.iter().map(row_to_user).collect();

    let total = client
        .query_one(
            "SELECT COUNT(*)::bigint AS n FROM users \
             WHERE deleted_at IS NULL AND ( \
               $1::text IS NULL OR \
               lower(email)     LIKE $1 OR \
               lower(username)  LIKE $1 OR \
               lower(full_name) LIKE $1 \
             )",
            &[&q_pat],
        )
        .await?;
    Ok((users, total.get::<_, i64>("n")))
}
