//! User persistence.

use intellipilot_core::user::{
    AdminUserRow, NewUser, NewUserWithFlags, OutToday, ProfileCard, ProfileUpdate, SessionInfo,
    TwoFactorStatus, User,
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

/// What it takes to count as a superadmin who can still reach the admin area:
/// promoted, enabled, not banned, not deleted.
///
/// Single source of truth for the "don't lock everyone out" guard. A banned
/// superadmin cannot log in, so counting one as a survivor would let the last
/// *usable* superadmin be demoted, deactivated or deleted.
const ACTIVE_SUPERADMIN: &str =
    "is_superadmin AND is_active AND banned_at IS NULL AND deleted_at IS NULL";

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

/// Count superadmins who can still log in (see [`ACTIVE_SUPERADMIN`]).
pub async fn count_active_superadmins(client: &deadpool_postgres::Client) -> Result<i64, DbError> {
    let row = client
        .query_one(
            &format!("SELECT COUNT(*)::bigint AS n FROM users WHERE {ACTIVE_SUPERADMIN}"),
            &[],
        )
        .await?;
    Ok(row.get::<_, i64>("n"))
}

/// Whether stripping this target's access could remove the last usable
/// superadmin, meaning the caller must run the last-admin guard first.
///
/// A banned superadmin already cannot log in, so they are not a survivor and
/// demoting/deleting them needs no guard. Expects a row selecting
/// `is_superadmin`, `is_active` and `banned`.
fn is_last_admin_risk(target: &Row) -> bool {
    target.get::<_, bool>("is_superadmin")
        && target.get::<_, bool>("is_active")
        && !target.get::<_, bool>("banned")
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
            "SELECT is_superadmin, is_active, banned_at IS NOT NULL AS banned, \
                    deleted_at IS NOT NULL AS deleted \
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
    if !value && is_last_admin_risk(&target) {
        let row = tx
            .query_one(
                &format!(
                    "SELECT COUNT(*)::bigint AS n FROM users \
                     WHERE {ACTIVE_SUPERADMIN} AND id <> $1"
                ),
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
            "SELECT is_superadmin, is_active, banned_at IS NOT NULL AS banned, \
                    deleted_at IS NOT NULL AS deleted \
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

    if !value && is_last_admin_risk(&target) {
        let row = tx
            .query_one(
                &format!(
                    "SELECT COUNT(*)::bigint AS n FROM users \
                     WHERE {ACTIVE_SUPERADMIN} AND id <> $1"
                ),
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

/// Ban or unban an account.
///
/// Deliberately independent of `is_active`. Deactivation is housekeeping that
/// the LDAP login path re-syncs (`find_or_link_ldap_user` sets `is_active =
/// true` on every directory login); a ban must survive that, so it lives in
/// columns the sync never touches and only a superadmin can clear.
///
/// Banning a superadmin who is still the last usable one is refused, same as
/// demotion and deletion.
pub async fn set_banned(
    client: &mut deadpool_postgres::Client,
    id: Uuid,
    banned: bool,
    by: Uuid,
    reason: Option<&str>,
) -> Result<AdminUpdateOutcome, DbError> {
    let tx = client.transaction().await?;

    let target = tx
        .query_opt(
            "SELECT is_superadmin, is_active, banned_at IS NOT NULL AS banned, \
                    deleted_at IS NOT NULL AS deleted \
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

    if banned && is_last_admin_risk(&target) {
        let row = tx
            .query_one(
                &format!(
                    "SELECT COUNT(*)::bigint AS n FROM users \
                     WHERE {ACTIVE_SUPERADMIN} AND id <> $1"
                ),
                &[&id],
            )
            .await?;
        if row.get::<_, i64>("n") == 0 {
            tx.rollback().await?;
            return Ok(AdminUpdateOutcome::LastSuperadmin);
        }
    }

    if banned {
        tx.execute(
            "UPDATE users SET banned_at = now(), banned_by = $2, ban_reason = $3 \
             WHERE id = $1",
            &[&id, &by, &reason],
        )
        .await?;
    } else {
        tx.execute(
            "UPDATE users SET banned_at = NULL, banned_by = NULL, ban_reason = NULL \
             WHERE id = $1",
            &[&id],
        )
        .await?;
    }
    tx.commit().await?;
    Ok(AdminUpdateOutcome::Updated)
}

/// Whether the account is currently banned. Cheap enough for the login path.
pub async fn is_banned(client: &deadpool_postgres::Client, id: Uuid) -> Result<bool, DbError> {
    let row = client
        .query_opt(
            "SELECT banned_at IS NOT NULL AS banned FROM users WHERE id = $1",
            &[&id],
        )
        .await?;
    Ok(row.is_some_and(|r| r.get::<_, bool>("banned")))
}

/// Whether an account may authenticate right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccountStatus {
    pub is_active: bool,
    pub is_banned: bool,
}

impl AccountStatus {
    /// True when neither the ban nor the deactivation gate is closed.
    #[must_use]
    pub const fn may_authenticate(self) -> bool {
        self.is_active && !self.is_banned
    }
}

/// Stamp `last_seen_at` and return the account's authentication status in one
/// round trip.
///
/// Called by the presence tracker at most once per throttle window per user,
/// not per request — the access-token path is otherwise DB-free and must stay
/// that way. `None` means no such user (or soft-deleted).
pub async fn touch_last_seen(
    client: &deadpool_postgres::Client,
    id: Uuid,
) -> Result<Option<AccountStatus>, DbError> {
    let row = client
        .query_opt(
            "UPDATE users SET last_seen_at = now() \
             WHERE id = $1 AND deleted_at IS NULL \
             RETURNING is_active, banned_at IS NOT NULL AS banned",
            &[&id],
        )
        .await?;
    Ok(row.map(|r| AccountStatus {
        is_active: r.get("is_active"),
        is_banned: r.get("banned"),
    }))
}

/// Record a successful login. Also stamps activity so a user who logs in and
/// goes idle still shows a fresh "last seen".
pub async fn stamp_login(client: &deadpool_postgres::Client, id: Uuid) -> Result<(), DbError> {
    client
        .execute(
            "UPDATE users SET last_login_at = now(), last_seen_at = now() WHERE id = $1",
            &[&id],
        )
        .await?;
    Ok(())
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
            "SELECT is_superadmin, is_active, banned_at IS NOT NULL AS banned, \
                    deleted_at IS NOT NULL AS deleted \
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

    if is_last_admin_risk(&target) {
        let row = tx
            .query_one(
                &format!(
                    "SELECT COUNT(*)::bigint AS n FROM users \
                     WHERE {ACTIVE_SUPERADMIN} AND id <> $1"
                ),
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

/// Status filter for the admin user list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum StatusFilter {
    #[default]
    All,
    Active,
    Inactive,
    Banned,
    /// Accounts with no second factor at all — the population most exposed to
    /// account takeover, and the one an admin most often wants to chase.
    NoTwoFactor,
}

impl StatusFilter {
    /// Parse the `status` query parameter; anything unrecognised means "all".
    #[must_use]
    pub fn parse(raw: Option<&str>) -> Self {
        match raw {
            Some("active") => Self::Active,
            Some("inactive") => Self::Inactive,
            Some("banned") => Self::Banned,
            Some("no_2fa") => Self::NoTwoFactor,
            _ => Self::All,
        }
    }

    /// The SQL predicate for this filter, applied to the `users` table and the
    /// `tf` lateral. Returns `None` for [`Self::All`].
    const fn predicate(self) -> Option<&'static str> {
        match self {
            Self::All => None,
            Self::Active => Some("users.is_active AND users.banned_at IS NULL"),
            Self::Inactive => Some("NOT users.is_active AND users.banned_at IS NULL"),
            Self::Banned => Some("users.banned_at IS NOT NULL"),
            Self::NoTwoFactor => Some(
                "users.totp_confirmed_at IS NULL AND NOT EXISTS( \
                   SELECT 1 FROM webauthn_credentials wc WHERE wc.user_id = users.id)",
            ),
        }
    }
}

/// Filter / pagination params for the admin user list.
#[derive(Debug, Clone, Default)]
pub struct ListFilter {
    /// Case-insensitive substring search across email + username + full_name.
    pub q: Option<String>,
    pub status: StatusFilter,
    pub limit: u32,
    pub offset: u32,
}

/// A session is live when its family is not revoked and it still holds a token
/// that has not expired. Shared by the aggregate below and [`crate::sessions`].
pub(crate) const ACTIVE_FAMILY: &str = "f.revoked_at IS NULL AND EXISTS( \
       SELECT 1 FROM refresh_tokens t WHERE t.family_id = f.id AND t.expires_at > now())";

/// Second-factor counts + live-session summary for one user, as lateral joins.
///
/// Lateral rather than per-row queries: the admin list renders up to 200 users
/// and an N+1 here would mean 600 extra round trips per page load.
fn security_join() -> String {
    format!(
        " LEFT JOIN LATERAL ( \
            SELECT (SELECT count(*)::bigint FROM webauthn_credentials wc \
                     WHERE wc.user_id = users.id) AS passkeys, \
                   (SELECT count(*)::bigint FROM recovery_codes rc \
                     WHERE rc.user_id = users.id AND rc.used_at IS NULL) AS recovery_left \
          ) tf ON true \
          LEFT JOIN LATERAL ( \
            SELECT count(*)::bigint AS n FROM refresh_token_families f \
            WHERE f.user_id = users.id AND {ACTIVE_FAMILY} \
          ) sc ON true \
          LEFT JOIN LATERAL ( \
            SELECT f.id           AS sess_id, \
                   f.created_at   AS sess_created, \
                   f.last_seen_at AS sess_seen, \
                   f.last_ip      AS sess_ip, \
                   f.country_code AS sess_country, \
                   f.city         AS sess_city, \
                   f.user_agent   AS sess_ua \
            FROM refresh_token_families f \
            WHERE f.user_id = users.id AND {ACTIVE_FAMILY} \
            ORDER BY f.last_seen_at DESC LIMIT 1 \
          ) ls ON true"
    )
}

// Aliased inside the lateral above, not here: `USER_COLS` selects `id`,
// `created_at` and `last_seen_at` unqualified, so exposing a session's columns
// under those names would make the whole SELECT ambiguous.
const SECURITY_COLS: &str = ", users.totp_confirmed_at, users.banned_at, users.ban_reason, \
       users.banned_by, users.last_seen_at, users.last_login_at, \
       tf.passkeys, tf.recovery_left, sc.n AS active_sessions, \
       ls.sess_id, ls.sess_created, ls.sess_seen, ls.sess_ip, ls.sess_country, \
       ls.sess_city, ls.sess_ua";

fn row_to_admin_row(row: &Row) -> AdminUserRow {
    let user = row_to_user(row);
    let totp = row
        .get::<_, Option<OffsetDateTime>>("totp_confirmed_at")
        .is_some();
    let passkeys: i64 = row.get("passkeys");
    let banned_at: Option<OffsetDateTime> = row.get("banned_at");

    // Precedence: a ban outranks deactivation, because it is the stronger
    // statement and the only one the user cannot have done to themselves.
    let status = if banned_at.is_some() {
        "banned"
    } else if user.is_active {
        "active"
    } else {
        "inactive"
    };

    let last_session = row.get::<_, Option<Uuid>>("sess_id").map(|id| SessionInfo {
        id,
        created_at: row.get("sess_created"),
        last_seen_at: row.get("sess_seen"),
        ip: row
            .get::<_, Option<std::net::IpAddr>>("sess_ip")
            .map(|a| a.to_string()),
        country_code: row.get("sess_country"),
        city: row.get("sess_city"),
        user_agent: row.get("sess_ua"),
    });

    AdminUserRow {
        status: status.to_owned(),
        two_factor: TwoFactorStatus {
            enabled: totp || passkeys > 0,
            totp,
            passkeys,
            recovery_codes_left: row.get("recovery_left"),
        },
        active_sessions: row.get("active_sessions"),
        last_session,
        last_seen_at: row.get("last_seen_at"),
        last_login_at: row.get("last_login_at"),
        banned_at,
        ban_reason: row.get("ban_reason"),
        banned_by: row.get("banned_by"),
        user,
    }
}

/// Paginated listing for the admin UI, carrying each account's security
/// posture. Returns active, inactive and banned users; excludes soft-deleted
/// ones and the internal `system` account.
pub async fn list(
    client: &deadpool_postgres::Client,
    filter: &ListFilter,
) -> Result<(Vec<AdminUserRow>, i64), DbError> {
    let limit = i64::from(filter.limit.clamp(1, 200));
    let offset = i64::from(filter.offset);
    let q_pat = filter.q.as_ref().map(|s| format!("%{}%", s.to_lowercase()));
    // Static strings chosen by a closed enum — no caller input reaches the SQL.
    let status_clause = filter
        .status
        .predicate()
        .map_or_else(String::new, |p| format!(" AND ({p})"));

    let base_where = format!(
        "users.deleted_at IS NULL AND users.auth_source <> 'system' AND ( \
           $1::text IS NULL OR \
           lower(users.email)     LIKE $1 OR \
           lower(users.username)  LIKE $1 OR \
           lower(users.full_name) LIKE $1 \
         ){status_clause}"
    );

    let rows = client
        .query(
            &format!(
                "SELECT {USER_COLS}{OUT_TODAY_COLS}{SECURITY_COLS} FROM users{join}{sec} \
                 WHERE {base_where} \
                 ORDER BY users.created_at DESC \
                 LIMIT $2 OFFSET $3",
                join = out_today_join("users"),
                sec = security_join(),
            ),
            &[&q_pat, &limit, &offset],
        )
        .await?;
    let users = rows.iter().map(row_to_admin_row).collect();

    let total = client
        .query_one(
            &format!("SELECT COUNT(*)::bigint AS n FROM users WHERE {base_where}"),
            &[&q_pat],
        )
        .await?;
    Ok((users, total.get::<_, i64>("n")))
}
