-- ===========================================================================
-- Account security: admin-driven 2FA recovery, bans, session visibility and
-- optional local IP geolocation.
--
-- Motivating defects:
--   * A user who loses every second factor is locked out permanently — the
--     only disable path (`DELETE /me/totp`) requires an authenticated session,
--     which is exactly what the lockout prevents. Superadmins get a reset.
--   * `is_active` cannot express a ban for directory accounts:
--     `users.find_or_link_ldap_user` runs `SET ... is_active = true` on every
--     LDAP login, silently resurrecting a deactivated account. Bans therefore
--     live in their own columns that the LDAP sync never writes.
-- ===========================================================================

-- --- Users: ban state + activity stamps ------------------------------------
--
-- `banned_at` is deliberately independent of `is_active`: deactivation is
-- admin housekeeping (reversible, synced from the directory), a ban is an
-- enforced lockout that only a superadmin can lift.
ALTER TABLE users
    ADD COLUMN banned_at     timestamptz,
    ADD COLUMN banned_by     uuid REFERENCES users(id) ON DELETE SET NULL,
    ADD COLUMN ban_reason    text,
    -- Last authenticated request, stamped at most once per throttle window by
    -- the presence tracker (not on every request).
    ADD COLUMN last_seen_at  timestamptz,
    -- Last successful login (password, LDAP, passkey or completed 2FA).
    ADD COLUMN last_login_at timestamptz;

CREATE INDEX users_banned_idx ON users (banned_at) WHERE banned_at IS NOT NULL;

-- Seed `last_login_at` from the audit trail so existing installs show real
-- history immediately instead of a column of blanks.
UPDATE users u
SET last_login_at = a.last_at
FROM (
    SELECT actor_id, max(created_at) AS last_at
    FROM audit_log
    WHERE actor_id IS NOT NULL
      AND action IN ('login_success', 'login_success_ldap')
    GROUP BY actor_id
) a
WHERE a.actor_id = u.id;

-- Best-effort seed for last activity: the most recent audit event of any kind
-- is a closer floor than NULL, and the presence tracker corrects it on the
-- user's next request.
UPDATE users u
SET last_seen_at = a.last_at
FROM (
    SELECT actor_id, max(created_at) AS last_at
    FROM audit_log
    WHERE actor_id IS NOT NULL
    GROUP BY actor_id
) a
WHERE a.actor_id = u.id;

-- --- Sessions: activity + resolved location --------------------------------
--
-- A refresh-token family is one logical session. `created_at`/`ip` recorded
-- where a session began; these columns track where it currently is.
ALTER TABLE refresh_token_families
    ADD COLUMN last_seen_at timestamptz NOT NULL DEFAULT now(),
    ADD COLUMN last_ip      inet,
    -- ISO 3166-1 alpha-2, resolved locally from the mmdb. NULL when
    -- geolocation is disabled (the default), the address is private, or the
    -- database has no entry for it.
    ADD COLUMN country_code char(2),
    -- City name as published by the database; NULL for country-only databases
    -- and for ranges the city database does not resolve.
    ADD COLUMN city         text;

-- Existing rows: the session started where it was last seen, as far as we know.
UPDATE refresh_token_families
SET last_seen_at = created_at,
    last_ip      = ip;

-- Backs the per-user "active sessions" aggregate on the admin user list.
CREATE INDEX refresh_token_families_user_seen_idx
    ON refresh_token_families (user_id, last_seen_at DESC)
    WHERE revoked_at IS NULL;

-- --- Platform settings: geolocation toggle ---------------------------------
--
-- Off by default and superadmin-only. IP-derived city data is personal data;
-- an operator opts in explicitly, and `POST /admin/geoip/purge` clears what
-- was already collected.
ALTER TABLE platform_settings
    ADD COLUMN geoip_enabled     boolean NOT NULL DEFAULT false,
    -- 'country' (~4 MB) or 'city' (~62 MB). City is the default because the
    -- admin list shows both country and city.
    ADD COLUMN geoip_variant     text    NOT NULL DEFAULT 'city'
        CHECK (geoip_variant IN ('country', 'city')),
    -- Monthly refresh. Superadmins can also trigger an update on demand.
    ADD COLUMN geoip_auto_update boolean NOT NULL DEFAULT true;

-- --- Installed geolocation database ----------------------------------------
--
-- Metadata only. The .mmdb itself lives on the filesystem under the storage
-- directory: it is up to 62 MB, is memory-mapped rather than read, and is
-- never redistributed in our image (DB-IP Lite is CC BY 4.0 — the operator's
-- instance downloads it).
CREATE TABLE geoip_database (
    id            smallint    PRIMARY KEY CHECK (id = 1),
    -- 'country' | 'city' — what is actually installed, which may lag the
    -- configured variant until the next refresh completes.
    variant       text,
    -- Publication month of the installed file, 'YYYY-MM'. Drives the
    -- "is there something newer?" check.
    build_month   text,
    -- Path relative to the storage directory.
    file_path     text,
    file_size     bigint,
    sha256        char(64),
    -- 'download' (fetched from the publisher) | 'upload' (admin-supplied).
    source        text,
    downloaded_at timestamptz,
    -- Last time an update was attempted, successful or not.
    checked_at    timestamptz,
    -- Message from the last failed attempt; NULL after a success. Surfaced in
    -- the admin card so a silently failing monthly refresh is visible.
    last_error    text,
    updated_at    timestamptz NOT NULL DEFAULT now()
);
INSERT INTO geoip_database (id) VALUES (1);
