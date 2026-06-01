-- Phase 10: Platform-level superadmin role + invite-only registration.
--
-- Until now, the platform has had no notion of an admin: the only `is_admin`
-- flag lived on per-project roles (V003). Registration was open to anyone
-- who could reach /api/v1/auth/register. This migration introduces:
--
--   * `users.is_superadmin`        — platform-wide admin flag
--   * `users.must_change_password` — direct-created accounts get this set,
--                                    the frontend forces a rotation on
--                                    first login
--   * `platform_settings`          — single-row table for runtime toggles
--                                    (currently just `open_registration`).
--                                    Defaults to FALSE — registration is
--                                    invite-only out of the box.
--   * `platform_invitations`       — tokenised email invitations issued by a
--                                    superadmin (no project scope, unlike
--                                    the per-project `invitations` table
--                                    from V003).

-- ---------------------------------------------------------------------------
-- users: superadmin + forced password change
-- ---------------------------------------------------------------------------
ALTER TABLE users
    ADD COLUMN is_superadmin        boolean NOT NULL DEFAULT false,
    ADD COLUMN must_change_password boolean NOT NULL DEFAULT false;

-- Partial index — superadmin queries are rare and only care about
-- live, non-deleted superadmins.
CREATE INDEX users_superadmin_idx
    ON users (is_superadmin)
    WHERE is_superadmin AND deleted_at IS NULL;

-- ---------------------------------------------------------------------------
-- platform_settings (single-row config)
-- ---------------------------------------------------------------------------
-- Enforce "exactly one row" via PK + CHECK so any code path can safely
-- `SELECT … WHERE id = 1` without worrying about duplicates.
CREATE TABLE platform_settings (
    id                smallint     PRIMARY KEY CHECK (id = 1),
    open_registration boolean      NOT NULL DEFAULT false,
    updated_at        timestamptz  NOT NULL DEFAULT now(),
    updated_by        uuid         REFERENCES users(id) ON DELETE SET NULL
);

INSERT INTO platform_settings (id) VALUES (1);

-- ---------------------------------------------------------------------------
-- platform_invitations
-- ---------------------------------------------------------------------------
-- Mirrors the per-project `invitations` table from V003 in shape and
-- conventions:
--   * raw 256-bit CSPRNG token sent to the invitee out-of-band
--   * SHA-256 hex of the token stored at rest (`token_hash char(64)`)
--   * single-use enforced atomically via `accepted_at IS NULL` check on the
--     consuming UPDATE
--
-- `role` controls what `is_superadmin` will be set to when the invitee
-- registers — kept as `varchar` (not enum) so future roles can be added
-- without a migration.
CREATE TABLE platform_invitations (
    id           uuid         PRIMARY KEY DEFAULT uuidv7(),
    email        text         NOT NULL,
    role         varchar(16)  NOT NULL DEFAULT 'user'
                              CHECK (role IN ('user', 'superadmin')),
    token_hash   char(64)     NOT NULL UNIQUE,
    invited_by   uuid         REFERENCES users(id) ON DELETE SET NULL,
    expires_at   timestamptz  NOT NULL,
    accepted_at  timestamptz,
    created_at   timestamptz  NOT NULL DEFAULT now()
);

-- Looking up pending invites by email (lowercased) is the hot path during
-- the admin "do they already have an open invite?" check.
CREATE INDEX platform_invitations_email_idx
    ON platform_invitations (lower(email))
    WHERE accepted_at IS NULL;
