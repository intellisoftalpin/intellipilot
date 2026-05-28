-- Phase 1: Identity & Sessions schema.
--
-- All IDs are UUIDv7 (sortable, native in Postgres 18 via uuidv7()).
-- All timestamps are `timestamptz` in UTC.

-- ---------------------------------------------------------------------------
-- users
-- ---------------------------------------------------------------------------
-- Email is stored already normalized (trimmed + lowercased) by the
-- application, so a plain unique text column gives case-insensitive
-- uniqueness without the citext extension (which maps awkwardly through
-- tokio-postgres' type system).
CREATE TABLE users (
    id                  uuid                PRIMARY KEY DEFAULT uuidv7(),
    email               text                NOT NULL UNIQUE,
    username            varchar(64)         NOT NULL UNIQUE,
    full_name           text                NOT NULL DEFAULT '',
    -- Argon2id-encoded password hash, e.g. "$argon2id$v=19$m=65536,t=3,p=4$..."
    -- Nullable to allow passkey-only users in Phase 2.
    password_hash       text,
    lang                varchar(8)          NOT NULL DEFAULT 'en',
    timezone            varchar(64)         NOT NULL DEFAULT 'UTC',
    is_active           boolean             NOT NULL DEFAULT true,
    -- GDPR erase: soft-delete with 30-day grace before hard purge.
    deleted_at          timestamptz,
    deleted_grace_until timestamptz,
    created_at          timestamptz         NOT NULL DEFAULT now(),
    updated_at          timestamptz         NOT NULL DEFAULT now()
);

CREATE INDEX users_active_idx ON users (is_active) WHERE deleted_at IS NULL;

-- Touch updated_at on every UPDATE.
CREATE OR REPLACE FUNCTION set_updated_at() RETURNS trigger AS $$
BEGIN
    NEW.updated_at := now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER users_set_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- ---------------------------------------------------------------------------
-- refresh_token_families
-- ---------------------------------------------------------------------------
-- A family represents one logical "session" — a chain of rotating refresh
-- tokens. Replaying any used token in a family revokes the whole family
-- (reuse detection).
CREATE TABLE refresh_token_families (
    id              uuid            PRIMARY KEY DEFAULT uuidv7(),
    user_id         uuid            NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    user_agent      text            NOT NULL DEFAULT '',
    ip              inet,
    created_at      timestamptz     NOT NULL DEFAULT now(),
    revoked_at      timestamptz,
    revoked_reason  text
);

CREATE INDEX refresh_token_families_user_idx
    ON refresh_token_families (user_id)
    WHERE revoked_at IS NULL;

-- ---------------------------------------------------------------------------
-- refresh_tokens
-- ---------------------------------------------------------------------------
-- The opaque refresh token (raw 256-bit random) is hashed with SHA-256 at
-- rest. On every use, a new token is issued and the old row's `used_at` is
-- set; `parent_id` links the chain.
CREATE TABLE refresh_tokens (
    id              uuid            PRIMARY KEY DEFAULT uuidv7(),
    family_id       uuid            NOT NULL REFERENCES refresh_token_families(id) ON DELETE CASCADE,
    -- 32-byte sha256 in hex (64 chars)
    token_hash      char(64)        NOT NULL UNIQUE,
    parent_id       uuid            REFERENCES refresh_tokens(id) ON DELETE SET NULL,
    expires_at      timestamptz     NOT NULL,
    used_at         timestamptz,
    created_at      timestamptz     NOT NULL DEFAULT now()
);

CREATE INDEX refresh_tokens_family_idx ON refresh_tokens (family_id);
CREATE INDEX refresh_tokens_expiry_idx ON refresh_tokens (expires_at)
    WHERE used_at IS NULL;

-- ---------------------------------------------------------------------------
-- audit_log
-- ---------------------------------------------------------------------------
-- Append-only. Separate from history (which lives in domain tables per Phase
-- 5). Captures security-relevant events: auth, permission changes, deletes.
CREATE TABLE audit_log (
    id          uuid            PRIMARY KEY DEFAULT uuidv7(),
    actor_id    uuid            REFERENCES users(id) ON DELETE SET NULL,
    action      varchar(64)     NOT NULL,
    target_type varchar(32),
    target_id   uuid,
    ip          inet,
    user_agent  text,
    metadata    jsonb           NOT NULL DEFAULT '{}'::jsonb,
    created_at  timestamptz     NOT NULL DEFAULT now()
);

CREATE INDEX audit_log_actor_idx ON audit_log (actor_id, created_at DESC);
CREATE INDEX audit_log_action_idx ON audit_log (action, created_at DESC);

-- ---------------------------------------------------------------------------
-- password_reset_tokens
-- ---------------------------------------------------------------------------
CREATE TABLE password_reset_tokens (
    id          uuid            PRIMARY KEY DEFAULT uuidv7(),
    user_id     uuid            NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash  char(64)        NOT NULL UNIQUE,
    expires_at  timestamptz     NOT NULL,
    used_at     timestamptz,
    created_at  timestamptz     NOT NULL DEFAULT now()
);

CREATE INDEX password_reset_tokens_user_idx ON password_reset_tokens (user_id)
    WHERE used_at IS NULL;

-- ---------------------------------------------------------------------------
-- login_attempts (progressive lockout)
-- ---------------------------------------------------------------------------
-- Tracks recent failed login attempts per (ip, identifier). Used to compute
-- progressive delay. Rows older than 1 hour are pruned by a background sweep.
CREATE TABLE login_attempts (
    id              uuid            PRIMARY KEY DEFAULT uuidv7(),
    -- Hashed identifier (sha256 of email/username) to avoid storing PII.
    identifier_hash char(64)        NOT NULL,
    ip              inet            NOT NULL,
    succeeded       boolean         NOT NULL,
    created_at      timestamptz     NOT NULL DEFAULT now()
);

CREATE INDEX login_attempts_ip_idx ON login_attempts (ip, created_at DESC);
CREATE INDEX login_attempts_identifier_idx
    ON login_attempts (identifier_hash, created_at DESC);
