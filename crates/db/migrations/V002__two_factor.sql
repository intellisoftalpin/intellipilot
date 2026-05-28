-- Phase 2: Strong AuthN — TOTP, passkeys (WebAuthn), recovery codes.

-- ---------------------------------------------------------------------------
-- users: TOTP columns
-- ---------------------------------------------------------------------------
-- Secret is stored encrypted (ChaCha20-Poly1305, key derived from the server
-- pepper). `totp_confirmed_at` is set only after the user proves possession
-- with a valid code, at which point TOTP counts as an active 2FA factor.
ALTER TABLE users
    ADD COLUMN totp_secret_enc   bytea,
    ADD COLUMN totp_confirmed_at timestamptz;

-- ---------------------------------------------------------------------------
-- webauthn_credentials (passkeys)
-- ---------------------------------------------------------------------------
CREATE TABLE webauthn_credentials (
    id              uuid            PRIMARY KEY DEFAULT uuidv7(),
    user_id         uuid            NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    -- Raw credential id (bytes) for uniqueness + lookup.
    credential_id   bytea           NOT NULL UNIQUE,
    -- Serialized webauthn-rs `Passkey` (includes public key + sign count).
    passkey         jsonb           NOT NULL,
    nickname        varchar(64)     NOT NULL DEFAULT '',
    -- Last observed authenticator signature counter (cloning detection).
    sign_count      bigint          NOT NULL DEFAULT 0,
    backup_eligible boolean         NOT NULL DEFAULT false,
    backup_state    boolean         NOT NULL DEFAULT false,
    created_at      timestamptz     NOT NULL DEFAULT now(),
    last_used_at    timestamptz
);

CREATE INDEX webauthn_credentials_user_idx ON webauthn_credentials (user_id);

-- ---------------------------------------------------------------------------
-- webauthn_states
-- ---------------------------------------------------------------------------
-- Short-lived server-side storage of the in-progress ceremony state between
-- the `start` and `finish` calls. Keyed by a random state id handed to the
-- client. Rows expire after a few minutes.
CREATE TABLE webauthn_states (
    id          uuid            PRIMARY KEY DEFAULT uuidv7(),
    user_id     uuid            REFERENCES users(id) ON DELETE CASCADE,
    -- 'register' | 'authenticate'
    kind        varchar(16)     NOT NULL,
    state       jsonb           NOT NULL,
    expires_at  timestamptz     NOT NULL,
    created_at  timestamptz     NOT NULL DEFAULT now()
);

CREATE INDEX webauthn_states_expiry_idx ON webauthn_states (expires_at);

-- ---------------------------------------------------------------------------
-- recovery_codes
-- ---------------------------------------------------------------------------
-- 10 single-use codes generated at 2FA enrollment. Stored argon2id-hashed;
-- the plaintext is shown to the user exactly once.
CREATE TABLE recovery_codes (
    id          uuid            PRIMARY KEY DEFAULT uuidv7(),
    user_id     uuid            NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash   text            NOT NULL,
    used_at     timestamptz,
    created_at  timestamptz     NOT NULL DEFAULT now()
);

CREATE INDEX recovery_codes_user_idx ON recovery_codes (user_id) WHERE used_at IS NULL;
