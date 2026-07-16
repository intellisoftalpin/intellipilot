-- ===========================================================================
-- Personal app tokens (one per user).
--
-- A personal token is a long-lived credential a user mints for themself
-- (MCP clients, scripts, CLI tools). Unlike admin app tokens (V004), which
-- authenticate as the synthetic INTELLIBOT actor with an explicit permission
-- grant, a personal token authenticates AS its owning user: every right and
-- permission is derived from that user, and all actions are attributed to
-- them.
--
-- One token per user (UNIQUE user_id). Reset swaps the credential in place;
-- disable toggles disabled_at; delete removes the row. Only the SHA-256 hex
-- digest of the raw `ippt_…` secret is stored — the raw value is shown to the
-- user exactly once, at creation/reset time.
-- ===========================================================================

CREATE TABLE personal_app_tokens (
    id           uuid        PRIMARY KEY DEFAULT uuidv7(),
    user_id      uuid        NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
    token_hash   text        NOT NULL UNIQUE,
    prefix       varchar(20) NOT NULL,
    last4        varchar(4)  NOT NULL,
    disabled_at  timestamptz,
    last_used_at timestamptz,
    created_at   timestamptz NOT NULL DEFAULT now()
);
