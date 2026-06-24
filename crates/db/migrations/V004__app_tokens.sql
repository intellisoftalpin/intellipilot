-- ===========================================================================
-- App tokens (machine API access) + the INTELLIBOT system actor.
--
-- A superadmin mints long-lived "app tokens" scoped to a set of projects and a
-- set of permissions. The raw secret (prefix `ipat_`) is shown exactly once at
-- creation; only its SHA-256 hex digest is stored, so a database leak never
-- exposes usable tokens. A token authenticates as the synthetic INTELLIBOT
-- user, so issues / comments / etc. created via a token are attributed to
-- INTELLIBOT rather than to a real person.
-- ===========================================================================

-- The INTELLIBOT system user. The id is fixed and mirrored by
-- `intellipilot_core::app_token::INTELLIBOT_USER_ID`. It cannot log in
-- (no password, auth_source='system') and is never a superadmin.
INSERT INTO users (id, email, username, full_name, is_active, is_superadmin, auth_source)
VALUES (
    'b0700000-0000-7000-8000-000000000000',
    'intellibot@system.local',
    'INTELLIBOT',
    'INTELLIBOT',
    true,
    false,
    'system'
);

CREATE TABLE app_tokens (
    id           uuid          PRIMARY KEY DEFAULT uuidv7(),
    name         varchar(128)  NOT NULL,
    -- SHA-256 hex digest of the raw `ipat_…` secret. The secret is never stored.
    token_hash   text          NOT NULL UNIQUE,
    -- Display hints used to identify the token after creation (the secret is
    -- gone): the leading `ipat_xxxxxx` and the last 4 chars.
    prefix       varchar(20)   NOT NULL,
    last4        varchar(4)    NOT NULL,
    -- Granted permissions as wire strings (e.g. 'issue.create'), JSONB array.
    permissions  jsonb         NOT NULL DEFAULT '[]'::jsonb,
    created_by   uuid          REFERENCES users(id) ON DELETE SET NULL,
    expires_at   timestamptz,
    revoked_at   timestamptz,
    last_used_at timestamptz,
    created_at   timestamptz   NOT NULL DEFAULT now()
);

-- Project scope: a token may only act inside these projects. FK cascade keeps
-- the scope consistent when a project is deleted.
CREATE TABLE app_token_projects (
    token_id   uuid NOT NULL REFERENCES app_tokens(id) ON DELETE CASCADE,
    project_id uuid NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    PRIMARY KEY (token_id, project_id)
);
CREATE INDEX app_token_projects_project_idx ON app_token_projects (project_id);
