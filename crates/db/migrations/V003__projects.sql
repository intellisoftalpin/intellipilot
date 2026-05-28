-- Phase 3: Projects, Roles, Memberships, Invitations.

-- ---------------------------------------------------------------------------
-- projects
-- ---------------------------------------------------------------------------
CREATE TABLE projects (
    id              uuid            PRIMARY KEY DEFAULT uuidv7(),
    slug            text            NOT NULL UNIQUE,
    name            text            NOT NULL,
    description     text            NOT NULL DEFAULT '',
    owner_id        uuid            NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    -- 'private' | 'internal' | 'public_readonly'
    visibility      varchar(16)     NOT NULL DEFAULT 'private',
    kanban_enabled  boolean         NOT NULL DEFAULT true,
    backlog_enabled boolean         NOT NULL DEFAULT true,
    wiki_enabled    boolean         NOT NULL DEFAULT true,
    epics_enabled   boolean         NOT NULL DEFAULT true,
    created_at      timestamptz     NOT NULL DEFAULT now(),
    modified_at     timestamptz     NOT NULL DEFAULT now(),
    deleted_at      timestamptz
);

CREATE INDEX projects_owner_idx ON projects (owner_id) WHERE deleted_at IS NULL;

CREATE TRIGGER projects_set_modified_at
    BEFORE UPDATE ON projects
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- The shared trigger function sets NEW.updated_at; projects uses modified_at,
-- so define a dedicated one. (Replace the trigger above.)
DROP TRIGGER projects_set_modified_at ON projects;

CREATE OR REPLACE FUNCTION set_modified_at() RETURNS trigger AS $$
BEGIN
    NEW.modified_at := now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER projects_set_modified_at
    BEFORE UPDATE ON projects
    FOR EACH ROW EXECUTE FUNCTION set_modified_at();

-- ---------------------------------------------------------------------------
-- roles
-- ---------------------------------------------------------------------------
CREATE TABLE roles (
    id           uuid           PRIMARY KEY DEFAULT uuidv7(),
    project_id   uuid           NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    slug         varchar(64)    NOT NULL,
    name         text           NOT NULL,
    "order"      integer        NOT NULL DEFAULT 0,
    is_admin     boolean        NOT NULL DEFAULT false,
    -- JSON array of permission strings.
    permissions  jsonb          NOT NULL DEFAULT '[]'::jsonb,
    created_at   timestamptz    NOT NULL DEFAULT now(),
    UNIQUE (project_id, slug)
);

CREATE INDEX roles_project_idx ON roles (project_id);

-- ---------------------------------------------------------------------------
-- memberships
-- ---------------------------------------------------------------------------
CREATE TABLE memberships (
    id           uuid           PRIMARY KEY DEFAULT uuidv7(),
    project_id   uuid           NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    user_id      uuid           NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id      uuid           NOT NULL REFERENCES roles(id) ON DELETE RESTRICT,
    invited_by   uuid           REFERENCES users(id) ON DELETE SET NULL,
    created_at   timestamptz    NOT NULL DEFAULT now(),
    UNIQUE (project_id, user_id)
);

CREATE INDEX memberships_project_idx ON memberships (project_id);
CREATE INDEX memberships_user_idx ON memberships (user_id);

-- ---------------------------------------------------------------------------
-- invitations
-- ---------------------------------------------------------------------------
CREATE TABLE invitations (
    id           uuid           PRIMARY KEY DEFAULT uuidv7(),
    project_id   uuid           NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    email        text           NOT NULL,
    role_id      uuid           NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    token_hash   char(64)       NOT NULL UNIQUE,
    invited_by   uuid           REFERENCES users(id) ON DELETE SET NULL,
    expires_at   timestamptz    NOT NULL,
    accepted_at  timestamptz,
    created_at   timestamptz    NOT NULL DEFAULT now()
);

CREATE INDEX invitations_project_idx ON invitations (project_id);
CREATE INDEX invitations_email_idx ON invitations (lower(email)) WHERE accepted_at IS NULL;
