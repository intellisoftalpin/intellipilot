-- Phase 5: Backlog domain — epics, user stories, tasks, issues, plus
-- comments, history, per-project ref counter, and idempotency keys.

-- ---------------------------------------------------------------------------
-- per-project reference counter (shared #N series across all entity kinds)
-- ---------------------------------------------------------------------------
CREATE TABLE project_ref_counters (
    project_id  uuid    PRIMARY KEY REFERENCES projects(id) ON DELETE CASCADE,
    last_ref    bigint  NOT NULL DEFAULT 0
);

-- ---------------------------------------------------------------------------
-- epics
-- ---------------------------------------------------------------------------
CREATE TABLE epics (
    id                  uuid            PRIMARY KEY DEFAULT uuidv7(),
    project_id          uuid            NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    ref                 bigint          NOT NULL,
    subject             text            NOT NULL,
    description         text            NOT NULL DEFAULT '',
    status_id           uuid            REFERENCES taxonomy_items(id) ON DELETE SET NULL,
    color               varchar(16)     NOT NULL DEFAULT '',
    owner_id            uuid            REFERENCES users(id) ON DELETE SET NULL,
    assigned_to         uuid            REFERENCES users(id) ON DELETE SET NULL,
    "order"             double precision NOT NULL DEFAULT 1.0,
    version             integer         NOT NULL DEFAULT 1,
    created_at          timestamptz     NOT NULL DEFAULT now(),
    modified_at         timestamptz     NOT NULL DEFAULT now(),
    deleted_at          timestamptz,
    deleted_grace_until timestamptz,
    UNIQUE (project_id, ref)
);
CREATE INDEX epics_project_idx ON epics (project_id) WHERE deleted_at IS NULL;
CREATE TRIGGER epics_set_modified_at BEFORE UPDATE ON epics
    FOR EACH ROW EXECUTE FUNCTION set_modified_at();

-- ---------------------------------------------------------------------------
-- user_stories
-- ---------------------------------------------------------------------------
CREATE TABLE user_stories (
    id                  uuid            PRIMARY KEY DEFAULT uuidv7(),
    project_id          uuid            NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    ref                 bigint          NOT NULL,
    subject             text            NOT NULL,
    description         text            NOT NULL DEFAULT '',
    status_id           uuid            REFERENCES taxonomy_items(id) ON DELETE SET NULL,
    epic_id             uuid            REFERENCES epics(id) ON DELETE SET NULL,
    owner_id            uuid            REFERENCES users(id) ON DELETE SET NULL,
    assigned_to         uuid            REFERENCES users(id) ON DELETE SET NULL,
    "order"             double precision NOT NULL DEFAULT 1.0,
    version             integer         NOT NULL DEFAULT 1,
    created_at          timestamptz     NOT NULL DEFAULT now(),
    modified_at         timestamptz     NOT NULL DEFAULT now(),
    deleted_at          timestamptz,
    deleted_grace_until timestamptz,
    UNIQUE (project_id, ref)
);
CREATE INDEX user_stories_project_idx ON user_stories (project_id) WHERE deleted_at IS NULL;
CREATE INDEX user_stories_epic_idx ON user_stories (epic_id) WHERE deleted_at IS NULL;
CREATE TRIGGER user_stories_set_modified_at BEFORE UPDATE ON user_stories
    FOR EACH ROW EXECUTE FUNCTION set_modified_at();

-- ---------------------------------------------------------------------------
-- tasks
-- ---------------------------------------------------------------------------
CREATE TABLE tasks (
    id                  uuid            PRIMARY KEY DEFAULT uuidv7(),
    project_id          uuid            NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    ref                 bigint          NOT NULL,
    subject             text            NOT NULL,
    description         text            NOT NULL DEFAULT '',
    status_id           uuid            REFERENCES taxonomy_items(id) ON DELETE SET NULL,
    user_story_id       uuid            REFERENCES user_stories(id) ON DELETE SET NULL,
    owner_id            uuid            REFERENCES users(id) ON DELETE SET NULL,
    assigned_to         uuid            REFERENCES users(id) ON DELETE SET NULL,
    "order"             double precision NOT NULL DEFAULT 1.0,
    version             integer         NOT NULL DEFAULT 1,
    created_at          timestamptz     NOT NULL DEFAULT now(),
    modified_at         timestamptz     NOT NULL DEFAULT now(),
    deleted_at          timestamptz,
    deleted_grace_until timestamptz,
    UNIQUE (project_id, ref)
);
CREATE INDEX tasks_project_idx ON tasks (project_id) WHERE deleted_at IS NULL;
CREATE INDEX tasks_us_idx ON tasks (user_story_id) WHERE deleted_at IS NULL;
CREATE TRIGGER tasks_set_modified_at BEFORE UPDATE ON tasks
    FOR EACH ROW EXECUTE FUNCTION set_modified_at();

-- ---------------------------------------------------------------------------
-- issues
-- ---------------------------------------------------------------------------
CREATE TABLE issues (
    id                  uuid            PRIMARY KEY DEFAULT uuidv7(),
    project_id          uuid            NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    ref                 bigint          NOT NULL,
    subject             text            NOT NULL,
    description         text            NOT NULL DEFAULT '',
    status_id           uuid            REFERENCES taxonomy_items(id) ON DELETE SET NULL,
    type_id             uuid            REFERENCES taxonomy_items(id) ON DELETE SET NULL,
    priority_id         uuid            REFERENCES taxonomy_items(id) ON DELETE SET NULL,
    severity_id         uuid            REFERENCES taxonomy_items(id) ON DELETE SET NULL,
    owner_id            uuid            REFERENCES users(id) ON DELETE SET NULL,
    assigned_to         uuid            REFERENCES users(id) ON DELETE SET NULL,
    version             integer         NOT NULL DEFAULT 1,
    created_at          timestamptz     NOT NULL DEFAULT now(),
    modified_at         timestamptz     NOT NULL DEFAULT now(),
    deleted_at          timestamptz,
    deleted_grace_until timestamptz,
    UNIQUE (project_id, ref)
);
CREATE INDEX issues_project_idx ON issues (project_id) WHERE deleted_at IS NULL;
CREATE TRIGGER issues_set_modified_at BEFORE UPDATE ON issues
    FOR EACH ROW EXECUTE FUNCTION set_modified_at();

-- ---------------------------------------------------------------------------
-- comments (polymorphic over entity kind)
-- ---------------------------------------------------------------------------
CREATE TABLE comments (
    id          uuid            PRIMARY KEY DEFAULT uuidv7(),
    project_id  uuid            NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    target_type varchar(16)     NOT NULL,  -- 'epic'|'user_story'|'task'|'issue'
    target_id   uuid            NOT NULL,
    author_id   uuid            REFERENCES users(id) ON DELETE SET NULL,
    body        text            NOT NULL,
    body_html   text            NOT NULL DEFAULT '',
    edited_at   timestamptz,
    created_at  timestamptz     NOT NULL DEFAULT now(),
    deleted_at  timestamptz
);
CREATE INDEX comments_target_idx ON comments (target_type, target_id) WHERE deleted_at IS NULL;

-- ---------------------------------------------------------------------------
-- history_entries (append-only field-change log per entity)
-- ---------------------------------------------------------------------------
CREATE TABLE history_entries (
    id          uuid            PRIMARY KEY DEFAULT uuidv7(),
    project_id  uuid            NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    target_type varchar(16)     NOT NULL,
    target_id   uuid            NOT NULL,
    actor_id    uuid            REFERENCES users(id) ON DELETE SET NULL,
    diff        jsonb           NOT NULL DEFAULT '{}'::jsonb,
    created_at  timestamptz     NOT NULL DEFAULT now()
);
CREATE INDEX history_target_idx ON history_entries (target_type, target_id, created_at);

-- ---------------------------------------------------------------------------
-- idempotency_keys
-- ---------------------------------------------------------------------------
CREATE TABLE idempotency_keys (
    id              uuid        PRIMARY KEY DEFAULT uuidv7(),
    idem_key        text        NOT NULL,
    user_id         uuid        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    method          varchar(8)  NOT NULL,
    path            text        NOT NULL,
    response_status integer     NOT NULL,
    response_body   jsonb       NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    expires_at      timestamptz NOT NULL,
    UNIQUE (user_id, idem_key, method, path)
);
CREATE INDEX idempotency_expiry_idx ON idempotency_keys (expires_at);
