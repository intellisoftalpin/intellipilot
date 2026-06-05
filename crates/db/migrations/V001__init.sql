-- IntelliPilot consolidated schema (from-scratch single migration).
--
-- Supersedes the former V001..V011 series. The backlog model is the unified
-- Jira-style one: epics stay a separate table; user_stories + tasks + issues
-- are merged into a single `issues` table where the *type* (Story/Task/Bug)
-- is a per-project `issue_type` taxonomy item, sub-tasks are expressed via a
-- self-referencing `parent_id`, and an optional `epic_id` groups issues under
-- an epic.
--
-- All IDs are UUIDv7 (sortable, native in Postgres 18 via uuidv7()).
-- All timestamps are `timestamptz` in UTC.

CREATE EXTENSION IF NOT EXISTS pg_trgm WITH SCHEMA public;

-- ===========================================================================
-- shared trigger helpers
-- ===========================================================================
CREATE FUNCTION set_updated_at() RETURNS trigger AS $$
BEGIN
    NEW.updated_at := now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE FUNCTION set_modified_at() RETURNS trigger AS $$
BEGIN
    NEW.modified_at := now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- ===========================================================================
-- identity & sessions
-- ===========================================================================
CREATE TABLE users (
    id                   uuid                PRIMARY KEY DEFAULT uuidv7(),
    email                text                NOT NULL UNIQUE,
    username             varchar(64)         NOT NULL UNIQUE,
    full_name            text                NOT NULL DEFAULT '',
    -- Argon2id-encoded password hash. Nullable to allow passkey-only users.
    password_hash        text,
    lang                 varchar(8)          NOT NULL DEFAULT 'en',
    timezone             varchar(64)         NOT NULL DEFAULT 'UTC',
    is_active            boolean             NOT NULL DEFAULT true,
    -- TOTP: secret encrypted (ChaCha20-Poly1305, key from server pepper).
    totp_secret_enc      bytea,
    totp_confirmed_at    timestamptz,
    -- Platform-wide admin flag + forced first-login password rotation.
    is_superadmin        boolean             NOT NULL DEFAULT false,
    must_change_password boolean             NOT NULL DEFAULT false,
    -- GDPR erase: soft-delete with grace before hard purge.
    deleted_at           timestamptz,
    deleted_grace_until  timestamptz,
    created_at           timestamptz         NOT NULL DEFAULT now(),
    updated_at           timestamptz         NOT NULL DEFAULT now()
);
CREATE INDEX users_active_idx ON users (is_active) WHERE deleted_at IS NULL;
CREATE INDEX users_superadmin_idx ON users (is_superadmin)
    WHERE is_superadmin AND deleted_at IS NULL;
CREATE TRIGGER users_set_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

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
    ON refresh_token_families (user_id) WHERE revoked_at IS NULL;

CREATE TABLE refresh_tokens (
    id              uuid            PRIMARY KEY DEFAULT uuidv7(),
    family_id       uuid            NOT NULL REFERENCES refresh_token_families(id) ON DELETE CASCADE,
    token_hash      char(64)        NOT NULL UNIQUE,
    parent_id       uuid            REFERENCES refresh_tokens(id) ON DELETE SET NULL,
    expires_at      timestamptz     NOT NULL,
    used_at         timestamptz,
    created_at      timestamptz     NOT NULL DEFAULT now()
);
CREATE INDEX refresh_tokens_family_idx ON refresh_tokens (family_id);
CREATE INDEX refresh_tokens_expiry_idx ON refresh_tokens (expires_at) WHERE used_at IS NULL;

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

CREATE TABLE login_attempts (
    id              uuid            PRIMARY KEY DEFAULT uuidv7(),
    identifier_hash char(64)        NOT NULL,
    ip              inet            NOT NULL,
    succeeded       boolean         NOT NULL,
    created_at      timestamptz     NOT NULL DEFAULT now()
);
CREATE INDEX login_attempts_ip_idx ON login_attempts (ip, created_at DESC);
CREATE INDEX login_attempts_identifier_idx ON login_attempts (identifier_hash, created_at DESC);

CREATE TABLE webauthn_credentials (
    id              uuid            PRIMARY KEY DEFAULT uuidv7(),
    user_id         uuid            NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id   bytea           NOT NULL UNIQUE,
    passkey         jsonb           NOT NULL,
    nickname        varchar(64)     NOT NULL DEFAULT '',
    sign_count      bigint          NOT NULL DEFAULT 0,
    backup_eligible boolean         NOT NULL DEFAULT false,
    backup_state    boolean         NOT NULL DEFAULT false,
    created_at      timestamptz     NOT NULL DEFAULT now(),
    last_used_at    timestamptz
);
CREATE INDEX webauthn_credentials_user_idx ON webauthn_credentials (user_id);

CREATE TABLE webauthn_states (
    id          uuid            PRIMARY KEY DEFAULT uuidv7(),
    user_id     uuid            REFERENCES users(id) ON DELETE CASCADE,
    kind        varchar(16)     NOT NULL,
    state       jsonb           NOT NULL,
    expires_at  timestamptz     NOT NULL,
    created_at  timestamptz     NOT NULL DEFAULT now()
);
CREATE INDEX webauthn_states_expiry_idx ON webauthn_states (expires_at);

CREATE TABLE recovery_codes (
    id          uuid            PRIMARY KEY DEFAULT uuidv7(),
    user_id     uuid            NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash   text            NOT NULL,
    used_at     timestamptz,
    created_at  timestamptz     NOT NULL DEFAULT now()
);
CREATE INDEX recovery_codes_user_idx ON recovery_codes (user_id) WHERE used_at IS NULL;

-- ===========================================================================
-- projects, roles, memberships, invitations
-- ===========================================================================
CREATE TABLE projects (
    id              uuid            PRIMARY KEY DEFAULT uuidv7(),
    slug            text            NOT NULL UNIQUE,
    name            text            NOT NULL,
    description     text            NOT NULL DEFAULT '',
    owner_id        uuid            NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
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
    FOR EACH ROW EXECUTE FUNCTION set_modified_at();

CREATE TABLE roles (
    id           uuid           PRIMARY KEY DEFAULT uuidv7(),
    project_id   uuid           NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    slug         varchar(64)    NOT NULL,
    name         text           NOT NULL,
    "order"      integer        NOT NULL DEFAULT 0,
    is_admin     boolean        NOT NULL DEFAULT false,
    permissions  jsonb          NOT NULL DEFAULT '[]'::jsonb,
    created_at   timestamptz    NOT NULL DEFAULT now(),
    UNIQUE (project_id, slug)
);
CREATE INDEX roles_project_idx ON roles (project_id);

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

-- ===========================================================================
-- taxonomy (per-project statuses, issue types, priorities, severities, points)
-- ===========================================================================
CREATE TABLE taxonomy_items (
    id          uuid            PRIMARY KEY DEFAULT uuidv7(),
    project_id  uuid            NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    -- 'epic_status' | 'issue_status' | 'issue_type'
    -- | 'priority' | 'severity' | 'point'
    kind        varchar(16)     NOT NULL,
    name        text            NOT NULL,
    slug        varchar(64)     NOT NULL,
    color       varchar(16)     NOT NULL DEFAULT '',
    "order"     double precision NOT NULL DEFAULT 1.0,
    is_closed   boolean,
    value       double precision,
    created_at  timestamptz     NOT NULL DEFAULT now(),
    UNIQUE (project_id, kind, slug)
);
CREATE INDEX taxonomy_items_project_kind_idx ON taxonomy_items (project_id, kind, "order");

-- ===========================================================================
-- milestones (sprints) — created before issues (issues.milestone_id FK)
-- ===========================================================================
CREATE TABLE milestones (
    id          uuid             PRIMARY KEY DEFAULT uuidv7(),
    project_id  uuid             NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name        text             NOT NULL,
    slug        varchar(100)     NOT NULL,
    start_date  date,
    end_date    date,
    closed      boolean          NOT NULL DEFAULT false,
    closed_at   timestamptz,
    "order"     double precision NOT NULL DEFAULT 1.0,
    version     integer          NOT NULL DEFAULT 1,
    created_at  timestamptz      NOT NULL DEFAULT now(),
    modified_at timestamptz      NOT NULL DEFAULT now(),
    deleted_at  timestamptz,
    UNIQUE (project_id, slug)
);
CREATE INDEX milestones_project_idx ON milestones (project_id) WHERE deleted_at IS NULL;
CREATE TRIGGER milestones_set_modified_at BEFORE UPDATE ON milestones
    FOR EACH ROW EXECUTE FUNCTION set_modified_at();

-- ===========================================================================
-- backlog: shared ref counter, epics, unified issues
-- ===========================================================================
CREATE TABLE project_ref_counters (
    project_id  uuid    PRIMARY KEY REFERENCES projects(id) ON DELETE CASCADE,
    last_ref    bigint  NOT NULL DEFAULT 0
);

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

-- Unified work item. type_id (taxonomy 'issue_type') distinguishes
-- Story/Task/Bug/custom; parent_id nests sub-tasks; epic_id groups under an
-- epic; milestone_id assigns to a sprint; points_id holds the estimate.
CREATE TABLE issues (
    id                  uuid             PRIMARY KEY DEFAULT uuidv7(),
    project_id          uuid             NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    ref                 bigint           NOT NULL,
    subject             text             NOT NULL,
    description         text             NOT NULL DEFAULT '',
    status_id           uuid             REFERENCES taxonomy_items(id) ON DELETE SET NULL,
    type_id             uuid             REFERENCES taxonomy_items(id) ON DELETE SET NULL,
    priority_id         uuid             REFERENCES taxonomy_items(id) ON DELETE SET NULL,
    severity_id         uuid             REFERENCES taxonomy_items(id) ON DELETE SET NULL,
    points_id           uuid             REFERENCES taxonomy_items(id) ON DELETE SET NULL,
    epic_id             uuid             REFERENCES epics(id) ON DELETE SET NULL,
    parent_id           uuid             REFERENCES issues(id) ON DELETE SET NULL,
    milestone_id        uuid             REFERENCES milestones(id) ON DELETE SET NULL,
    owner_id            uuid             REFERENCES users(id) ON DELETE SET NULL,
    assigned_to         uuid             REFERENCES users(id) ON DELETE SET NULL,
    "order"             double precision NOT NULL DEFAULT 1.0,
    version             integer          NOT NULL DEFAULT 1,
    created_at          timestamptz      NOT NULL DEFAULT now(),
    modified_at         timestamptz      NOT NULL DEFAULT now(),
    deleted_at          timestamptz,
    deleted_grace_until timestamptz,
    UNIQUE (project_id, ref)
);
CREATE INDEX issues_project_idx ON issues (project_id) WHERE deleted_at IS NULL;
CREATE INDEX issues_epic_idx ON issues (epic_id) WHERE deleted_at IS NULL;
CREATE INDEX issues_parent_idx ON issues (parent_id) WHERE deleted_at IS NULL;
CREATE INDEX issues_milestone_idx ON issues (milestone_id) WHERE deleted_at IS NULL;
CREATE TRIGGER issues_set_modified_at BEFORE UPDATE ON issues
    FOR EACH ROW EXECUTE FUNCTION set_modified_at();

-- ===========================================================================
-- comments + history (polymorphic over 'epic' | 'issue')
-- ===========================================================================
CREATE TABLE comments (
    id          uuid            PRIMARY KEY DEFAULT uuidv7(),
    project_id  uuid            NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    target_type varchar(16)     NOT NULL,  -- 'epic' | 'issue'
    target_id   uuid            NOT NULL,
    author_id   uuid            REFERENCES users(id) ON DELETE SET NULL,
    body        text            NOT NULL,
    body_html   text            NOT NULL DEFAULT '',
    edited_at   timestamptz,
    created_at  timestamptz     NOT NULL DEFAULT now(),
    deleted_at  timestamptz
);
CREATE INDEX comments_target_idx ON comments (target_type, target_id) WHERE deleted_at IS NULL;

CREATE TABLE history_entries (
    id          uuid            PRIMARY KEY DEFAULT uuidv7(),
    project_id  uuid            NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    target_type varchar(16)     NOT NULL,  -- 'epic' | 'issue'
    target_id   uuid            NOT NULL,
    actor_id    uuid            REFERENCES users(id) ON DELETE SET NULL,
    diff        jsonb           NOT NULL DEFAULT '{}'::jsonb,
    created_at  timestamptz     NOT NULL DEFAULT now()
);
CREATE INDEX history_target_idx ON history_entries (target_type, target_id, created_at);

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

-- ===========================================================================
-- labels & components (apply to any issue)
-- ===========================================================================
CREATE TABLE labels (
    id          uuid            PRIMARY KEY DEFAULT uuidv7(),
    project_id  uuid            NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name        varchar(64)     NOT NULL,
    color       varchar(16)     NOT NULL DEFAULT '',
    created_at  timestamptz     NOT NULL DEFAULT now(),
    UNIQUE (project_id, name)
);
CREATE INDEX labels_project_idx ON labels (project_id);

CREATE TABLE components (
    id              uuid            PRIMARY KEY DEFAULT uuidv7(),
    project_id      uuid            NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name            varchar(64)     NOT NULL,
    color           varchar(16)     NOT NULL DEFAULT '',
    git_repository  text,
    created_at      timestamptz     NOT NULL DEFAULT now(),
    UNIQUE (project_id, name)
);
CREATE INDEX components_project_idx ON components (project_id);

CREATE TABLE issue_labels (
    issue_id  uuid NOT NULL REFERENCES issues(id) ON DELETE CASCADE,
    label_id  uuid NOT NULL REFERENCES labels(id) ON DELETE CASCADE,
    PRIMARY KEY (issue_id, label_id)
);

CREATE TABLE issue_components (
    issue_id      uuid NOT NULL REFERENCES issues(id) ON DELETE CASCADE,
    component_id  uuid NOT NULL REFERENCES components(id) ON DELETE CASCADE,
    PRIMARY KEY (issue_id, component_id)
);

-- ===========================================================================
-- attachments (polymorphic over 'epic' | 'issue' | 'wiki')
-- ===========================================================================
CREATE TABLE attachments (
    id           uuid        PRIMARY KEY DEFAULT uuidv7(),
    project_id   uuid        NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    target_type  varchar(16) NOT NULL,  -- 'epic' | 'issue' | 'wiki'
    target_id    uuid        NOT NULL,
    uploader_id  uuid        REFERENCES users(id) ON DELETE SET NULL,
    filename     text        NOT NULL,
    content_type varchar(255) NOT NULL,
    size_bytes   bigint      NOT NULL,
    sha256       char(64)    NOT NULL,
    storage_key  text        NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    deleted_at   timestamptz
);
CREATE INDEX attachments_target_idx ON attachments (target_type, target_id) WHERE deleted_at IS NULL;
CREATE INDEX attachments_gc_idx ON attachments (deleted_at) WHERE deleted_at IS NOT NULL;

-- ===========================================================================
-- wiki
-- ===========================================================================
CREATE TABLE wiki_pages (
    id          uuid         PRIMARY KEY DEFAULT uuidv7(),
    project_id  uuid         NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    slug        varchar(200) NOT NULL,
    title       text         NOT NULL,
    body        text         NOT NULL DEFAULT '',
    body_html   text         NOT NULL DEFAULT '',
    version     integer      NOT NULL DEFAULT 1,
    editor_id   uuid         REFERENCES users(id) ON DELETE SET NULL,
    created_at  timestamptz  NOT NULL DEFAULT now(),
    modified_at timestamptz  NOT NULL DEFAULT now(),
    deleted_at  timestamptz,
    UNIQUE (project_id, slug)
);
CREATE INDEX wiki_pages_project_idx ON wiki_pages (project_id) WHERE deleted_at IS NULL;
CREATE TRIGGER wiki_pages_set_modified_at BEFORE UPDATE ON wiki_pages
    FOR EACH ROW EXECUTE FUNCTION set_modified_at();

CREATE TABLE wiki_page_revisions (
    id         uuid        PRIMARY KEY DEFAULT uuidv7(),
    page_id    uuid        NOT NULL REFERENCES wiki_pages(id) ON DELETE CASCADE,
    rev        integer     NOT NULL,
    title      text        NOT NULL,
    body       text        NOT NULL,
    editor_id  uuid        REFERENCES users(id) ON DELETE SET NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (page_id, rev)
);
CREATE INDEX wiki_revisions_page_idx ON wiki_page_revisions (page_id, rev);

-- ===========================================================================
-- unified full-text search, maintained by triggers
-- ===========================================================================
CREATE TABLE search_index (
    entity_type varchar(16) NOT NULL,  -- 'epic' | 'issue' | 'wiki' | 'comment'
    entity_id   uuid        NOT NULL,
    project_id  uuid        NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    ref         bigint,
    title       text        NOT NULL DEFAULT '',
    body        text        NOT NULL DEFAULT '',
    tsv         tsvector,
    updated_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (entity_type, entity_id)
);
CREATE INDEX search_tsv_idx ON search_index USING GIN (tsv);
CREATE INDEX search_trgm_idx ON search_index USING GIN ((title || ' ' || body) gin_trgm_ops);
CREATE INDEX search_project_idx ON search_index (project_id);

CREATE FUNCTION search_index_tsv() RETURNS trigger AS $$
BEGIN
    NEW.tsv := setweight(to_tsvector('english', coalesce(NEW.title, '')), 'A')
            || setweight(to_tsvector('english', coalesce(NEW.body, '')), 'B');
    NEW.updated_at := now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER search_index_tsv_trg BEFORE INSERT OR UPDATE ON search_index
    FOR EACH ROW EXECUTE FUNCTION search_index_tsv();

-- Work items (epic/issue): subject/description + ref. Type passed as arg.
CREATE FUNCTION sync_search_workitem() RETURNS trigger AS $$
DECLARE etype text := TG_ARGV[0];
BEGIN
    IF TG_OP = 'DELETE' THEN
        DELETE FROM search_index WHERE entity_type = etype AND entity_id = OLD.id;
        RETURN OLD;
    END IF;
    IF NEW.deleted_at IS NOT NULL THEN
        DELETE FROM search_index WHERE entity_type = etype AND entity_id = NEW.id;
        RETURN NEW;
    END IF;
    INSERT INTO search_index (entity_type, entity_id, project_id, ref, title, body)
    VALUES (etype, NEW.id, NEW.project_id, NEW.ref, NEW.subject, NEW.description)
    ON CONFLICT (entity_type, entity_id) DO UPDATE
        SET project_id = EXCLUDED.project_id, ref = EXCLUDED.ref,
            title = EXCLUDED.title, body = EXCLUDED.body;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER epics_search AFTER INSERT OR UPDATE OR DELETE ON epics
    FOR EACH ROW EXECUTE FUNCTION sync_search_workitem('epic');
CREATE TRIGGER issues_search AFTER INSERT OR UPDATE OR DELETE ON issues
    FOR EACH ROW EXECUTE FUNCTION sync_search_workitem('issue');

CREATE FUNCTION sync_search_wiki() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        DELETE FROM search_index WHERE entity_type = 'wiki' AND entity_id = OLD.id;
        RETURN OLD;
    END IF;
    IF NEW.deleted_at IS NOT NULL THEN
        DELETE FROM search_index WHERE entity_type = 'wiki' AND entity_id = NEW.id;
        RETURN NEW;
    END IF;
    INSERT INTO search_index (entity_type, entity_id, project_id, ref, title, body)
    VALUES ('wiki', NEW.id, NEW.project_id, NULL, NEW.title, NEW.body)
    ON CONFLICT (entity_type, entity_id) DO UPDATE
        SET project_id = EXCLUDED.project_id, title = EXCLUDED.title, body = EXCLUDED.body;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER wiki_pages_search AFTER INSERT OR UPDATE OR DELETE ON wiki_pages
    FOR EACH ROW EXECUTE FUNCTION sync_search_wiki();

CREATE FUNCTION sync_search_comment() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        DELETE FROM search_index WHERE entity_type = 'comment' AND entity_id = OLD.id;
        RETURN OLD;
    END IF;
    IF NEW.deleted_at IS NOT NULL THEN
        DELETE FROM search_index WHERE entity_type = 'comment' AND entity_id = NEW.id;
        RETURN NEW;
    END IF;
    INSERT INTO search_index (entity_type, entity_id, project_id, ref, title, body)
    VALUES ('comment', NEW.id, NEW.project_id, NULL, '', NEW.body)
    ON CONFLICT (entity_type, entity_id) DO UPDATE
        SET project_id = EXCLUDED.project_id, body = EXCLUDED.body;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER comments_search AFTER INSERT OR UPDATE OR DELETE ON comments
    FOR EACH ROW EXECUTE FUNCTION sync_search_comment();

-- ===========================================================================
-- platform admin: superadmin settings + invitations
-- ===========================================================================
CREATE TABLE platform_settings (
    id                smallint     PRIMARY KEY CHECK (id = 1),
    open_registration boolean      NOT NULL DEFAULT false,
    updated_at        timestamptz  NOT NULL DEFAULT now(),
    updated_by        uuid         REFERENCES users(id) ON DELETE SET NULL
);
INSERT INTO platform_settings (id) VALUES (1);

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
CREATE INDEX platform_invitations_email_idx
    ON platform_invitations (lower(email)) WHERE accepted_at IS NULL;
