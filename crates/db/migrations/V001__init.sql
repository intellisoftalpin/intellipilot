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
    -- Authentication source: 'local' (Argon2 password) or 'ldap' (directory).
    auth_source          text                NOT NULL DEFAULT 'local',
    -- The user's distinguished name in the directory (informational).
    ldap_dn              text,
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
    size_id             uuid             REFERENCES taxonomy_items(id) ON DELETE SET NULL,
    epic_id             uuid             REFERENCES epics(id) ON DELETE SET NULL,
    parent_id           uuid             REFERENCES issues(id) ON DELETE SET NULL,
    milestone_id        uuid             REFERENCES milestones(id) ON DELETE SET NULL,
    owner_id            uuid             REFERENCES users(id) ON DELETE SET NULL,
    assigned_to         uuid             REFERENCES users(id) ON DELETE SET NULL,
    -- Business-driver category (fixed enum, see core::backlog::IssueCategory).
    category            varchar(32),
    -- Requesting customer (FK added at end of file once `customers` exists).
    customer_id         uuid,
    start_date          date,
    due_date            date,
    -- Resolution (fixed enum) + system-managed close timestamp.
    resolution          varchar(32),
    resolved_at         timestamptz,
    -- Fix version: structured (FK added at end once `release_versions` exists)
    -- or free text. At most one is set (enforced in the API).
    release_version_id  uuid,
    release_text        varchar(100),
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
CREATE INDEX issues_due_date_idx ON issues (due_date) WHERE deleted_at IS NULL;
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
-- Git integration: per-project SSH credential vault, repositories, and
-- component<->repository links (each pinned to a branch). Underpins the future
-- "clone & analyze" feature.
-- ===========================================================================
CREATE TABLE ssh_keys (
    id               uuid         PRIMARY KEY DEFAULT uuidv7(),
    project_id       uuid         NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name             varchar(64)  NOT NULL,
    -- true = read-only deploy key; false = read/write.
    read_only        boolean      NOT NULL DEFAULT true,
    key_type         varchar(32)  NOT NULL DEFAULT 'ed25519',
    public_key       text         NOT NULL,
    -- Private key encrypted at rest (ChaCha20-Poly1305, key from server
    -- pepper). NEVER selected into API responses.
    private_key_enc  bytea        NOT NULL,
    fingerprint      text         NOT NULL,
    created_at       timestamptz  NOT NULL DEFAULT now(),
    created_by       uuid         REFERENCES users(id) ON DELETE SET NULL,
    UNIQUE (project_id, name)
);
CREATE INDEX ssh_keys_project_idx ON ssh_keys (project_id);

CREATE TABLE repositories (
    id               uuid         PRIMARY KEY DEFAULT uuidv7(),
    project_id       uuid         NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name             varchar(128) NOT NULL,
    ssh_url          text         NOT NULL,
    -- Deleting a key detaches it from its repositories (ON DELETE SET NULL):
    -- the repos remain but need a new key assigned before they are reachable.
    ssh_key_id       uuid         REFERENCES ssh_keys(id) ON DELETE SET NULL,
    default_branch   varchar(255),
    host_fingerprint text,
    created_at       timestamptz  NOT NULL DEFAULT now(),
    created_by       uuid         REFERENCES users(id) ON DELETE SET NULL,
    UNIQUE (project_id, ssh_url)
);
CREATE INDEX repositories_project_idx ON repositories (project_id);
CREATE INDEX repositories_ssh_key_idx ON repositories (ssh_key_id);

CREATE TABLE component_repositories (
    component_id   uuid         NOT NULL REFERENCES components(id) ON DELETE CASCADE,
    repository_id  uuid         NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    -- The specific branch linked (customizable; need not be the repo default).
    branch         varchar(255) NOT NULL,
    created_at     timestamptz  NOT NULL DEFAULT now(),
    PRIMARY KEY (component_id, repository_id)
);
CREATE INDEX component_repositories_repo_idx ON component_repositories (repository_id);

-- ===========================================================================
-- Customers (per-project) — who requested a feature. Linked from issues whose
-- category is 'customer_request'.
-- ===========================================================================
CREATE TABLE customers (
    id            uuid         PRIMARY KEY DEFAULT uuidv7(),
    project_id    uuid         NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name          varchar(200) NOT NULL,
    company_name  varchar(200),
    contact_email varchar(254),
    phone         varchar(64),
    notes         text,
    created_at    timestamptz  NOT NULL DEFAULT now(),
    created_by    uuid         REFERENCES users(id) ON DELETE SET NULL,
    modified_at   timestamptz  NOT NULL DEFAULT now(),
    UNIQUE (project_id, name)
);
CREATE INDEX customers_project_idx ON customers (project_id);
CREATE TRIGGER customers_set_modified_at BEFORE UPDATE ON customers
    FOR EACH ROW EXECUTE FUNCTION set_modified_at();

-- ===========================================================================
-- Releases (a named product / release line) + their versions. A version may
-- map to a git tag on a linked repository; releases may be linked to
-- components, and an issue's fix-version points at a specific version.
-- ===========================================================================
CREATE TABLE releases (
    id          uuid         PRIMARY KEY DEFAULT uuidv7(),
    project_id  uuid         NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name        varchar(128) NOT NULL,
    description text,
    created_at  timestamptz  NOT NULL DEFAULT now(),
    created_by  uuid         REFERENCES users(id) ON DELETE SET NULL,
    UNIQUE (project_id, name)
);
CREATE INDEX releases_project_idx ON releases (project_id);

CREATE TABLE release_versions (
    id            uuid             PRIMARY KEY DEFAULT uuidv7(),
    release_id    uuid             NOT NULL REFERENCES releases(id) ON DELETE CASCADE,
    version       varchar(64)      NOT NULL,
    status        varchar(16)      NOT NULL DEFAULT 'planned',
    target_date   date,
    released_at   timestamptz,
    notes         text             NOT NULL DEFAULT '',
    repository_id uuid             REFERENCES repositories(id) ON DELETE SET NULL,
    git_tag       varchar(255),
    "order"       double precision NOT NULL DEFAULT 1.0,
    created_at    timestamptz      NOT NULL DEFAULT now(),
    UNIQUE (release_id, version)
);
CREATE INDEX release_versions_release_idx ON release_versions (release_id);

CREATE TABLE component_releases (
    component_id uuid        NOT NULL REFERENCES components(id) ON DELETE CASCADE,
    release_id   uuid        NOT NULL REFERENCES releases(id) ON DELETE CASCADE,
    created_at   timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (component_id, release_id)
);
CREATE INDEX component_releases_release_idx ON component_releases (release_id);

-- ===========================================================================
-- Issue relationships + watchers
-- ===========================================================================
CREATE TABLE issue_links (
    id              uuid        PRIMARY KEY DEFAULT uuidv7(),
    project_id      uuid        NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    source_issue_id uuid        NOT NULL REFERENCES issues(id) ON DELETE CASCADE,
    target_issue_id uuid        NOT NULL REFERENCES issues(id) ON DELETE CASCADE,
    type            varchar(16) NOT NULL,  -- 'blocks' | 'relates' | 'duplicates'
    created_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (source_issue_id, target_issue_id, type),
    CHECK (source_issue_id <> target_issue_id)
);
CREATE INDEX issue_links_source_idx ON issue_links (source_issue_id);
CREATE INDEX issue_links_target_idx ON issue_links (target_issue_id);

CREATE TABLE issue_watchers (
    issue_id   uuid        NOT NULL REFERENCES issues(id) ON DELETE CASCADE,
    user_id    uuid        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (issue_id, user_id)
);

-- Deferred FKs on `issues` (targets defined above).
ALTER TABLE issues
    ADD CONSTRAINT issues_customer_fk
        FOREIGN KEY (customer_id) REFERENCES customers(id) ON DELETE SET NULL,
    ADD CONSTRAINT issues_release_version_fk
        FOREIGN KEY (release_version_id) REFERENCES release_versions(id) ON DELETE SET NULL;

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
    id                  smallint     PRIMARY KEY CHECK (id = 1),
    open_registration   boolean      NOT NULL DEFAULT false,
    -- White-label branding. NULL app_name / app_icon means "use the bundled
    -- defaults" (the "IntelliPilot" name and the app's built-in logo). app_message
    -- is an optional notice shown on the login screen.
    app_name            text,
    app_message         text,
    app_icon            bytea,
    app_icon_mime       text,
    app_icon_updated_at timestamptz,
    updated_at          timestamptz  NOT NULL DEFAULT now(),
    updated_by          uuid         REFERENCES users(id) ON DELETE SET NULL
);
INSERT INTO platform_settings (id) VALUES (1);

-- Single-row LDAP / directory configuration, edited by a superadmin via the
-- admin UI. Authentication uses a direct bind as the logging-in user, so no
-- bind secret is stored here.
CREATE TABLE ldap_settings (
    id                      smallint    PRIMARY KEY CHECK (id = 1),
    -- Master switch. When true, non-superadmins must authenticate via LDAP.
    enabled                 boolean     NOT NULL DEFAULT false,
    -- e.g. ldap://dc.example.com:389
    server_url              text        NOT NULL DEFAULT '',
    -- Negotiate StartTLS after connecting (the reference's `use_ssl`).
    use_start_tls           boolean     NOT NULL DEFAULT false,
    -- Skip TLS certificate verification (lab / self-signed only).
    skip_tls_verify         boolean     NOT NULL DEFAULT false,
    -- Search base, e.g. dc=example,dc=com
    base_dn                 text        NOT NULL DEFAULT '',
    -- Appended to a bare login name lacking '@' to form a UPN, e.g. example.com
    default_domain          text        NOT NULL DEFAULT '',
    -- Bind DN template; '%s' is replaced with the (UPN-formed) identifier.
    bind_dn_format          text        NOT NULL DEFAULT '%s',
    -- User search filter; '%s' is replaced with the identifier's local part.
    user_search_filter      text        NOT NULL DEFAULT '(sAMAccountName=%s)',
    -- Group (CN or DN) whose members are granted superadmin. Empty = disabled.
    superadmin_group        text        NOT NULL DEFAULT '',
    -- Attribute names for provisioning the local user record.
    attr_email              text        NOT NULL DEFAULT 'mail',
    attr_display_name       text        NOT NULL DEFAULT 'displayName',
    attr_username           text        NOT NULL DEFAULT 'sAMAccountName',
    connection_timeout_secs integer     NOT NULL DEFAULT 10,
    -- Bind mode: 'direct' (bind as the logging-in user via bind_dn_format) or
    -- 'search' (a service account searches for the user's DN, then we bind as
    -- that DN to verify the password). 'search' suits OpenLDAP where the login
    -- identifier isn't the entry's RDN.
    bind_mode               text        NOT NULL DEFAULT 'direct',
    -- Service/bind account for 'search' mode (full DN, e.g.
    -- cn=svc-search,dc=example,dc=com).
    service_bind_dn         text        NOT NULL DEFAULT '',
    -- Service account password (write-only; never returned by the API).
    service_bind_password   text        NOT NULL DEFAULT '',
    -- Base DN for the user search in 'search' mode. Empty falls back to base_dn.
    user_search_base        text        NOT NULL DEFAULT '',
    -- Base DN for the reverse group-membership search. Empty disables it.
    group_search_base       text        NOT NULL DEFAULT '',
    -- Reverse group search filter; '%s' is replaced with the user's DN.
    group_search_filter     text        NOT NULL DEFAULT '(member=%s)',
    updated_at              timestamptz NOT NULL DEFAULT now(),
    updated_by              uuid        REFERENCES users(id) ON DELETE SET NULL
);
INSERT INTO ldap_settings (id) VALUES (1);

-- Single-row outbound notification configuration, edited by a superadmin via
-- the admin UI. Two independent channels: email (SMTP or Mailgun, mutually
-- exclusive) and Matrix. Secrets are stored here and never returned by the API
-- (write-only: the response exposes only "is set" booleans).
CREATE TABLE notification_settings (
    id                   smallint    PRIMARY KEY CHECK (id = 1),
    -- Email channel ------------------------------------------------------
    mail_enabled         boolean     NOT NULL DEFAULT false,
    -- 'smtp' | 'mailgun' — only one transport is active at a time.
    mail_provider        text        NOT NULL DEFAULT 'smtp',
    mail_from_address    text        NOT NULL DEFAULT '',
    mail_from_name       text        NOT NULL DEFAULT 'IntelliPilot',
    -- SMTP transport
    smtp_host            text        NOT NULL DEFAULT '',
    smtp_port            integer     NOT NULL DEFAULT 587,
    smtp_username        text        NOT NULL DEFAULT '',
    smtp_password        text        NOT NULL DEFAULT '',
    -- Negotiate StartTLS after connecting (port 587). When false, an implicit
    -- TLS connection is used (port 465).
    smtp_use_starttls    boolean     NOT NULL DEFAULT true,
    smtp_skip_tls_verify boolean     NOT NULL DEFAULT false,
    -- Mailgun HTTP API transport
    mailgun_api_key      text        NOT NULL DEFAULT '',
    mailgun_domain       text        NOT NULL DEFAULT '',
    -- Region base URL; EU is https://api.eu.mailgun.net
    mailgun_base_url     text        NOT NULL DEFAULT 'https://api.mailgun.net',
    -- Matrix channel -----------------------------------------------------
    matrix_enabled       boolean     NOT NULL DEFAULT false,
    -- e.g. https://chat.example.com
    matrix_homeserver    text        NOT NULL DEFAULT '',
    -- e.g. !room:chat.example.com
    matrix_room_id       text        NOT NULL DEFAULT '',
    matrix_access_token  text        NOT NULL DEFAULT '',
    -- Telegram channel ---------------------------------------------------
    telegram_enabled     boolean     NOT NULL DEFAULT false,
    telegram_bot_token   text        NOT NULL DEFAULT '',
    telegram_chat_id     text        NOT NULL DEFAULT '',
    -- Per-event toggles. Each event can be delivered over email and/or the
    -- messenger channels (Matrix + Telegram) independently.
    mail_on_login            boolean NOT NULL DEFAULT false,
    mail_on_issue_created    boolean NOT NULL DEFAULT false,
    mail_on_issue_resolved   boolean NOT NULL DEFAULT false,
    mail_on_daily_report     boolean NOT NULL DEFAULT false,
    msg_on_login             boolean NOT NULL DEFAULT false,
    msg_on_issue_created     boolean NOT NULL DEFAULT false,
    msg_on_issue_resolved    boolean NOT NULL DEFAULT false,
    msg_on_daily_report      boolean NOT NULL DEFAULT false,
    updated_at           timestamptz NOT NULL DEFAULT now(),
    updated_by           uuid        REFERENCES users(id) ON DELETE SET NULL
);
INSERT INTO notification_settings (id) VALUES (1);

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
