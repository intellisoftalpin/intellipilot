-- ===========================================================================
-- Multiple boards (personal + shared).
--
-- Evolves the per-user `board_views` saved-views mechanism (V010) into a
-- first-class `boards` entity. A board belongs to a project, has a creator
-- (`owner_id`) and a `visibility`:
--   * 'personal' — visible only to its owner; any project viewer may create
--     their own and manage them.
--   * 'shared'   — visible to every project member; managing them is gated by
--     the board.shared.{create,modify,delete} permissions.
--
-- `config` (jsonb) holds the board's columns (visible + order), swimlane
-- grouping, locked filters, and display options — stored opaque so the shape
-- can evolve without a migration.
--
-- Existing per-user saved views are migrated into personal boards (preserved).
-- Every existing project gets one shared default board so none is board-less.
-- ===========================================================================

CREATE TABLE boards (
    id          uuid             PRIMARY KEY DEFAULT uuidv7(),
    project_id  uuid             NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    owner_id    uuid             REFERENCES users(id) ON DELETE SET NULL,
    visibility  varchar(10)      NOT NULL DEFAULT 'personal',
    name        text             NOT NULL,
    color       varchar(16)      NOT NULL DEFAULT '',
    config      jsonb            NOT NULL DEFAULT '{}'::jsonb,
    "order"     double precision NOT NULL DEFAULT 1.0,
    created_at  timestamptz      NOT NULL DEFAULT now(),
    modified_at timestamptz      NOT NULL DEFAULT now(),
    CONSTRAINT boards_visibility_valid CHECK (visibility IN ('personal', 'shared'))
);
CREATE INDEX boards_project_idx ON boards (project_id);
CREATE INDEX boards_owner_idx ON boards (project_id, owner_id);
CREATE TRIGGER boards_set_modified_at BEFORE UPDATE ON boards
    FOR EACH ROW EXECUTE FUNCTION set_modified_at();

-- Preserve existing per-user saved views as personal boards.
INSERT INTO boards (project_id, owner_id, visibility, name, color, config, "order")
SELECT project_id, user_id, 'personal', name, '', config,
       row_number() OVER (PARTITION BY project_id, user_id ORDER BY name)
FROM board_views;

-- One shared default board per existing (live) project.
INSERT INTO boards (project_id, owner_id, visibility, name, color, config, "order")
SELECT id, NULL, 'shared', 'Board', '', '{}'::jsonb, 0
FROM projects
WHERE deleted_at IS NULL;

DROP TABLE board_last_used;
DROP TABLE board_views;

-- Remember which board each user had open last (replaces board_last_used,
-- which stored a config blob; now we remember the board id).
CREATE TABLE board_last_opened (
    project_id  uuid        NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    user_id     uuid        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    board_id    uuid        REFERENCES boards(id) ON DELETE SET NULL,
    modified_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (project_id, user_id)
);
