-- ===========================================================================
-- Issues & Kanban rework.
--
--   * taxonomy_items gain an is_new flag — the mirror of is_closed, meaningful
--     only for the issue_status kind. At most ONE status per project may be the
--     "new" status (partial unique index). New issues created without an
--     explicit status are auto-placed in it; the board renders it first.
--     Backfill: the lowest-ordered open status per project becomes is_new.
--
--   * customers become many-to-many with issues via issue_customers (mirrors
--     issue_components). The old single issues.customer_id is migrated into the
--     join table and dropped.
--
--   * per-user kanban board configuration: board_views holds named saved states
--     and board_last_used remembers the last board each user looked at. The
--     config (visible columns, order, filter, grouping) is stored opaque as
--     jsonb so the shape can evolve without further migrations.
--
-- All additions preserve existing installs.
-- ===========================================================================

-- 1. is_new status flag (mirror of is_closed) + at-most-one-per-project guard.
ALTER TABLE taxonomy_items
    ADD COLUMN is_new boolean;

-- Backfill: the lowest-ordered non-closed status of each project is its "new".
WITH first_open AS (
    SELECT DISTINCT ON (project_id) id
    FROM taxonomy_items
    WHERE kind = 'issue_status' AND COALESCE(is_closed, false) = false
    ORDER BY project_id, "order"
)
UPDATE taxonomy_items t
SET is_new = true
FROM first_open f
WHERE t.id = f.id;

CREATE UNIQUE INDEX taxonomy_items_one_new_per_project
    ON taxonomy_items (project_id)
    WHERE kind = 'issue_status' AND is_new IS TRUE;

-- 2. Multi-customer: join table mirroring issue_components, backfilled from the
--    old single FK, then drop the column.
CREATE TABLE issue_customers (
    issue_id    uuid NOT NULL REFERENCES issues(id) ON DELETE CASCADE,
    customer_id uuid NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
    PRIMARY KEY (issue_id, customer_id)
);
CREATE INDEX issue_customers_customer_idx ON issue_customers (customer_id);

INSERT INTO issue_customers (issue_id, customer_id)
    SELECT id, customer_id FROM issues WHERE customer_id IS NOT NULL;

ALTER TABLE issues DROP CONSTRAINT issues_customer_fk;
ALTER TABLE issues DROP COLUMN customer_id;

-- 3. Per-user kanban board configuration.
CREATE TABLE board_views (
    id          uuid             PRIMARY KEY DEFAULT uuidv7(),
    project_id  uuid             NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    user_id     uuid             NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name        text             NOT NULL,
    config      jsonb            NOT NULL DEFAULT '{}'::jsonb,
    created_at  timestamptz      NOT NULL DEFAULT now(),
    modified_at timestamptz      NOT NULL DEFAULT now()
);
CREATE INDEX board_views_owner_idx ON board_views (project_id, user_id);
CREATE TRIGGER board_views_set_modified_at BEFORE UPDATE ON board_views
    FOR EACH ROW EXECUTE FUNCTION set_modified_at();

CREATE TABLE board_last_used (
    project_id  uuid             NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    user_id     uuid             NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    config      jsonb            NOT NULL DEFAULT '{}'::jsonb,
    modified_at timestamptz      NOT NULL DEFAULT now(),
    PRIMARY KEY (project_id, user_id)
);
