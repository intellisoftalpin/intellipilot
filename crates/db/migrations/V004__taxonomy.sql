-- Phase 4: Per-project taxonomy (statuses, issue types, priorities,
-- severities, points) in one unified table keyed by `kind`.

CREATE TABLE taxonomy_items (
    id          uuid            PRIMARY KEY DEFAULT uuidv7(),
    project_id  uuid            NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    -- 'us_status' | 'task_status' | 'issue_status' | 'issue_type'
    -- | 'priority' | 'severity' | 'point'
    kind        varchar(16)     NOT NULL,
    name        text            NOT NULL,
    slug        varchar(64)     NOT NULL,
    color       varchar(16)     NOT NULL DEFAULT '',
    -- Fractional rank for reordering (midpoint insertion).
    "order"     double precision NOT NULL DEFAULT 1.0,
    -- Status kinds only.
    is_closed   boolean,
    -- Points only.
    value       double precision,
    created_at  timestamptz     NOT NULL DEFAULT now(),
    UNIQUE (project_id, kind, slug)
);

CREATE INDEX taxonomy_items_project_kind_idx
    ON taxonomy_items (project_id, kind, "order");
