-- Phase 5 (extension): project-level Labels and Components for issues.

-- ---------------------------------------------------------------------------
-- labels
-- ---------------------------------------------------------------------------
CREATE TABLE labels (
    id          uuid            PRIMARY KEY DEFAULT uuidv7(),
    project_id  uuid            NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name        varchar(64)     NOT NULL,
    color       varchar(16)     NOT NULL DEFAULT '',
    created_at  timestamptz     NOT NULL DEFAULT now(),
    UNIQUE (project_id, name)
);
CREATE INDEX labels_project_idx ON labels (project_id);

-- ---------------------------------------------------------------------------
-- components (with optional git repository link)
-- ---------------------------------------------------------------------------
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

-- ---------------------------------------------------------------------------
-- issue ↔ label / component (many-to-many)
-- ---------------------------------------------------------------------------
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
