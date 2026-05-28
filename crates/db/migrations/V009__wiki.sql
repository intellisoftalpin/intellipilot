-- Phase 8: Wiki pages with immutable revision history.

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

-- Append-only: one row per save; never updated or deleted (except via page
-- cascade).
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
