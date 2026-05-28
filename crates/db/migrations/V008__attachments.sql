-- Phase 7: Attachments on backlog entities (and, later, wiki pages).

CREATE TABLE attachments (
    id           uuid        PRIMARY KEY DEFAULT uuidv7(),
    project_id   uuid        NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    -- 'epic' | 'user_story' | 'task' | 'issue' | 'wiki'
    target_type  varchar(16) NOT NULL,
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
CREATE INDEX attachments_target_idx
    ON attachments (target_type, target_id) WHERE deleted_at IS NULL;
-- Supports the background GC sweep over soft-deleted rows.
CREATE INDEX attachments_gc_idx
    ON attachments (deleted_at) WHERE deleted_at IS NOT NULL;
