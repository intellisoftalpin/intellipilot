-- ===========================================================================
-- Short, memorable deep links.
--
--   * boards gain a `key`: a short lowercase slug, unique per project, used
--     as the URL segment instead of the board UUID. Auto-derived from the
--     board name (initials for multi-word names, the truncated word
--     otherwise) with a numeric suffix on collision; editable in board
--     settings.
--   * `project_prefix_history` / `board_key_history` keep every previously
--     used project issue-prefix / board key, so short links shared before a
--     rename keep resolving. Superadmins can inspect and prune the history.
--
-- The project issue-prefix itself (V009) is already globally unique and
-- needs no schema change: URL resolution merely compares case-insensitively.
-- ===========================================================================

-- 1. Board key column (nullable during backfill).
ALTER TABLE boards ADD COLUMN key varchar(12);

-- 2. Backfill a per-project-unique key for every existing board.
DO $$
DECLARE
    r     record;
    base  text;
    cand  text;
    n     integer;
    words text[];
BEGIN
    FOR r IN SELECT id, project_id, name FROM boards WHERE key IS NULL
             ORDER BY project_id, "order", created_at LOOP
        -- Lowercase alphanumeric words of the name.
        words := regexp_split_to_array(
            trim(regexp_replace(lower(r.name), '[^a-z0-9]+', ' ', 'g')), ' ');
        words := array_remove(words, '');
        IF words IS NULL OR cardinality(words) = 0 THEN
            base := 'b';
        ELSIF cardinality(words) >= 2 THEN
            -- Initials of up to 6 words: "Sprint Board" -> "sb".
            SELECT string_agg(left(w, 1), '') INTO base
              FROM unnest(words[1:6]) AS w;
        ELSE
            -- Single word truncated: "Board" -> "board".
            base := left(words[1], 6);
        END IF;

        cand := base;
        n := 1;
        WHILE EXISTS (SELECT 1 FROM boards
                      WHERE project_id = r.project_id AND key = cand) LOOP
            n := n + 1;
            cand := left(base, 12 - length(n::text) - 1) || '-' || n::text;
        END LOOP;
        UPDATE boards SET key = cand WHERE id = r.id;
    END LOOP;
END $$;

-- 3. Tighten constraints now that every board has a key.
ALTER TABLE boards
    ALTER COLUMN key SET NOT NULL,
    ADD CONSTRAINT boards_key_format
        CHECK (key ~ '^[a-z0-9]([a-z0-9-]{0,10}[a-z0-9])?$'),
    ADD CONSTRAINT boards_key_unique UNIQUE (project_id, key);

-- 4. Rename history: last claim of a value wins (upsert on rename), so a
--    freed value redirects to wherever it was used most recently. Live
--    prefixes/keys always shadow history at resolution time.
CREATE TABLE project_prefix_history (
    id          uuid        PRIMARY KEY DEFAULT uuidv7(),
    project_id  uuid        NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    prefix      varchar(3)  NOT NULL,
    replaced_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT project_prefix_history_format CHECK (prefix ~ '^[A-Z]{2,3}$'),
    CONSTRAINT project_prefix_history_unique UNIQUE (prefix)
);
CREATE INDEX project_prefix_history_project_idx
    ON project_prefix_history (project_id);

CREATE TABLE board_key_history (
    id          uuid        PRIMARY KEY DEFAULT uuidv7(),
    project_id  uuid        NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    board_id    uuid        NOT NULL REFERENCES boards(id) ON DELETE CASCADE,
    key         varchar(12) NOT NULL,
    replaced_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT board_key_history_unique UNIQUE (project_id, key)
);
CREATE INDEX board_key_history_board_idx ON board_key_history (board_id);
