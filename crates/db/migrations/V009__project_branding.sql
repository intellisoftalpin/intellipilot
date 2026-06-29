-- ===========================================================================
-- Project branding & independent epic numbering.
--
--   * projects gain an issue_prefix (2–3 uppercase letters, globally unique):
--     issue keys render as "<PREFIX>-<ref>" and epic keys as "<PREFIX>-E-<ref>".
--   * projects gain a card color (hex from the predefined palette) and an
--     uploaded icon image, modelled exactly like epic covers / user avatars
--     (kind + storage key + mime + updated-at for cache-busting). 'none' means
--     render the prefix-initials fallback.
--   * epics get their own ref sequence (project_ref_counters.last_epic_ref) so
--     they number independently of issues (PS-E-1, PS-E-2, …). Existing epic
--     numbers are preserved; the counter is seeded from the current max.
--
-- All additions are nullable / defaulted, then backfilled, so existing installs
-- keep working and end up with a valid, unique prefix and a stable color.
-- ===========================================================================

-- 1. New project columns (backfilled below before constraints are tightened).
ALTER TABLE projects
    ADD COLUMN issue_prefix           varchar(3),
    ADD COLUMN color                  varchar(16) NOT NULL DEFAULT '',
    ADD COLUMN icon_image_kind        varchar(8)  NOT NULL DEFAULT 'none',
    ADD COLUMN icon_image_storage_key text,
    ADD COLUMN icon_image_mime        varchar(64),
    ADD COLUMN icon_image_updated_at  timestamptz;

ALTER TABLE projects
    ADD CONSTRAINT projects_icon_image_kind_valid
        CHECK (icon_image_kind IN ('none', 'image'));

-- 2. Separate epic counter. Issues keep last_ref; epics continue from their
--    current max so existing epic numbers are never renumbered.
ALTER TABLE project_ref_counters
    ADD COLUMN last_epic_ref bigint NOT NULL DEFAULT 0;

UPDATE project_ref_counters c
SET last_epic_ref = COALESCE(
    (SELECT max(e.ref) FROM epics e WHERE e.project_id = c.project_id), 0);

-- 3. Backfill card color deterministically from the 10-color palette (matches
--    the frontend ColorPalette.swatches), so each project gets a stable color.
WITH pal(idx, hex) AS (VALUES
    (0, '#999999'), (1, '#ff8a84'), (2, '#ffcc00'), (3, '#9dce0a'), (4, '#669900'),
    (5, '#0079bc'), (6, '#5c3566'), (7, '#cc0000'), (8, '#ff7518'), (9, '#34495e'))
UPDATE projects p
SET color = pal.hex
FROM pal
WHERE p.color = ''
  AND pal.idx = ((('x' || substr(md5(p.id::text), 1, 8))::bit(32)::int % 10) + 10) % 10;

-- 4. Backfill a valid, globally-unique issue_prefix for every existing project.
--    Derive up to 3 leading uppercase letters from the name; resolve collisions
--    by scanning AA, AB, … ZZ then AAA… deterministically.
DO $$
DECLARE
    r       RECORD;
    letters text;
    cand    text;
    i       int;
BEGIN
    FOR r IN SELECT id, name FROM projects WHERE issue_prefix IS NULL ORDER BY created_at LOOP
        letters := upper(regexp_replace(r.name, '[^A-Za-z]', '', 'g'));
        IF length(letters) >= 2 THEN
            cand := left(letters, 3);
        ELSE
            cand := 'PRJ';
        END IF;
        i := 0;
        WHILE EXISTS (SELECT 1 FROM projects WHERE issue_prefix = cand) LOOP
            IF i < 676 THEN
                cand := chr(65 + ((i / 26) % 26)) || chr(65 + (i % 26));
            ELSE
                cand := chr(65 + ((i / 676) % 26)) || chr(65 + ((i / 26) % 26)) || chr(65 + (i % 26));
            END IF;
            i := i + 1;
        END LOOP;
        UPDATE projects SET issue_prefix = cand WHERE id = r.id;
    END LOOP;
END $$;

-- 5. Tighten constraints now that every row has a valid, unique prefix.
ALTER TABLE projects
    ALTER COLUMN issue_prefix SET NOT NULL,
    ADD CONSTRAINT projects_issue_prefix_format CHECK (issue_prefix ~ '^[A-Z]{2,3}$'),
    ADD CONSTRAINT projects_issue_prefix_unique UNIQUE (issue_prefix);
