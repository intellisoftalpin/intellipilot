-- ===========================================================================
-- Per-component fix versions on an issue.
--
-- An issue can already affect several components; until now it could only
-- carry one fix version for all of them, which is wrong whenever a change
-- ships in different versions of different components. This adds one version
-- per assigned component.
--
-- `issues.release_version_id` is KEPT. Every issues-list `?version=` filter,
-- the CSV/XLSX export and the board group-by read it, and rewriting all of
-- them would be a large change for no user-visible gain. It becomes a
-- **mirror** of the new table, maintained by trigger — the same technique
-- V019 used for `issues.milestone_id`.
--
-- Purely additive: one new table, a backfill, and triggers. Existing rows keep
-- working exactly as before.
-- ===========================================================================

CREATE TABLE issue_component_versions (
    issue_id           uuid NOT NULL REFERENCES issues(id) ON DELETE CASCADE,
    component_id       uuid NOT NULL REFERENCES components(id) ON DELETE CASCADE,
    release_version_id uuid NOT NULL REFERENCES release_versions(id) ON DELETE CASCADE,
    -- One version per component per issue: the whole point of the table.
    PRIMARY KEY (issue_id, component_id)
);
CREATE INDEX issue_component_versions_version_idx
    ON issue_component_versions (release_version_id);

COMMENT ON TABLE issue_component_versions IS
    'The version each affected component ships the fix in. '
    'issues.release_version_id mirrors the first of these.';

-- --- 1. Backfill -----------------------------------------------------------
-- Give every component of an issue the version that issue already carried.
-- Issues with a version but no components have nowhere to put it, so they
-- keep it in the old column alone — nothing is lost either way.

INSERT INTO issue_component_versions (issue_id, component_id, release_version_id)
SELECT i.id, ic.component_id, i.release_version_id
FROM issues i
JOIN issue_components ic ON ic.issue_id = i.id
WHERE i.release_version_id IS NOT NULL
ON CONFLICT DO NOTHING;

-- --- 2. Keep the mirror in step -------------------------------------------
-- The mirror is the lowest-ordered version among the issue's per-component
-- rows, so it is deterministic rather than "whichever was written last".
--
-- Note this fires ONLY for issues that have (or just lost) per-component
-- rows. An issue that never had any keeps whatever is in the column, which is
-- what preserves the component-less case above.

CREATE FUNCTION issue_mirror_release_version() RETURNS trigger AS $$
DECLARE
    target uuid;
    mirror uuid;
BEGIN
    target := COALESCE(NEW.issue_id, OLD.issue_id);
    SELECT icv.release_version_id INTO mirror
    FROM issue_component_versions icv
    JOIN release_versions rv ON rv.id = icv.release_version_id
    WHERE icv.issue_id = target
    ORDER BY rv."order", rv.id
    LIMIT 1;

    UPDATE issues
    SET release_version_id = mirror
    WHERE id = target
      AND release_version_id IS DISTINCT FROM mirror;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER issue_component_versions_mirror
    AFTER INSERT OR UPDATE OR DELETE ON issue_component_versions
    FOR EACH ROW EXECUTE FUNCTION issue_mirror_release_version();

-- --- 3. A version belongs to a component the issue actually affects --------
-- Unassigning a component takes its version with it; otherwise the row would
-- linger, invisible in the UI but still feeding the mirror.

CREATE FUNCTION issue_component_versions_prune() RETURNS trigger AS $$
BEGIN
    DELETE FROM issue_component_versions
    WHERE issue_id = OLD.issue_id
      AND component_id = OLD.component_id;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER issue_components_prune_versions
    AFTER DELETE ON issue_components
    FOR EACH ROW EXECUTE FUNCTION issue_component_versions_prune();
