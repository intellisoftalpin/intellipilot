-- ===========================================================================
-- Milestone rework.
--
--   1. milestones gain a description and a *business* release date (the
--      commercial ship date, always strictly after the technical end date).
--   2. Milestone membership becomes structural: issues reach a milestone
--      ONLY through their epic. `issues.milestone_id` is kept -- every board
--      filter, group-by, export and stats query reads it -- but it stops
--      being writable by anyone. Two triggers own it from here on, so the
--      invariant holds even against direct SQL.
--   3. The two new business-release permissions are backfilled into the
--      roles that already behave like a product owner.
--
-- Every addition is nullable / defaulted, so existing installs keep working.
-- ===========================================================================

-- --- 1. New milestone fields ----------------------------------------------

ALTER TABLE milestones
    ADD COLUMN description           text NOT NULL DEFAULT '',
    ADD COLUMN business_release_date date;

-- A business release only means something relative to a technical release:
-- it needs an end date and must land strictly after it. Enforced here as well
-- as in the API so no code path can produce an undrawable gantt tail.
ALTER TABLE milestones
    ADD CONSTRAINT milestones_business_release_after_end
        CHECK (
            business_release_date IS NULL
            OR (end_date IS NOT NULL AND business_release_date > end_date)
        );

-- --- 2. Epic-derived milestone membership ---------------------------------

-- Snapshot every direct issue->milestone assignment that does NOT agree with
-- the issue's epic, BEFORE the backfill rewrites it. Purely a safety net for
-- operators: nothing reads this table, and it can be dropped once an install
-- is happy with the migration.
CREATE TABLE issues_milestone_legacy (
    issue_id             uuid        PRIMARY KEY,
    project_id           uuid        NOT NULL,
    legacy_milestone_id  uuid        NOT NULL,
    epic_id              uuid,
    captured_at          timestamptz NOT NULL DEFAULT now()
);

COMMENT ON TABLE issues_milestone_legacy IS
    'Pre-V019 direct issue->milestone assignments that the epic-derived '
    'backfill overwrote. Retained for manual recovery; read by nothing.';

INSERT INTO issues_milestone_legacy (issue_id, project_id, legacy_milestone_id, epic_id)
SELECT i.id, i.project_id, i.milestone_id, i.epic_id
FROM issues i
LEFT JOIN epics e ON e.id = i.epic_id AND e.deleted_at IS NULL
WHERE i.milestone_id IS NOT NULL
  AND i.milestone_id IS DISTINCT FROM e.milestone_id;

-- Backfill to the epic-derived truth. `IS DISTINCT FROM` keeps rows that are
-- already correct untouched, so `modified_at` (and therefore the board's
-- delta-sync feed) only moves for issues that genuinely changed.
UPDATE issues i
SET milestone_id = e.milestone_id
FROM epics e
WHERE e.id = i.epic_id
  AND e.deleted_at IS NULL
  AND i.milestone_id IS DISTINCT FROM e.milestone_id;

UPDATE issues i
SET milestone_id = NULL
WHERE i.milestone_id IS NOT NULL
  AND NOT EXISTS (
      SELECT 1 FROM epics e
      WHERE e.id = i.epic_id AND e.deleted_at IS NULL
  );

-- An issue's milestone is always its live epic's milestone. Recomputed on
-- every insert and update -- not just when `epic_id` appears in the SET list
-- -- so a stray `UPDATE issues SET milestone_id = ...` cannot desynchronise
-- it. A soft-deleted epic yields NULL (SELECT ... INTO sets NULL on no rows).
CREATE FUNCTION issue_milestone_from_epic() RETURNS trigger AS $$
BEGIN
    IF NEW.epic_id IS NULL THEN
        NEW.milestone_id := NULL;
    ELSE
        SELECT e.milestone_id INTO NEW.milestone_id
        FROM epics e
        WHERE e.id = NEW.epic_id AND e.deleted_at IS NULL;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER issues_milestone_from_epic
    BEFORE INSERT OR UPDATE ON issues
    FOR EACH ROW EXECUTE FUNCTION issue_milestone_from_epic();

-- Moving an epic between milestones (or soft-deleting / restoring it) carries
-- its issues along. The `IS DISTINCT FROM` guard means a no-op epic save
-- writes zero issue rows, keeping the delta-sync feed quiet.
CREATE FUNCTION epic_milestone_cascade() RETURNS trigger AS $$
DECLARE
    effective uuid;
BEGIN
    effective := CASE WHEN NEW.deleted_at IS NULL THEN NEW.milestone_id ELSE NULL END;
    UPDATE issues
    SET milestone_id = effective
    WHERE epic_id = NEW.id
      AND milestone_id IS DISTINCT FROM effective;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER epics_milestone_cascade
    AFTER UPDATE OF milestone_id, deleted_at ON epics
    FOR EACH ROW
    WHEN (
        NEW.milestone_id IS DISTINCT FROM OLD.milestone_id
        OR (NEW.deleted_at IS NULL) IS DISTINCT FROM (OLD.deleted_at IS NULL)
    )
    EXECUTE FUNCTION epic_milestone_cascade();

-- --- 3. Business-release permission backfill -------------------------------
-- Same shape as V007: append-only, idempotent, and keyed on behaviour rather
-- than on the role's slug (projects may have renamed or replaced the seeded
-- roles). Admin roles get everything; non-admin roles that already hold
-- `milestone.delete` are product-owner-equivalent and get both.

UPDATE roles
SET permissions = permissions || sub.missing
FROM (
    SELECT r.id,
           COALESCE(
               jsonb_agg(p.perm) FILTER (WHERE NOT (r.permissions ? p.perm)),
               '[]'::jsonb
           ) AS missing
    FROM roles r
    CROSS JOIN (VALUES
        ('milestone.business_release.view'),
        ('milestone.business_release.modify')
    ) AS p(perm)
    WHERE r.is_admin = true
       OR r.permissions ? 'milestone.delete'
    GROUP BY r.id
) AS sub
WHERE roles.id = sub.id
  AND sub.missing <> '[]'::jsonb;
