-- ===========================================================================
-- "Considered completed" status flag.
--
-- Progress on epics and milestones counted an issue as finished only when its
-- status carried `is_closed` — in a default project, just Done and Archived.
-- That conflates two different questions:
--
--   is_closed       — is this issue *closed*? Drives the resolution-required
--                     rule, the open/closed filters, the dashboard and the
--                     board's column logic.
--   counts_as_done  — is there any work left? Drives progress bars only.
--
-- A task sitting in "In Staging" needs no more work and should fill the
-- progress ring, but it is emphatically not closed: it still wants a
-- resolution, and hiding it behind a "closed" filter would lose it. Splitting
-- the flags lets a project nominate any status as complete for reporting
-- without disturbing any behavioural rule.
--
-- The two flags are deliberately independent — neither implies the other, so
-- a project can also mark a closed status as *not* counting toward progress.
--
-- Purely additive. The backfill copies is_closed, so every existing install
-- reports exactly the numbers it reported before this migration ran.
-- ===========================================================================

ALTER TABLE taxonomy_items
    ADD COLUMN counts_as_done boolean;

-- Only the issue_status kind carries the flag, mirroring is_closed / is_new.
-- COALESCE because is_closed is itself nullable on rows seeded before it was
-- mandatory for the kind.
UPDATE taxonomy_items
SET counts_as_done = COALESCE(is_closed, false)
WHERE kind = 'issue_status';

COMMENT ON COLUMN taxonomy_items.is_closed IS
    'Whether this status closes the issue: demands a resolution, hides it '
    'from open-issue filters, and counts it as closed on the dashboard. For '
    'progress bars see counts_as_done.';

COMMENT ON COLUMN taxonomy_items.counts_as_done IS
    'Whether epic and milestone progress treat this status as finished work. '
    'Independent of is_closed: a status can fill the progress ring without '
    'closing the issue (e.g. In Staging), or close it without counting. '
    'NULL for kinds other than issue_status.';
