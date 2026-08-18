-- ===========================================================================
-- Split a milestone's end date into planned and actual.
--
-- `end_date` keeps its name and its meaning: the *planned* technical end.
-- Renaming it would touch every board filter, export and gantt query for no
-- gain, so the new column is the addition instead.
--
-- `actual_end_date` is when the milestone really finished. The gap between
-- the two is the slip (or the time saved), which the gantt draws in its own
-- colour.
--
-- Purely additive: one nullable column plus a widened CHECK. Existing rows
-- have `actual_end_date IS NULL` and behave exactly as before.
-- ===========================================================================

ALTER TABLE milestones
    ADD COLUMN actual_end_date date;

COMMENT ON COLUMN milestones.end_date IS
    'Planned technical end date. See actual_end_date for when it really '
    'finished; the difference between the two is the slip.';

COMMENT ON COLUMN milestones.actual_end_date IS
    'When the milestone actually finished. NULL while it is still open or '
    'was never recorded. Set automatically from end_date on completion.';

-- The business (commercial) release trails whichever technical release
-- actually happened — the real end date when one is recorded, the planned one
-- otherwise. V019 could only compare against the planned date, which allowed
-- a slipped milestone to announce its business release *before* the release
-- it announces.
ALTER TABLE milestones
    DROP CONSTRAINT milestones_business_release_after_end;

ALTER TABLE milestones
    ADD CONSTRAINT milestones_business_release_after_end
        CHECK (
            business_release_date IS NULL
            OR (
                COALESCE(actual_end_date, end_date) IS NOT NULL
                AND business_release_date > COALESCE(actual_end_date, end_date)
            )
        );
