-- ===========================================================================
-- Split a milestone's start date into planned and actual.
--
-- Same shape as V021 did for the end date: `start_date` keeps its name and
-- becomes the *planned* start, and `actual_start_date` is the addition. It is
-- only ever set by hand -- nothing derives it.
--
-- Purely additive: one nullable column plus a CHECK that cannot fail on
-- existing rows (every one of them has `actual_start_date IS NULL`).
-- ===========================================================================

ALTER TABLE milestones
    ADD COLUMN actual_start_date date;

COMMENT ON COLUMN milestones.start_date IS
    'Planned start date. See actual_start_date for when work really began.';

COMMENT ON COLUMN milestones.actual_start_date IS
    'When work on the milestone actually began. NULL until recorded; set by '
    'hand only.';

-- A milestone cannot really finish before it really started. Mirrored in the
-- API so the user gets a 422 rather than a 500 from the constraint.
ALTER TABLE milestones
    ADD CONSTRAINT milestones_actual_end_after_actual_start
        CHECK (
            actual_start_date IS NULL
            OR actual_end_date IS NULL
            OR actual_end_date >= actual_start_date
        );
