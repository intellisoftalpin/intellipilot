-- ===========================================================================
-- Meetings + flexible time logging.
--
--   * A new time-entry kind, 'meeting', for time spent in meetings rather than
--     on a task. Meetings are project-OPTIONAL (a sprint planning belongs to a
--     project; a company all-hands does not) and carry an optional meeting_type.
--   * Work entries may now be logged WITHOUT a task (issue_id stays NULL) — the
--     API requires a note in that case.
--
-- The work⇒project rule is relaxed so: work must have a project; meetings may
-- have one or not; absences must not.
-- ===========================================================================

ALTER TABLE time_entries
    ADD COLUMN meeting_type varchar(16);

ALTER TABLE time_entries DROP CONSTRAINT time_entries_kind_valid;
ALTER TABLE time_entries
    ADD CONSTRAINT time_entries_kind_valid
        CHECK (kind IN ('work', 'meeting', 'vacation', 'illness', 'day_off', 'holiday'));

ALTER TABLE time_entries DROP CONSTRAINT time_entries_work_has_project;
ALTER TABLE time_entries
    ADD CONSTRAINT time_entries_project_by_kind
        CHECK (
            (kind = 'work' AND project_id IS NOT NULL)
            OR (kind = 'meeting')
            OR (kind IN ('vacation', 'illness', 'day_off', 'holiday') AND project_id IS NULL)
        );

-- meeting_type is only meaningful on meetings, and is one of the known types.
ALTER TABLE time_entries
    ADD CONSTRAINT time_entries_meeting_type_valid
        CHECK (
            meeting_type IS NULL
            OR (kind = 'meeting'
                AND meeting_type IN ('daily', 'planning', 'troubleshooting',
                                     'retro', 'refinement', 'other'))
        );
