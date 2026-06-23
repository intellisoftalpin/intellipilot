-- ===========================================================================
-- Time tracking (release 0.4.4)
--
-- Incremental migration over the V001 baseline. Adds:
--   * time_entries        — unified per-day records (worked time + absences)
--   * time_period_locks   — per project-month read-only lock set by admins
--   * vacation_allowances — superadmin-managed yearly quota + carryover
--   * users.work_minutes_per_day — per-user daily target (default 8h)
--
-- Design notes:
--   * Worked time and absences share one table. A `work` row is tied to a
--     project (and usually an issue); an absence row (vacation / illness /
--     day_off / holiday) is person-level and carries no project.
--   * Time logs survive task deletion (issue_id -> SET NULL, link goes
--     inactive) and a user leaving a project (memberships cascade is unrelated
--     to this table). They are removed only if the whole project or user is
--     hard-deleted.
-- ===========================================================================

CREATE TABLE time_entries (
    id            uuid          PRIMARY KEY DEFAULT uuidv7(),
    user_id       uuid          NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    -- 'work' | 'vacation' | 'illness' | 'day_off' | 'holiday'
    kind          varchar(16)   NOT NULL DEFAULT 'work',
    -- Worked time belongs to a project; absences are person-level (NULL).
    project_id    uuid          REFERENCES projects(id) ON DELETE CASCADE,
    -- The task the time was logged against. SET NULL on task deletion so the
    -- entry is retained with an inactive link.
    issue_id      uuid          REFERENCES issues(id) ON DELETE SET NULL,
    entry_date    date          NOT NULL,
    minutes       integer       NOT NULL,
    note          text          NOT NULL DEFAULT '',
    -- Groups the per-day rows materialised from a single multi-day absence
    -- booking, so the whole booking can be cancelled/edited as a unit.
    booking_id    uuid,
    created_at    timestamptz   NOT NULL DEFAULT now(),
    modified_at   timestamptz   NOT NULL DEFAULT now(),
    version       integer       NOT NULL DEFAULT 1,
    CONSTRAINT time_entries_minutes_range CHECK (minutes > 0 AND minutes <= 1440),
    CONSTRAINT time_entries_kind_valid
        CHECK (kind IN ('work', 'vacation', 'illness', 'day_off', 'holiday')),
    -- Work rows require a project; absence rows must not carry one.
    CONSTRAINT time_entries_work_has_project
        CHECK ((kind = 'work') = (project_id IS NOT NULL))
);
CREATE INDEX time_entries_user_date_idx ON time_entries (user_id, entry_date);
CREATE INDEX time_entries_project_date_idx ON time_entries (project_id, entry_date)
    WHERE project_id IS NOT NULL;
CREATE INDEX time_entries_issue_idx ON time_entries (issue_id)
    WHERE issue_id IS NOT NULL;
CREATE INDEX time_entries_booking_idx ON time_entries (booking_id)
    WHERE booking_id IS NOT NULL;
CREATE TRIGGER time_entries_set_modified_at
    BEFORE UPDATE ON time_entries
    FOR EACH ROW EXECUTE FUNCTION set_modified_at();

-- A project admin freezes a (project, year, month). While a row exists, that
-- project's work entries in the month are read-only to members without the
-- time.manage permission.
CREATE TABLE time_period_locks (
    id          uuid          PRIMARY KEY DEFAULT uuidv7(),
    project_id  uuid          NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    year        integer       NOT NULL,
    month       integer       NOT NULL,
    locked_by   uuid          REFERENCES users(id) ON DELETE SET NULL,
    locked_at   timestamptz   NOT NULL DEFAULT now(),
    UNIQUE (project_id, year, month),
    CONSTRAINT time_period_locks_month_valid CHECK (month BETWEEN 1 AND 12)
);
CREATE INDEX time_period_locks_project_idx ON time_period_locks (project_id);

-- Superadmin-managed yearly vacation quota. One row per user per year; unused
-- days from earlier years are retained as explicit `carried_over_days` so the
-- history stays visible.
CREATE TABLE vacation_allowances (
    id                 uuid               PRIMARY KEY DEFAULT uuidv7(),
    user_id            uuid               NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    year               integer            NOT NULL,
    allowance_days     double precision   NOT NULL DEFAULT 0,
    carried_over_days  double precision   NOT NULL DEFAULT 0,
    note               text               NOT NULL DEFAULT '',
    set_by             uuid               REFERENCES users(id) ON DELETE SET NULL,
    created_at         timestamptz        NOT NULL DEFAULT now(),
    modified_at        timestamptz        NOT NULL DEFAULT now(),
    UNIQUE (user_id, year),
    CONSTRAINT vacation_allowances_non_negative
        CHECK (allowance_days >= 0 AND carried_over_days >= 0)
);
CREATE INDEX vacation_allowances_user_idx ON vacation_allowances (user_id);
CREATE TRIGGER vacation_allowances_set_modified_at
    BEFORE UPDATE ON vacation_allowances
    FOR EACH ROW EXECUTE FUNCTION set_modified_at();

-- Per-user daily target used by the "missing timesheet" check and to convert
-- absence hours into vacation days. Default 8h.
ALTER TABLE users ADD COLUMN work_minutes_per_day integer NOT NULL DEFAULT 480;
