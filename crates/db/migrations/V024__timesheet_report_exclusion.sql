-- ===========================================================================
-- Exclude a user from timesheet reports.
--
-- Some people are on the platform without a fill obligation — top managers and
-- freelance consultants. They should not appear as a row in team timesheet
-- tables, and should not be nagged about unfilled working days. What they must
-- keep is the ability to track their own time: this is a *reporting* exclusion,
-- not a technical restriction.
--
-- Where the flag applies (see crates/db/src/time_tracking.rs):
--   * the per-project team grid and the cross-project superadmin grid —
--     the row is omitted entirely;
--   * the project time-entry list and its CSV/XLSX export — entries omitted;
--   * the personal completeness summary — `missing_days` comes back empty, so
--     the dashboard / project-overview warning card renders nothing.
--
-- Where it deliberately does NOT apply:
--   * per-issue time logs, so issue-level effort data stays correct;
--   * the admin cross-project entry list, so a superadmin retains one view
--     that shows every hour;
--   * the user's own timesheet, logging, locks and vacation balance.
--
-- Purely additive and defaulted, so every existing install behaves exactly as
-- it did before this migration ran.
-- ===========================================================================

ALTER TABLE users
    ADD COLUMN exclude_from_time_reports boolean NOT NULL DEFAULT false;

COMMENT ON COLUMN users.exclude_from_time_reports IS
    'Hide this user from team timesheet tables, project time-entry lists and '
    'exports, and suppress their unfilled-days warning. Time tracking itself '
    'is unaffected: the user can still log time and see their own entries, '
    'and their hours remain in per-issue time logs and the admin '
    'cross-project entry list.';
