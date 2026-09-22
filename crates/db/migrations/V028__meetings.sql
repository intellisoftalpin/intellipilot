-- ===========================================================================
-- V028: project meetings and their minutes.
--
--   1. `meetings` — one row per meeting. The calendar date is required; the
--      start/end times are optional *local* wall-clock times, interpreted in
--      the meeting's own IANA `timezone`. Storing the date as entered (rather
--      than as an instant) is deliberate: a meeting held 23:30 in Zurich is on
--      that day's calendar for everyone, whatever their own zone.
--      The summary (markdown) and the full transcript (plain text) live on
--      the row itself, so both are editable and searchable.
--   2. Link tables — participants (users), issues, epics and customers.
--   3. `attachments.kind` — meeting files reuse the attachments table
--      (target_type 'meeting') so they share content-addressed storage,
--      signed downloads and GC. `kind` says what the file is to the meeting
--      (recording / transcript / summary / other); it stays NULL for every
--      other target.
--   4. A search_index trigger (entity_type 'meeting').
--   5. The meeting.* permissions, backfilled onto existing roles.
--
-- Purely additive: new tables, one nullable column, one trigger and a
-- permission backfill. Existing installs are unaffected.
-- ===========================================================================

-- --- 1. Meetings -----------------------------------------------------------
CREATE TABLE meetings (
    id           uuid         PRIMARY KEY DEFAULT uuidv7(),
    project_id   uuid         NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    title        varchar(300) NOT NULL,
    meeting_date date         NOT NULL,
    start_time   time,
    end_time     time,
    timezone     varchar(64)  NOT NULL DEFAULT 'UTC',
    -- A room, an address or a call link — free text.
    location     text         NOT NULL DEFAULT '',
    description  text         NOT NULL DEFAULT '',
    summary      text         NOT NULL DEFAULT '',
    transcript   text         NOT NULL DEFAULT '',
    created_by   uuid         REFERENCES users(id) ON DELETE SET NULL,
    version      integer      NOT NULL DEFAULT 1,
    created_at   timestamptz  NOT NULL DEFAULT now(),
    modified_at  timestamptz  NOT NULL DEFAULT now(),
    deleted_at   timestamptz,
    CONSTRAINT meetings_title_not_blank CHECK (length(btrim(title)) > 0),
    -- An end time only makes sense after a start time on the same day.
    CONSTRAINT meetings_end_needs_start CHECK (end_time IS NULL OR start_time IS NOT NULL),
    CONSTRAINT meetings_end_after_start CHECK (end_time IS NULL OR end_time > start_time)
);
CREATE INDEX meetings_project_date_idx ON meetings (project_id, meeting_date)
    WHERE deleted_at IS NULL;

COMMENT ON TABLE meetings IS
    'Project meetings. meeting_date/start_time/end_time are local to timezone; '
    'the calendar always shows a meeting on meeting_date.';

-- --- 2. Links --------------------------------------------------------------
CREATE TABLE meeting_participants (
    meeting_id uuid NOT NULL REFERENCES meetings(id) ON DELETE CASCADE,
    user_id    uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    PRIMARY KEY (meeting_id, user_id)
);
CREATE INDEX meeting_participants_user_idx ON meeting_participants (user_id);

CREATE TABLE meeting_issues (
    meeting_id uuid NOT NULL REFERENCES meetings(id) ON DELETE CASCADE,
    issue_id   uuid NOT NULL REFERENCES issues(id) ON DELETE CASCADE,
    PRIMARY KEY (meeting_id, issue_id)
);
CREATE INDEX meeting_issues_issue_idx ON meeting_issues (issue_id);

CREATE TABLE meeting_epics (
    meeting_id uuid NOT NULL REFERENCES meetings(id) ON DELETE CASCADE,
    epic_id    uuid NOT NULL REFERENCES epics(id) ON DELETE CASCADE,
    PRIMARY KEY (meeting_id, epic_id)
);
CREATE INDEX meeting_epics_epic_idx ON meeting_epics (epic_id);

CREATE TABLE meeting_customers (
    meeting_id  uuid NOT NULL REFERENCES meetings(id) ON DELETE CASCADE,
    customer_id uuid NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
    PRIMARY KEY (meeting_id, customer_id)
);
CREATE INDEX meeting_customers_customer_idx ON meeting_customers (customer_id);

-- --- 3. Meeting files ------------------------------------------------------
ALTER TABLE attachments ADD COLUMN kind varchar(16);
ALTER TABLE attachments ADD CONSTRAINT attachments_kind_valid CHECK (
    (target_type = 'meeting' AND kind IN ('recording', 'transcript', 'summary', 'other'))
    OR (target_type <> 'meeting' AND kind IS NULL)
);

-- --- 4. Search -------------------------------------------------------------
-- Title plus description, summary and transcript. The body is capped: a
-- tsvector has a 1 MB ceiling and search_index keeps two of them (V026), and
-- a multi-hour transcript would blow through it. The full text stays on the
-- meeting row; only search coverage is bounded.
CREATE FUNCTION sync_search_meeting() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        DELETE FROM search_index WHERE entity_type = 'meeting' AND entity_id = OLD.id;
        RETURN OLD;
    END IF;
    IF NEW.deleted_at IS NOT NULL THEN
        DELETE FROM search_index WHERE entity_type = 'meeting' AND entity_id = NEW.id;
        RETURN NEW;
    END IF;
    INSERT INTO search_index (entity_type, entity_id, project_id, ref, title, body)
    VALUES ('meeting', NEW.id, NEW.project_id, NULL, NEW.title,
            left(concat_ws(E'\n\n', NULLIF(NEW.description, ''), NULLIF(NEW.summary, ''),
                           NULLIF(NEW.transcript, '')), 100000))
    ON CONFLICT (entity_type, entity_id) DO UPDATE
        SET project_id = EXCLUDED.project_id, title = EXCLUDED.title, body = EXCLUDED.body;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER meetings_search AFTER INSERT OR UPDATE OR DELETE ON meetings
    FOR EACH ROW EXECUTE FUNCTION sync_search_meeting();

-- --- 5. Permission backfill ------------------------------------------------
-- Same shape as V007/V019/V020: append-only, idempotent, keyed on behaviour
-- rather than on role slugs (projects may have renamed the seeded roles).
--
-- Meetings are for the team, not for stakeholders: transcripts and
-- recordings are internal. So view is implied by issue.modify (held by
-- developers and up, never by the view-only stakeholder baseline), not by
-- issue.view. Admins can still grant meeting.view to any role by hand.
--
--   meeting.view   <- issue.modify
--   meeting.create <- issue.modify
--   meeting.modify <- issue.modify
--   meeting.delete <- issue.delete   (product owner and up)

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
        ('meeting.view',   'issue.modify'),
        ('meeting.create', 'issue.modify'),
        ('meeting.modify', 'issue.modify'),
        ('meeting.delete', 'issue.delete')
    ) AS p(perm, implied_by)
    WHERE r.is_admin = true
       OR r.permissions ? p.implied_by
    GROUP BY r.id
) AS sub
WHERE roles.id = sub.id
  AND sub.missing <> '[]'::jsonb;
