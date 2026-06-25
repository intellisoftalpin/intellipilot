-- ===========================================================================
-- Epic board: dates, cover image, and the per-project column → status mapping.
--
-- All additions are nullable / defaulted so existing installs keep working:
--   * epics gain optional start_date / end_date (mirroring issues' dates).
--   * epics gain a cover image stored in the object-storage backend, modelled
--     exactly like user avatars (kind + storage key + mime + updated-at for
--     cache-busting). 'none' means render the colour swatch fallback.
--   * projects gain epic_board_settings (jsonb): which issue_status taxonomy
--     items map to the board's "In Progress" column. "Done" is derived from
--     is_closed; "All" is the catch-all remainder. Empty object = unconfigured.
-- ===========================================================================

ALTER TABLE epics
    ADD COLUMN start_date              date,
    ADD COLUMN end_date                date,
    ADD COLUMN cover_image_kind        varchar(8)   NOT NULL DEFAULT 'none',
    ADD COLUMN cover_image_storage_key text,
    ADD COLUMN cover_image_mime        varchar(64),
    ADD COLUMN cover_image_updated_at  timestamptz;

ALTER TABLE epics
    ADD CONSTRAINT epics_cover_image_kind_valid
        CHECK (cover_image_kind IN ('none', 'image'));

ALTER TABLE projects
    ADD COLUMN epic_board_settings jsonb NOT NULL DEFAULT '{}';
