-- ===========================================================================
-- User profiles & avatars
--
-- Adds to the users table:
--   * avatar: one of 'default' (initials), 'image' (uploaded, incl. animated
--     GIF — stored in the object-storage backend, key on the row), or 'emoji'.
--   * motto: a short personal tagline.
--   * daily mood: an emoji + <=16-char status that auto-expires — `mood_set_on`
--     records the day it was set; the read layer blanks it once the day passes.
-- ===========================================================================

ALTER TABLE users
    ADD COLUMN avatar_kind        varchar(8)    NOT NULL DEFAULT 'default',
    ADD COLUMN avatar_storage_key text,
    ADD COLUMN avatar_mime        varchar(64),
    ADD COLUMN avatar_emoji       text,
    ADD COLUMN avatar_updated_at  timestamptz,
    ADD COLUMN motto              varchar(140)  NOT NULL DEFAULT '',
    ADD COLUMN mood_emoji         text,
    ADD COLUMN mood_text          varchar(16)   NOT NULL DEFAULT '',
    ADD COLUMN mood_set_on        date;

ALTER TABLE users
    ADD CONSTRAINT users_avatar_kind_valid
        CHECK (avatar_kind IN ('default', 'image', 'emoji'));
