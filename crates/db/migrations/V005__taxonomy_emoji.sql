-- Optional emoji glyph for taxonomy items (used for issue types and
-- priorities so they are identifiable by a small logo, e.g. 🐞 for a bug).
-- Empty string means "no emoji". Existing installs keep working unchanged.
ALTER TABLE taxonomy_items
    ADD COLUMN emoji varchar(16) NOT NULL DEFAULT '';
