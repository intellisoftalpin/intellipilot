-- Release badge color, shared by all versions under a release.
ALTER TABLE releases ADD COLUMN color varchar(16) NOT NULL DEFAULT '';
