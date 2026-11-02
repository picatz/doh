-- The devices the server has answered, by profile, device name, and
-- address: what the web UI's setup guide and its "Connected" rest on.
-- Written in batches, a few times a minute, and bounded by count when
-- written, keeping the most recently seen.
CREATE TABLE seen_devices (
	profile    TEXT    NOT NULL,
	device     TEXT    NOT NULL DEFAULT '',
	client     TEXT    NOT NULL DEFAULT '',
	tenant     TEXT    NOT NULL DEFAULT '',
	transport  TEXT    NOT NULL DEFAULT '',
	first_seen INTEGER NOT NULL,
	last_seen  INTEGER NOT NULL,
	PRIMARY KEY (profile, device, client)
) STRICT, WITHOUT ROWID;
CREATE INDEX seen_devices_by_use ON seen_devices (last_seen);
