-- The first schema of state.db. Migrations are append-only: never edit
-- one that has shipped; add the next file instead.
--
-- Times are Unix nanoseconds. Secrets are never stored: sessions, setup
-- links, and DPoP proofs are kept by the SHA-256 of their identifiers.

-- Browser sessions of the web UI (internal/signin).
CREATE TABLE sessions (
	id_hash   BLOB    PRIMARY KEY CHECK (length(id_hash) = 32),
	person    TEXT    NOT NULL DEFAULT '',
	name      TEXT    NOT NULL,
	role      TEXT    NOT NULL,
	tenant    TEXT    NOT NULL DEFAULT '',
	method    TEXT    NOT NULL,
	pending   INTEGER NOT NULL CHECK (pending IN (0, 1)),
	created   INTEGER NOT NULL,
	expires   INTEGER NOT NULL,
	last_seen INTEGER NOT NULL
) STRICT, WITHOUT ROWID;
CREATE INDEX sessions_by_expiry ON sessions (expires);
CREATE INDEX sessions_by_use ON sessions (pending, last_seen);
CREATE INDEX sessions_by_person ON sessions (person) WHERE person != '';

-- Setup links: how a device finds its profile, for 30 minutes.
CREATE TABLE setup_links (
	code_hash BLOB    PRIMARY KEY CHECK (length(code_hash) = 32),
	profile   TEXT    NOT NULL,
	device    TEXT    NOT NULL DEFAULT '',
	expires   INTEGER NOT NULL
) STRICT, WITHOUT ROWID;
CREATE INDEX setup_links_by_expiry ON setup_links (expires);

-- DPoP proof identifiers (jti) each replay cache has accepted, until they
-- could no longer be fresh.
CREATE TABLE dpop_proofs (
	cache    TEXT    NOT NULL,
	jti_hash BLOB    NOT NULL CHECK (length(jti_hash) = 32),
	expires  INTEGER NOT NULL,
	PRIMARY KEY (cache, jti_hash)
) STRICT, WITHOUT ROWID;
CREATE INDEX dpop_proofs_by_expiry ON dpop_proofs (cache, expires);

-- What alerts remember: the devices each scope (a tenant, or '' for the
-- operator) has seen, and the alerts sent recently, so a restart neither
-- reports old devices as new nor repeats an alert within its hour.
CREATE TABLE alert_scopes (
	scope         TEXT    PRIMARY KEY,
	devices_since INTEGER NOT NULL
) STRICT, WITHOUT ROWID;

CREATE TABLE alert_devices (
	scope     TEXT    NOT NULL REFERENCES alert_scopes (scope) ON DELETE CASCADE,
	device    TEXT    NOT NULL,
	last_seen INTEGER NOT NULL,
	PRIMARY KEY (scope, device)
) STRICT, WITHOUT ROWID;
CREATE INDEX alert_devices_by_use ON alert_devices (scope, last_seen);

CREATE TABLE alert_sent (
	scope TEXT    NOT NULL,
	kind  TEXT    NOT NULL,
	key   TEXT    NOT NULL,
	sent  INTEGER NOT NULL,
	PRIMARY KEY (scope, kind, key)
) STRICT, WITHOUT ROWID;
CREATE INDEX alert_sent_by_time ON alert_sent (sent);

-- The audit trail: every change made through the admin API. seq orders
-- events, and pages continue from it.
CREATE TABLE audit (
	seq          INTEGER PRIMARY KEY AUTOINCREMENT,
	time         INTEGER NOT NULL,
	tenant       TEXT    NOT NULL DEFAULT '',
	actor_kind   TEXT    NOT NULL,
	actor_id     TEXT    NOT NULL DEFAULT '',
	actor_name   TEXT    NOT NULL DEFAULT '',
	actor_tenant TEXT    NOT NULL DEFAULT '',
	actor_via    TEXT    NOT NULL DEFAULT '',
	action       TEXT    NOT NULL,
	target_type  TEXT    NOT NULL DEFAULT '',
	target_id    TEXT    NOT NULL DEFAULT '',
	summary      TEXT    NOT NULL DEFAULT '',
	details      TEXT    NOT NULL DEFAULT '{}' CHECK (json_valid(details))
) STRICT;
CREATE INDEX audit_by_tenant ON audit (tenant, seq);
CREATE INDEX audit_by_time ON audit (time);
