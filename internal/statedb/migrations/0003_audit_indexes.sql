-- Indexes for each way the audit trail is filtered, each ending in seq so
-- a page walks its events newest first and stops at the page's end, as
-- far back as it is: by tenant (0001's audit_by_tenant), by the action's
-- resource (its first dotted part, "profile" of "profile.updated", as a
-- generated column, so "profile" and "profile.updated" both use it), and
-- by the actor's ID or name, within a tenant or across all of them.
ALTER TABLE audit ADD COLUMN resource TEXT
	GENERATED ALWAYS AS (substr(action, 1, instr(action || '.', '.') - 1)) VIRTUAL;
CREATE INDEX audit_by_tenant_resource ON audit (tenant, resource, seq);
CREATE INDEX audit_by_resource ON audit (resource, seq);
CREATE INDEX audit_by_tenant_actor_id ON audit (tenant, actor_id, seq);
CREATE INDEX audit_by_tenant_actor_name ON audit (tenant, actor_name, seq);
CREATE INDEX audit_by_actor_id ON audit (actor_id, seq);
CREATE INDEX audit_by_actor_name ON audit (actor_name, seq);
