package serve

import (
	"cmp"
	"context"
	"log/slog"
	"maps"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/picatz/doh/internal/audit"
	"github.com/picatz/doh/internal/policy"
	"github.com/picatz/doh/internal/services"
)

// DefaultAuditRetention is how long the audit trail is kept by default.
const DefaultAuditRetention = 365 * 24 * time.Hour

// change is a change made through the admin API, for the server's log and
// its audit trail. It never holds a secret.
type change struct {
	// action is what was done, dotted from the resource down, such as
	// "profile.updated", and message the log line's, after "admin: ".
	action, message string

	// tenant is whose resource changed: "" for the operator's.
	tenant string

	target  audit.Target
	summary string
	details map[string]string
}

// details returns key-value pairs as details, leaving out empty values.
func details(kv ...string) map[string]string {
	d := make(map[string]string, len(kv)/2)
	for i := 0; i+1 < len(kv); i += 2 {
		if kv[i+1] != "" {
			d[kv[i]] = kv[i+1]
		}
	}
	return d
}

// audit logs c, and who made it, and records it in the audit trail, if
// there is one. Failing to record it is logged, not returned: the change
// is already made.
func (s *Server) audit(r *http.Request, c change) {
	s.auditBy(r, principalOf(r), c)
}

// auditBy is audit for a change made by who, for requests made without
// signing in, such as an alert address's confirmation link.
func (s *Server) auditBy(r *http.Request, who principal, c change) {
	attrs := make([]slog.Attr, 0, len(c.details)+3)
	for _, k := range slices.Sorted(maps.Keys(c.details)) {
		attrs = append(attrs, slog.String(k, c.details[k]))
	}
	if c.tenant != who.tenant {
		attrs = append(attrs, slog.String("for_tenant", c.tenant))
	}
	attrs = append(attrs, slog.String("by", who.by))
	if who.tenant != "" {
		attrs = append(attrs, slog.String("tenant", who.tenant))
	}
	s.logger.LogAttrs(r.Context(), slog.LevelInfo, "admin: "+c.message, attrs...)

	if s.auditLog == nil {
		return
	}
	e := audit.Event{
		Time:    time.Now().UTC(),
		Tenant:  c.tenant,
		Actor:   who.actor,
		Action:  c.action,
		Target:  c.target,
		Summary: c.summary,
		Details: c.details,
	}
	// Recording outlives a request that's gone, so a change is recorded
	// even if its client hung up.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 5*time.Second)
	defer cancel()
	if err := s.auditLog.Record(ctx, e); err != nil {
		s.logger.ErrorContext(ctx, "admin: recording an audit event", slog.String("action", c.action), slog.Any("error", err))
	}
}

// auditPolicy records how a change to the policy changed it: an event
// for each profile and tenant created, deleted, or changed, and one for
// the rest.
func (s *Server) auditPolicy(r *http.Request, before, after *policy.Policy) {
	for _, c := range policyChanges(before, after) {
		s.audit(r, c)
	}
}

// policyChanges describes how after differs from before.
func policyChanges(before, after *policy.Policy) []change {
	var out []change

	profiles := func(p *policy.Policy) map[string]*policy.Profile {
		m := make(map[string]*policy.Profile, len(p.Profiles))
		for i := range p.Profiles {
			m[p.Profiles[i].ID] = &p.Profiles[i]
		}
		return m
	}
	was, is := profiles(before), profiles(after)
	for _, pr := range after.Profiles {
		old, ok := was[pr.ID]
		switch {
		case !ok:
			out = append(out, change{
				action: "profile.created", message: "profile created", tenant: pr.Tenant,
				target:  audit.Target{Type: "profile", ID: pr.ID},
				summary: "Created profile " + profileLabel(&pr),
				details: details("profile", pr.ID, "name", pr.Name),
			})
		default:
			d := audit.Diff(old, &pr)
			if len(d) == 0 {
				continue
			}
			d["profile"] = pr.ID
			c := change{
				action: "profile.updated", message: "profile changed", tenant: pr.Tenant,
				target:  audit.Target{Type: "profile", ID: pr.ID},
				summary: profileSummary(&pr, d),
				details: d,
			}
			if old.Tenant != pr.Tenant {
				// Moved between tenants: both see it.
				moved := c
				moved.tenant = old.Tenant
				out = append(out, moved)
			}
			out = append(out, c)
		}
	}
	for _, pr := range before.Profiles {
		if _, ok := is[pr.ID]; !ok {
			out = append(out, change{
				action: "profile.deleted", message: "profile deleted", tenant: pr.Tenant,
				target:  audit.Target{Type: "profile", ID: pr.ID},
				summary: "Deleted profile " + profileLabel(&pr),
				details: details("profile", pr.ID, "name", pr.Name),
			})
		}
	}

	tenants := func(p *policy.Policy) map[string]*policy.Tenant {
		m := make(map[string]*policy.Tenant, len(p.Tenants))
		for i := range p.Tenants {
			m[p.Tenants[i].ID] = &p.Tenants[i]
		}
		return m
	}
	wasT, isT := tenants(before), tenants(after)
	for _, t := range after.Tenants {
		old, ok := wasT[t.ID]
		target := audit.Target{Type: "tenant", ID: t.ID}
		switch {
		case !ok:
			out = append(out, change{action: "tenant.created", message: "tenant created", tenant: t.ID, target: target,
				summary: "Created tenant " + t.ID, details: details("tenant", t.ID, "name", t.Name)})
		default:
			if d := audit.Diff(old, &t); len(d) > 0 {
				d["tenant"] = t.ID
				out = append(out, change{action: "tenant.updated", message: "tenant changed", tenant: t.ID, target: target,
					summary: "Changed tenant " + t.ID + ": " + strings.Join(slices.Sorted(maps.Keys(d)), ", "), details: d})
			}
		}
	}
	for _, t := range before.Tenants {
		if _, ok := isT[t.ID]; !ok {
			out = append(out, change{action: "tenant.deleted", message: "tenant deleted", tenant: t.ID,
				target: audit.Target{Type: "tenant", ID: t.ID}, summary: "Deleted tenant " + t.ID, details: details("tenant", t.ID)})
		}
	}

	// Anything else, such as the policy's own settings, is the
	// operator's.
	rest := func(p *policy.Policy) policy.Policy {
		c := *p
		c.Profiles, c.Tenants = nil, nil
		return c
	}
	if d := audit.Diff(rest(before), rest(after)); len(d) > 0 {
		out = append(out, change{action: "policy.updated", message: "policy changed",
			target: audit.Target{Type: "policy"}, summary: "Changed the policy: " + strings.Join(slices.Sorted(maps.Keys(d)), ", "), details: d})
	}
	return out
}

// profileLabel names a profile for people.
func profileLabel(pr *policy.Profile) string {
	if pr.Name != "" && pr.Name != pr.ID {
		return pr.Name + " (" + pr.ID + ")"
	}
	return pr.ID
}

// profileSummary describes a profile's change, d, for people: what was
// allowed, denied, or blocked, by name, and which settings changed.
func profileSummary(pr *policy.Profile, d map[string]string) string {
	var parts []string
	phrase := func(key, verb string, name func(string) string) {
		if v, ok := d[key]; ok {
			items := strings.Split(v, ", ")
			if name != nil {
				for i, it := range items {
					items[i] = name(it)
				}
			}
			parts = append(parts, verb+" "+strings.Join(items, ", "))
		}
	}
	app := func(id string) string {
		if svc, ok := services.Lookup(id); ok && svc.Name != "" {
			return svc.Name + " (" + id + ")"
		}
		return id
	}
	phrase("services.added", "blocked", app)
	phrase("services.removed", "unblocked", app)
	phrase("allow.added", "allowed", nil)
	phrase("allow.removed", "stopped allowing", nil)
	phrase("deny.added", "denied", nil)
	phrase("deny.removed", "stopped denying", nil)
	phrase("lists.added", "added list", nil)
	phrase("lists.removed", "removed list", nil)
	phrase("block_tlds.added", "blocked TLD", nil)
	phrase("block_tlds.removed", "unblocked TLD", nil)
	described := []string{"profile", "services.added", "services.removed", "allow.added", "allow.removed",
		"deny.added", "deny.removed", "lists.added", "lists.removed", "block_tlds.added", "block_tlds.removed"}
	var other []string
	for _, k := range slices.Sorted(maps.Keys(d)) {
		if !slices.Contains(described, k) {
			other = append(other, k)
		}
	}
	if len(other) > 0 {
		parts = append(parts, "changed "+strings.Join(other, ", "))
	}
	if len(parts) == 0 {
		return "Changed profile " + profileLabel(pr)
	}
	s := strings.Join(parts, "; ")
	return strings.ToUpper(s[:1]) + s[1:] + " in profile " + profileLabel(pr)
}

// apiAudit lists the audit trail: a tenant's own, or for the operator,
// everyone's, or one tenant's with ?tenant=.
func (s *Server) apiAudit(w http.ResponseWriter, r *http.Request) {
	who := principalOf(r)
	if who.role != roleAdmin {
		writeError(w, http.StatusForbidden, "the audit trail takes an admin")
		return
	}
	if s.auditLog == nil {
		writeError(w, http.StatusNotFound, "the audit trail needs a data directory (--data-dir)")
		return
	}
	q := r.URL.Query()
	f, err := audit.ParseFilter(q)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	switch tenant := q.Get("tenant"); {
	case !who.operator():
		// Tenants only ever see their own; asking for another's shows
		// nothing, as if it didn't exist.
		f.Tenant = who.tenant
		if q.Has("tenant") && tenant != who.tenant {
			writeJSON(w, http.StatusOK, audit.Page{Events: []audit.Event{}})
			return
		}
	case q.Has("tenant"):
		f.Tenant = tenant
	default:
		f.AllTenants = true
	}
	page, err := s.auditLog.List(r.Context(), f)
	if err != nil {
		s.logger.ErrorContext(r.Context(), "admin: reading the audit trail", slog.Any("error", err))
		writeError(w, http.StatusInternalServerError, "reading the audit trail failed")
		return
	}
	writeJSON(w, http.StatusOK, page)
}

// actorOf describes a principal for the audit trail.
func actorOf(kind audit.ActorKind, id, name, tenant, via string) audit.Actor {
	return audit.Actor{Kind: kind, ID: id, Name: cmp.Or(name, id), Tenant: tenant, Via: via}
}
