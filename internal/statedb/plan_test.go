package statedb

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/picatz/doh/internal/audit"
)

// TestAudit_EveryFilterUsesAnIndex checks, with EXPLAIN QUERY PLAN, that
// each way the audit trail is filtered walks an index in seq order, never
// the whole table, and never sorts, except an actor filter, which matches
// an ID or a name and sorts only that actor's events.
func TestAudit_EveryFilterUsesAnIndex(t *testing.T) {
	db, _ := openTest(t)
	ctx := t.Context()
	// Rows enough for the planner to choose as it would on a server that
	// has kept a while of changes: first as servers run, without
	// statistics, then with them, as after ANALYZE.
	store := db.Audit()
	for i := range 300 {
		tenant := []string{"", "smiths", "joneses"}[i%3]
		action := []string{"profile.updated", "alerts.destination.added", "service_account.key.rotated", "person.deleted"}[i%4]
		if err := store.Record(ctx, audit.Event{Time: time.Unix(int64(1e9+i), 0), Tenant: tenant, Action: action,
			Actor: audit.Actor{Kind: audit.ActorPerson, ID: "p" + string(rune('a'+i%7)), Name: "Person " + string(rune('A'+i%7))}}); err != nil {
			t.Fatal(err)
		}
	}
	token := audit.EncodePageToken(150)
	for _, analyzed := range []bool{false, true} {
		if analyzed {
			if _, err := db.exec(ctx, "ANALYZE"); err != nil {
				t.Fatal(err)
			}
		}
		for _, tc := range []struct {
			name  string
			f     audit.Filter
			index string // the index the plan must use, or for an actor, one of
			// "|"-separated ones: the planner may walk the tenant's events in
			// order when the actor's are a large share of them
			sorts bool // whether it may sort
		}{
			{"a tenant's", audit.Filter{Tenant: "smiths"}, "audit_by_tenant", false},
			{"a tenant's, a later page", audit.Filter{Tenant: "smiths", PageToken: token}, "audit_by_tenant", false},
			{"a tenant's, before a time", audit.Filter{Tenant: "smiths", Before: time.Unix(1e9+100, 0)}, "audit_by_tenant", false},
			{"a tenant's profiles", audit.Filter{Tenant: "smiths", Action: "profile"}, "audit_by_tenant_resource", false},
			{"a tenant's key rotations, a later page", audit.Filter{Tenant: "smiths", Action: "service_account.key.rotated", PageToken: token}, "audit_by_tenant_resource", false},
			{"everyone's alerts", audit.Filter{AllTenants: true, Action: "alerts"}, "audit_by_resource", false},
			{"a tenant's, by one person", audit.Filter{Tenant: "smiths", Actor: "pa"}, "audit_by_tenant_actor_id|audit_by_tenant_actor_name|audit_by_tenant", true},
			{"everyone's, by one person", audit.Filter{AllTenants: true, Actor: "Person A"}, "audit_by_actor_id|audit_by_actor_name", true},
		} {
			t.Run(fmt.Sprintf("%s, statistics %v", tc.name, analyzed), func(t *testing.T) {
				query, args, err := listQuery(tc.f)
				if err != nil {
					t.Fatal(err)
				}
				rows, err := db.readRows(ctx, "EXPLAIN QUERY PLAN "+query, args...)
				if err != nil {
					t.Fatal(err)
				}
				defer rows.Close()
				var plan []string
				for rows.Next() {
					var id, parent, unused int
					var detail string
					if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
						t.Fatal(err)
					}
					plan = append(plan, detail)
				}
				got := strings.Join(plan, "\n")
				uses := false
				for _, index := range strings.Split(tc.index, "|") {
					uses = uses || strings.Contains(got, "USING INDEX "+index+" ") || strings.Contains(got, "USING COVERING INDEX "+index+" ")
				}
				if !uses {
					t.Errorf("plan doesn't use %s:\n%s", tc.index, got)
				}
				for _, line := range plan {
					if strings.HasPrefix(line, "SCAN audit") && !strings.Contains(line, "INDEX") {
						t.Errorf("plan scans the whole table:\n%s", got)
					}
				}
				if sorts := strings.Contains(got, "TEMP B-TREE"); sorts && !tc.sorts {
					t.Errorf("plan sorts instead of walking seq in order:\n%s", got)
				}
			})
		}
	}
}

// TestAudit_ActionFilterIsExactOrUnder checks the resource column narrows
// an action filter without widening or narrowing what it matches.
func TestAudit_ActionFilterIsExactOrUnder(t *testing.T) {
	db, _ := openTest(t)
	ctx := t.Context()
	store := db.Audit()
	for i, action := range []string{"profile.updated", "profile", "profiles.updated", "profile-x.created", "service_account.key.added", "service_account.keys"} {
		if err := store.Record(ctx, audit.Event{Time: time.Unix(int64(1e9+i), 0), Action: action, Actor: audit.Actor{Kind: audit.ActorToken}}); err != nil {
			t.Fatal(err)
		}
	}
	for filter, want := range map[string]string{
		"profile":                 "profile.updated profile",
		"profile.updated":         "profile.updated",
		"service_account.key":     "service_account.key.added",
		"service_account":         "service_account.key.added service_account.keys",
		"service_account.keys.no": "",
	} {
		page, err := store.List(ctx, audit.Filter{Action: filter})
		if err != nil {
			t.Fatal(err)
		}
		var got []string
		for i := len(page.Events) - 1; i >= 0; i-- {
			got = append(got, page.Events[i].Action)
		}
		if strings.Join(got, " ") != want {
			t.Errorf("action %q matches %q, want %q", filter, got, want)
		}
	}
}
