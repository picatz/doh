package cli

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/picatz/doh/internal/audit"
)

func TestAuditCommand(t *testing.T) {
	now := time.Now().UTC()
	page := audit.Page{Events: []audit.Event{
		{
			ID: "evt_2", Time: now.Add(-time.Hour), Tenant: "smiths", Action: "profile.updated",
			Actor:   audit.Actor{Kind: audit.ActorPerson, ID: "p1", Name: "Kent"},
			Target:  audit.Target{Type: "profile", ID: "kids"},
			Summary: "Unblocked TikTok (tiktok) in profile kids",
			Details: map[string]string{"profile": "kids", "services.removed": "tiktok"},
		},
		{
			ID: "evt_1", Time: now.Add(-2 * time.Hour), Action: "service_account.key.revoked",
			Actor:   audit.Actor{Kind: audit.ActorServiceAccount, ID: "sa1", Name: "Deploys", Via: "key 3f2a"},
			Summary: "Revoked key 3f2a of service account Deploys",
		},
	}}
	responses := map[string]any{"GET /api/v1/audit": page}

	out, f, err := runClient(t, newAuditCommand(), responses, "audit", "--actor", "Kent", "--action", "profile", "--before", "2026-11-02T00:00:00Z", "--tenant", "smiths", "-n", "10")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := f.requests[0], "GET /api/v1/audit?action=profile&actor=Kent&before=2026-11-02T00%3A00%3A00Z&limit=10&tenant=smiths"; got != want {
		t.Errorf("request = %s, want %s", got, want)
	}
	for _, want := range []string{"Kent  Unblocked TikTok (tiktok) in profile kids [tenant smiths]", "services.removed: tiktok", "1 hour ago", "Deploys  Revoked key", "by key 3f2a"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}

	// -n bounds what's printed; --json prints JSON lines.
	out, _, err = runClient(t, newAuditCommand(), responses, "audit", "-n", "1", "--json")
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	var e audit.Event
	if len(lines) != 1 || json.Unmarshal([]byte(lines[0]), &e) != nil || e.Details["services.removed"] != "tiktok" {
		t.Errorf("--json -n 1 = %q", out)
	}

	if _, _, err := runClient(t, newAuditCommand(), responses, "audit", "-n", "0"); err == nil {
		t.Error("-n 0 was accepted")
	}
}
