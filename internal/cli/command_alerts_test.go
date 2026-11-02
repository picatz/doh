package cli

import (
	"strings"
	"testing"
	"time"

	"github.com/picatz/doh/internal/alerts"
	"github.com/picatz/doh/internal/api"
)

const testWebhookSecret = alerts.SecretPrefix + "MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw"

func alertsResponses(now time.Time) map[string]any {
	view := api.Alerts{
		Tenant:         "smiths",
		Settings:       alerts.Settings{Kinds: []alerts.Kind{alerts.KindThreat, alerts.KindNewDevice}, QuietHours: &alerts.QuietHours{Start: "22:00", End: "07:00"}, TimeZone: "America/New_York"},
		AvailableKinds: alerts.KindsFor("smiths"),
		Destinations: []alerts.Destination{
			{ID: "0123456789abcdef", Type: alerts.Ntfy, URL: "https://ntfy.sh/smiths", Name: "Phones", LastSuccess: now.Add(-2 * time.Hour)},
			{ID: "fedcba9876543210", Type: alerts.Webhook, URL: "https://hooks.example/doh", LastFailure: now.Add(-time.Hour), LastError: "the destination answered 500 Internal Server Error"},
		},
		Deliveries: []alerts.Delivery{
			{Time: now.Add(-time.Hour), Kind: alerts.KindThreat, Summary: "Threat blocked on kids-ipad", Destination: "0123456789abcdef", OK: true, Attempts: 2},
		},
	}
	return map[string]any{
		"GET /api/v1/alerts":                                  view,
		"PATCH /api/v1/alerts":                                view,
		"POST /api/v1/alerts/destinations":                    api.NewAlertDestination{Destination: alerts.Destination{ID: "fedcba9876543210", Type: alerts.Webhook, URL: "https://hooks.example/doh"}, Secret: testWebhookSecret},
		"DELETE /api/v1/alerts/destinations/fedcba9876543210": struct{}{},
		"POST /api/v1/alerts/test": api.AlertTest{Deliveries: []alerts.Delivery{
			{Destination: "0123456789abcdef", OK: true, Attempts: 1},
			{Destination: "fedcba9876543210", Error: "the destination answered 404 Not Found", Attempts: 1},
		}},
	}
}

func TestAlertsCommands(t *testing.T) {
	responses := alertsResponses(time.Now())

	t.Run("show", func(t *testing.T) {
		out, f, err := runClient(t, newAlertsCommand(), responses, "alerts", "show", "--tenant", "smiths")
		if err != nil {
			t.Fatal(err)
		}
		if f.requests[0] != "GET /api/v1/alerts?tenant=smiths" {
			t.Errorf("request = %s", f.requests[0])
		}
		for _, want := range []string{"the smiths tenant", "threat, new-device (off: failing)", "22:00 to 07:00, America/New_York", "Phones", "2 hours ago", "500 Internal Server Error", "Threat blocked on kids-ipad", "after 2 tries"} {
			if !strings.Contains(out, want) {
				t.Errorf("show lacks %q:\n%s", want, out)
			}
		}
	})

	t.Run("set", func(t *testing.T) {
		_, f, err := runClient(t, newAlertsCommand(), responses, "alerts", "set", "kinds=threat,new-device", "quiet=22:00-07:00", "tz=America/New_York")
		if err != nil {
			t.Fatal(err)
		}
		if got := f.bodies[0]; got != `{"kinds":["threat","new-device"],"quiet_hours":{"start":"22:00","end":"07:00"},"time_zone":"America/New_York"}` {
			t.Errorf("patch = %s", got)
		}
	})

	t.Run("set kinds=all asks which kinds there are", func(t *testing.T) {
		_, f, err := runClient(t, newAlertsCommand(), responses, "alerts", "set", "kinds=all", "quiet=off")
		if err != nil {
			t.Fatal(err)
		}
		if len(f.requests) != 2 || f.bodies[1] != `{"kinds":["threat","new-device","failing"],"quiet_hours":null}` {
			t.Errorf("requests %q, patch %s", f.requests, f.bodies[len(f.bodies)-1])
		}
	})

	t.Run("set refuses what it can't send", func(t *testing.T) {
		for _, args := range [][]string{{"kinds=everything"}, {"quiet=22:00"}, {"nokey"}, {"volume=11"}, {"tz=UTC", "tz=UTC"}} {
			if _, f, err := runClient(t, newAlertsCommand(), responses, append([]string{"alerts", "set"}, args...)...); err == nil || len(f.requests) != 0 {
				t.Errorf("set %q: %v after %d requests", args, err, len(f.requests))
			}
		}
	})

	t.Run("add-webhook shows the secret once", func(t *testing.T) {
		out, f, err := runClient(t, newAlertsCommand(), responses, "alerts", "add-webhook", "https://hooks.example/doh", "--name", "Hub")
		if err != nil {
			t.Fatal(err)
		}
		if strings.Count(out, testWebhookSecret) != 1 || !strings.Contains(out, "shown only now") {
			t.Errorf("output:\n%s", out)
		}
		if f.bodies[0] != `{"type":"webhook","url":"https://hooks.example/doh","name":"Hub"}` {
			t.Errorf("request = %s", f.bodies[0])
		}
	})

	t.Run("add-ntfy", func(t *testing.T) {
		_, f, err := runClient(t, newAlertsCommand(), responses, "alerts", "add-ntfy", "https://ntfy.sh/smiths")
		if err != nil {
			t.Fatal(err)
		}
		if f.bodies[0] != `{"type":"ntfy","url":"https://ntfy.sh/smiths"}` {
			t.Errorf("request = %s", f.bodies[0])
		}
	})

	t.Run("remove", func(t *testing.T) {
		out, _, err := runClient(t, newAlertsCommand(), responses, "alerts", "remove", "fedcba9876543210")
		if err != nil || !strings.Contains(out, "Removed fedcba9876543210") {
			t.Errorf("remove = %q, %v", out, err)
		}
	})

	t.Run("test reports each destination, failing if any failed", func(t *testing.T) {
		out, _, err := runClient(t, newAlertsCommand(), responses, "alerts", "test")
		if err == nil || !strings.Contains(err.Error(), "1 of 2") {
			t.Errorf("test err = %v", err)
		}
		if !strings.Contains(out, "0123456789abcdef  ✓ delivered") || !strings.Contains(out, "fedcba9876543210  ✗ the destination answered 404") {
			t.Errorf("test output:\n%s", out)
		}
	})
}
