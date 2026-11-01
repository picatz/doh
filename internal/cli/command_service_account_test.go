package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/picatz/doh/internal/api"
	"github.com/picatz/doh/internal/serviceaccount"
)

const testSecret = serviceaccount.SecretPrefix + "0123456789abcdef_" + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

func serviceAccountResponses(now time.Time) map[string]any {
	ha := serviceaccount.Account{ID: "haaaaaaaaaaaaaaa", Name: "Home Assistant", Tenant: "smiths", Role: serviceaccount.RoleReader, Keys: []serviceaccount.Key{
		{ID: "0123456789abcdef", Expires: now.Add(90 * 24 * time.Hour), LastUsed: now.Add(-2 * time.Hour)},
		{ID: "fedcba9876543210", Expires: now.Add(-time.Hour)},
	}}
	ci := serviceaccount.Account{ID: "ciiiiiiiiiiiiiii", Name: "CI", Role: serviceaccount.RoleAdmin, Keys: []serviceaccount.Key{
		{ID: "1111111111111111", Expires: now.Add(24 * time.Hour)},
		{ID: "2222222222222222", Expires: now.Add(48 * time.Hour)},
	}}
	newKey := api.NewKey{Account: ha.ID, Key: serviceaccount.Key{ID: "0123456789abcdef", Expires: now.Add(90 * 24 * time.Hour)}, Secret: testSecret}
	return map[string]any{
		"GET /api/v1/service-accounts":                                                api.ServiceAccounts{ServiceAccounts: []serviceaccount.Account{ha, ci}},
		"POST /api/v1/service-accounts":                                               ha,
		"POST /api/v1/service-accounts/haaaaaaaaaaaaaaa/keys":                         newKey,
		"POST /api/v1/service-accounts/haaaaaaaaaaaaaaa/keys/0123456789abcdef/rotate": newKey,
		"DELETE /api/v1/service-accounts/haaaaaaaaaaaaaaa":                            struct{}{},
		"DELETE /api/v1/service-accounts/haaaaaaaaaaaaaaa/keys/fedcba9876543210":      struct{}{},
		"POST /api/v1/service-accounts/ciiiiiiiiiiiiiii/keys/2222222222222222/rotate": newKey,
	}
}

func TestServiceAccountCommands(t *testing.T) {
	now := time.Now()
	responses := serviceAccountResponses(now)

	t.Run("list", func(t *testing.T) {
		out, _, err := runClient(t, newServiceAccountCommand(), responses, "service-account", "list")
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{"Home Assistant", "smiths", "reader", "0123456789abcdef", "(in 90 days)", "2 hours ago", "expired", "CI", "admin", "never"} {
			if !strings.Contains(out, want) {
				t.Errorf("list lacks %q:\n%s", want, out)
			}
		}
		// Each account's name appears once, on its first key's row.
		if n := strings.Count(out, "Home Assistant"); n != 1 {
			t.Errorf("account name listed %d times:\n%s", n, out)
		}
	})

	t.Run("create prints the key once, with how to use it", func(t *testing.T) {
		out, f, err := runClient(t, newServiceAccountCommand(), responses, "sa", "create", "Home Assistant", "--tenant", "smiths", "--expires", "30d")
		if err != nil {
			t.Fatal(err)
		}
		if strings.Count(out, testSecret) != 1 || !strings.Contains(out, "shown only now") || !strings.Contains(out, "a reader for the smiths tenant") {
			t.Errorf("create output:\n%s", out)
		}
		var req api.ServiceAccountRequest
		if err := json.Unmarshal([]byte(f.bodies[0]), &req); err != nil || req.Tenant != "smiths" || req.Role != "reader" {
			t.Errorf("create request = %s", f.bodies[0])
		}
		var key api.KeyRequest
		if err := json.Unmarshal([]byte(f.bodies[1]), &key); err != nil || key.Expires.Sub(now) < 29*24*time.Hour || key.Expires.Sub(now) > 31*24*time.Hour {
			t.Errorf("key request = %s, want 30 days", f.bodies[1])
		}
	})

	t.Run("create --secret-file writes the key privately, never printing it", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "ha.key")
		out, _, err := runClient(t, newServiceAccountCommand(), responses, "sa", "create", "Home Assistant", "--secret-file", path, "--json")
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(out, testSecret) {
			t.Error("the secret was printed despite --secret-file")
		}
		b, err := os.ReadFile(path)
		if err != nil || strings.TrimSpace(string(b)) != testSecret {
			t.Fatalf("secret file = %q, %v", b, err)
		}
		if fi, _ := os.Stat(path); runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
			t.Errorf("secret file mode = %v, want 0600", fi.Mode().Perm())
		}

		// An existing file is never overwritten, and nothing is made.
		_, f, err := runClient(t, newServiceAccountCommand(), responses, "sa", "create", "Other", "--secret-file", path)
		if err == nil || !strings.Contains(err.Error(), "already exists") || len(f.requests) != 0 {
			t.Errorf("create over an existing secret file: %v after %d requests", err, len(f.requests))
		}
	})

	t.Run("rotate picks the only working key", func(t *testing.T) {
		out, f, err := runClient(t, newServiceAccountCommand(), responses, "sa", "key", "rotate", "home assistant", "--grace", "1h")
		if err != nil {
			t.Fatal(err)
		}
		if got := f.requests[len(f.requests)-1]; !strings.HasPrefix(got, "POST /api/v1/service-accounts/haaaaaaaaaaaaaaa/keys/0123456789abcdef/rotate") {
			t.Errorf("rotated %s, want the only unexpired key", got)
		}
		var req api.RotateKeyRequest
		if err := json.Unmarshal([]byte(f.bodies[len(f.bodies)-1]), &req); err != nil || req.PreviousExpires.Sub(now) < 59*time.Minute || req.PreviousExpires.Sub(now) > 61*time.Minute {
			t.Errorf("rotate request = %s, want an hour's grace", f.bodies[len(f.bodies)-1])
		}
		if !strings.Contains(out, "(in 1 hour)") || !strings.Contains(out, testSecret) {
			t.Errorf("rotate output:\n%s", out)
		}
	})

	t.Run("rotate asks which key when there are several", func(t *testing.T) {
		_, _, err := runClient(t, newServiceAccountCommand(), responses, "sa", "key", "rotate", "CI")
		if err == nil || !strings.Contains(err.Error(), "1111111111111111, 2222222222222222") {
			t.Errorf("rotate with two keys: %v", err)
		}
		if _, _, err := runClient(t, newServiceAccountCommand(), responses, "sa", "key", "rotate", "CI", "2222222222222222"); err != nil {
			t.Errorf("rotate a named key: %v", err)
		}
	})

	t.Run("delete and revoke", func(t *testing.T) {
		out, _, err := runClient(t, newServiceAccountCommand(), responses, "sa", "delete", "haaaaaaaaaaaaaaa")
		if err != nil || !strings.Contains(out, "its 2 keys no longer work") {
			t.Errorf("delete = %q, %v", out, err)
		}
		out, _, err = runClient(t, newServiceAccountCommand(), responses, "sa", "key", "revoke", "Home Assistant", "fedcba9876543210")
		if err != nil || !strings.Contains(out, "Revoked key fedcba9876543210") {
			t.Errorf("revoke = %q, %v", out, err)
		}
		if _, _, err := runClient(t, newServiceAccountCommand(), responses, "sa", "delete", "nobody"); err == nil || !strings.Contains(err.Error(), "doh service-account list") {
			t.Errorf("delete an unknown account: %v", err)
		}
	})

	t.Run("bad flags fail before any request", func(t *testing.T) {
		for _, args := range [][]string{
			{"sa", "create", "x", "--expires", "0d"},
			{"sa", "create", "x", "--expires", "forever"},
			{"sa", "key", "add", "x", "--expires", "-5h"},
			{"sa", "key", "rotate", "x", "--grace", "200h"},
		} {
			_, f, err := runClient(t, newServiceAccountCommand(), responses, args...)
			if err == nil || len(f.requests) != 0 {
				t.Errorf("%q: %v after %d requests", args, err, len(f.requests))
			}
		}
	})
}

func TestLifetime(t *testing.T) {
	for in, want := range map[string]time.Duration{"90d": 90 * 24 * time.Hour, "12h": 12 * time.Hour, " 1d ": 24 * time.Hour, "90m": 90 * time.Minute} {
		if got, err := lifetime(in); err != nil || got != want {
			t.Errorf("lifetime(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	for _, in := range []string{"", "d", "0d", "-1d", "1.5d", "0", "-1h", "soon"} {
		if got, err := lifetime(in); err == nil {
			t.Errorf("lifetime(%q) = %v, want an error", in, got)
		}
	}
}

func TestUntil(t *testing.T) {
	now := time.Now()
	for d, want := range map[time.Duration]string{
		10 * time.Second:                   "in 1 minute",
		90*24*time.Hour - time.Millisecond: "in 90 days",
		24*time.Hour - time.Millisecond:    "in 24 hours",
		59*time.Minute + 50*time.Second:    "in 1 hour",
		47*time.Hour + 50*time.Minute:      "in 2 days",
		366*24*time.Hour - 3*time.Hour:     "in 366 days",
		45 * time.Minute:                   "in 45 minutes",
		time.Hour + 20*time.Minute:         "in 1 hour",
	} {
		if got := until(now.Add(d), now); got != want {
			t.Errorf("until(+%v) = %q, want %q", d, got, want)
		}
	}
}
