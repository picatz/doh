package cli

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/picatz/doh/internal/api"
	"github.com/picatz/doh/internal/signin"
	"github.com/spf13/cobra"
)

func TestUICommand(t *testing.T) {
	expires := time.Now().Add(5 * time.Minute)
	responses := map[string]any{
		"POST /api/v1/signin-links": api.SigninLink{URL: "http://localhost:9090/#signin=c0de", Expires: expires, PasskeyRequired: true},
	}

	// The link goes to standard output alone, for scripts; the note to
	// standard error.
	f := &fakeAPI{t: t, responses: responses}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	root := &cobra.Command{Use: "doh", SilenceErrors: true}
	root.AddCommand(newUICommand())
	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{"ui", "--reader", "--addr", srv.URL, "--token", "t0ken"})
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}

	if got := stdout.String(); got != "http://localhost:9090/#signin=c0de\n" {
		t.Errorf("stdout = %q", got)
	}
	if note := stderr.String(); !strings.Contains(note, "Single-use; expires in 5 minutes.") || !strings.Contains(note, "passkey") {
		t.Errorf("stderr = %q", note)
	}
	if len(f.bodies) != 1 || !strings.Contains(f.bodies[0], `"role":"reader"`) {
		t.Errorf("request bodies = %q, want a reader link", f.bodies)
	}
	if strings.Contains(stdout.String()+stderr.String(), "t0ken") {
		t.Error("the API token was printed")
	}

	out, _, err := runClient(t, newUICommand(), responses, "ui", "--json")
	var link api.SigninLink
	if err != nil || json.Unmarshal([]byte(out), &link) != nil || link.URL == "" {
		t.Errorf("--json = %q, %v", out, err)
	}
}

func TestPeopleCommands(t *testing.T) {
	now := time.Now()
	people := api.People{People: []signin.Person{
		{ID: "QUxJQ0U", Name: "Alice", Role: signin.RoleAdmin, Passkeys: []signin.Passkey{
			{ID: "a1", Name: "MacBook", Synced: true, LastUsed: now.Add(-3 * time.Hour)},
			{ID: "a2", Name: "YubiKey", LastUsed: now.Add(-30 * time.Hour)},
		}},
		{ID: "Qk9C", Name: "Bob", Role: signin.RoleReader},
		{ID: "Qk9CMg", Name: "bob", Role: signin.RoleReader},
	}}
	responses := map[string]any{
		"GET /api/v1/people":                        people,
		"DELETE /api/v1/people/QUxJQ0U":             struct{}{},
		"DELETE /api/v1/people/QUxJQ0U/passkeys/a2": struct{}{},
	}

	t.Run("list", func(t *testing.T) {
		out, _, err := runClient(t, newPeopleCommand(), responses, "people", "list")
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{"NAME", "Alice", "admin", "MacBook (synced), YubiKey", "3 hours ago", "Bob", "never"} {
			if !strings.Contains(out, want) {
				t.Errorf("list output lacks %q:\n%s", want, out)
			}
		}
	})

	t.Run("list empty", func(t *testing.T) {
		out, _, err := runClient(t, newPeopleCommand(), map[string]any{"GET /api/v1/people": api.People{People: []signin.Person{}}}, "people", "list")
		if err != nil || !strings.Contains(out, "doh ui") {
			t.Errorf("empty list = %q, %v", out, err)
		}
	})

	t.Run("remove by name", func(t *testing.T) {
		out, f, err := runClient(t, newPeopleCommand(), responses, "people", "remove", "alice")
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(out, "Removed Alice and their 2 passkeys.") || f.requests[len(f.requests)-1] != "DELETE /api/v1/people/QUxJQ0U?" {
			t.Errorf("out = %q, requests = %q", out, f.requests)
		}
	})

	t.Run("remove passkey by name", func(t *testing.T) {
		out, f, err := runClient(t, newPeopleCommand(), responses, "people", "remove-passkey", "QUxJQ0U", "yubikey")
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(out, "Removed Alice's passkey YubiKey.") || f.requests[len(f.requests)-1] != "DELETE /api/v1/people/QUxJQ0U/passkeys/a2?" {
			t.Errorf("out = %q, requests = %q", out, f.requests)
		}
	})

	t.Run("ambiguous name", func(t *testing.T) {
		_, f, err := runClient(t, newPeopleCommand(), responses, "people", "remove", "Bob")
		if err == nil || !strings.Contains(err.Error(), "use an ID") {
			t.Errorf("err = %v, want an ambiguity error", err)
		}
		for _, r := range f.requests {
			if strings.HasPrefix(r, "DELETE") {
				t.Errorf("deleted despite ambiguity: %s", r)
			}
		}
	})

	t.Run("unknown", func(t *testing.T) {
		if _, _, err := runClient(t, newPeopleCommand(), responses, "people", "remove-passkey", "Alice", "Phone"); err == nil {
			t.Error("removed an unknown passkey")
		}
	})
}

func TestAgo(t *testing.T) {
	now := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	for d, want := range map[time.Duration]string{
		10 * time.Second: "just now",
		time.Minute:      "1 minute ago",
		90 * time.Minute: "1 hour ago",
		47 * time.Hour:   "47 hours ago",
		72 * time.Hour:   "3 days ago",
	} {
		if got := ago(now.Add(-d), now); got != want {
			t.Errorf("ago(%v) = %q, want %q", d, got, want)
		}
	}
	if got := ago(time.Time{}, now); got != "never" {
		t.Errorf("ago(zero) = %q", got)
	}
}
