package cli

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/picatz/doh/internal/api"
	"github.com/picatz/doh/internal/policy"
	"github.com/spf13/cobra"
)

func TestTenantCommands(t *testing.T) {
	responses := map[string]any{
		"GET /api/v1/tenants": api.Tenants{Tenants: []policy.Tenant{
			{ID: "smiths", Name: "The Smiths", Networks: []string{"192.168.10.0/24"}},
			{ID: "jones", Networks: []string{"192.168.20.0/24", "fd20::/64"}, CustomLists: true, MaxProfiles: 5},
		}},
		"GET /api/v1/profiles": api.Profiles{Profiles: []policy.Profile{
			{ID: "default"}, {ID: "smith-kids", Tenant: "smiths"}, {ID: "smith-tv", Tenant: "smiths"},
		}},
		"POST /api/v1/tenants":         policy.Tenant{ID: "browns", Name: "The Browns"},
		"PATCH /api/v1/tenants/smiths": policy.Tenant{ID: "smiths"},
		"DELETE /api/v1/tenants/jones": struct{}{},
	}

	t.Run("list", func(t *testing.T) {
		out, _, err := runClient(t, newTenantCommand(), responses, "tenant", "list")
		if err != nil {
			t.Fatal(err)
		}
		lines := strings.Split(strings.TrimSpace(out), "\n")
		if len(lines) != 3 || !strings.Contains(lines[0], "CUSTOM LISTS") {
			t.Fatalf("list output:\n%s", out)
		}
		for _, want := range [][]string{
			{"smiths", "The Smiths", "192.168.10.0/24", "2", "no", "20"},
			{"jones", "-", "192.168.20.0/24,fd20::/64", "0", "yes", "5"},
		} {
			row := lines[1]
			if want[0] == "jones" {
				row = lines[2]
			}
			if got := strings.Fields(row); strings.Join(got, " ") != strings.Join(want, " ") {
				t.Errorf("row = %q, want %q", got, want)
			}
		}
	})

	t.Run("create", func(t *testing.T) {
		out, f, err := runClient(t, newTenantCommand(), responses, "tenant", "create", "browns",
			"--name", "The Browns", "--network", "192.168.30.0/24", "--network", "fd30::/64", "--custom-lists", "--max-profiles", "3")
		if err != nil {
			t.Fatal(err)
		}
		var sent policy.Tenant
		if err := json.Unmarshal([]byte(f.bodies[0]), &sent); err != nil {
			t.Fatal(err)
		}
		if sent.ID != "browns" || sent.Name != "The Browns" || len(sent.Networks) != 2 || !sent.CustomLists || sent.MaxProfiles != 3 {
			t.Errorf("sent %+v", sent)
		}
		if !strings.Contains(out, "doh tenant invite browns") {
			t.Errorf("create output = %q, want the next step", out)
		}
	})

	t.Run("set", func(t *testing.T) {
		_, f, err := runClient(t, newTenantCommand(), responses, "tenant", "set", "smiths", "networks=192.168.10.0/24", "custom_lists=true", "max_profiles=4")
		if err != nil {
			t.Fatal(err)
		}
		// networks is always a list, even with one value.
		if want := `{"custom_lists":true,"max_profiles":4,"networks":["192.168.10.0/24"]}`; strings.TrimSpace(f.bodies[0]) != want {
			t.Errorf("patch = %s, want %s", f.bodies[0], want)
		}
	})

	t.Run("delete", func(t *testing.T) {
		out, f, err := runClient(t, newTenantCommand(), responses, "tenant", "delete", "jones")
		if err != nil || f.requests[0] != "DELETE /api/v1/tenants/jones?" || !strings.Contains(out, "signed out its people") {
			t.Errorf("delete = %q, %v, %v", out, f.requests, err)
		}
	})

	t.Run("delete refused", func(t *testing.T) {
		_, _, err := runClient(t, newTenantCommand(), map[string]any{}, "tenant", "delete", "smiths")
		if err == nil {
			t.Error("delete of a missing endpoint succeeded")
		}
	})

	t.Run("no tenants", func(t *testing.T) {
		out, _, err := runClient(t, newTenantCommand(), map[string]any{"GET /api/v1/tenants": api.Tenants{Tenants: []policy.Tenant{}}}, "tenant", "list")
		if err != nil || !strings.Contains(out, "doh tenant create") {
			t.Errorf("empty list = %q, %v", out, err)
		}
	})
}

func TestTenantInvite(t *testing.T) {
	responses := map[string]any{
		"POST /api/v1/signin-links": api.SigninLink{URL: "http://localhost:9090/#signin=c0de", Expires: time.Now().Add(5 * time.Minute)},
	}
	for _, args := range [][]string{
		{"tenant", "invite", "smiths", "--reader"},
		{"ui", "--tenant", "smiths", "--reader"},
	} {
		f := &fakeAPI{t: t, responses: responses}
		srv := httptest.NewServer(f)
		t.Cleanup(srv.Close)
		root := &cobra.Command{Use: "doh", SilenceErrors: true}
		root.AddCommand(newTenantCommand(), newUICommand())
		var stdout, stderr bytes.Buffer
		root.SetOut(&stdout)
		root.SetErr(&stderr)
		root.SetArgs(append(args, "--addr", srv.URL, "--token", "t0ken"))
		if err := root.Execute(); err != nil {
			t.Fatal(err)
		}

		if stdout.String() != "http://localhost:9090/#signin=c0de\n" {
			t.Errorf("%v stdout = %q, want the link alone", args, stdout.String())
		}
		if !strings.Contains(stderr.String(), `Signs in to tenant "smiths" as a reader.`) {
			t.Errorf("%v stderr = %q", args, stderr.String())
		}
		var req api.SigninLinkRequest
		if err := json.Unmarshal([]byte(f.bodies[0]), &req); err != nil || req.Tenant != "smiths" || req.Role != "reader" {
			t.Errorf("%v request = %s", args, f.bodies[0])
		}
	}
}

func TestProfileTenants(t *testing.T) {
	responses := map[string]any{
		"GET /api/v1/profiles":  api.Profiles{Profiles: []policy.Profile{{ID: "default"}, {ID: "smith-kids", Tenant: "smiths"}}},
		"POST /api/v1/profiles": policy.Profile{ID: "smith-tv", Tenant: "smiths"},
	}

	out, _, err := runClient(t, newProfileCommand(), responses, "profile", "list")
	if err != nil || !strings.Contains(out, "TENANT") || !strings.Contains(out, "smiths") {
		t.Errorf("list with tenants = %q, %v", out, err)
	}
	plain, _, _ := runClient(t, newProfileCommand(), map[string]any{"GET /api/v1/profiles": api.Profiles{Profiles: []policy.Profile{{ID: "default"}}}}, "profile", "list")
	if strings.Contains(plain, "TENANT") {
		t.Errorf("list without tenants shows a TENANT column:\n%s", plain)
	}

	_, f, err := runClient(t, newProfileCommand(), responses, "profile", "create", "smith-tv", "--tenant", "smiths")
	if err != nil || !strings.Contains(f.bodies[0], `"tenant":"smiths"`) {
		t.Errorf("create --tenant sent %q, %v", f.bodies, err)
	}
}
