package cli

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/picatz/doh/internal/api"
	"github.com/picatz/doh/internal/blocklist"
	"github.com/picatz/doh/internal/policy"
	"github.com/picatz/doh/internal/querylog"
	"github.com/spf13/cobra"
)

// fakeAPI records requests and answers with canned responses by
// "METHOD path".
type fakeAPI struct {
	t         *testing.T
	responses map[string]any
	requests  []string
	bodies    []string
}

func (f *fakeAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer t0ken" {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(api.Error{Error: "invalid token"})
		return
	}
	key := r.Method + " " + r.URL.EscapedPath()
	f.requests = append(f.requests, key+"?"+r.URL.RawQuery)
	body, _ := io.ReadAll(r.Body)
	f.bodies = append(f.bodies, string(body))

	resp, ok := f.responses[key]
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(api.Error{Error: "no such endpoint: " + key})
		return
	}
	if b, ok := resp.([]byte); ok {
		w.Header().Set("Content-Type", api.MobileConfigType)
		w.Write(b)
		return
	}
	if s, ok := resp.(string); ok {
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, s)
		return
	}
	json.NewEncoder(w).Encode(resp)
}

// runClient runs cmd against a fake API serving responses.
func runClient(t *testing.T, cmd *cobra.Command, responses map[string]any, args ...string) (string, *fakeAPI, error) {
	t.Helper()
	f := &fakeAPI{t: t, responses: responses}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)

	root := &cobra.Command{Use: "doh", SilenceErrors: true}
	root.AddCommand(cmd)
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(io.Discard)
	root.SetArgs(append(args, "--addr", srv.URL, "--token", "t0ken"))
	err := root.Execute()
	return out.String(), f, err
}

func TestMergePatch(t *testing.T) {
	tests := []struct {
		args    []string
		want    string
		wantErr bool
	}{
		{[]string{"security.newly_registered=true", "safe_search=true"}, `{"safe_search":true,"security":{"newly_registered":true}}`, false},
		{[]string{"lists=threat-intel,gambling"}, `{"lists":["threat-intel","gambling"]}`, false},
		{[]string{"lists=threat-intel"}, `{"lists":["threat-intel"]}`, false},
		{[]string{"allow="}, `{"allow":null}`, false},
		{[]string{"security.newly_registered_days=14", "name=Kids"}, `{"name":"Kids","security":{"newly_registered_days":14}}`, false},
		{[]string{"block_response=null"}, `{"block_response":"null"}`, false},
		{[]string{"block_response="}, `{"block_response":null}`, false},
		{[]string{"name=a=b"}, `{"name":"a=b"}`, false},
		{[]string{"nokey"}, "", true},
		{[]string{"=x"}, "", true},
		{[]string{"a..b=1"}, "", true},
		{[]string{"name=a", "name=b"}, "", true},
		{[]string{"security=1", "security.bypass=true"}, "", true},
	}
	for _, tt := range tests {
		got, err := mergePatch(tt.args, profileListKeys)
		if (err != nil) != tt.wantErr {
			t.Errorf("mergePatch(%q) err = %v", tt.args, err)
			continue
		}
		if tt.wantErr {
			continue
		}
		b, _ := json.Marshal(got)
		if string(b) != tt.want {
			t.Errorf("mergePatch(%q) = %s, want %s", tt.args, b, tt.want)
		}
	}
}

func TestProfileSetCommand(t *testing.T) {
	out, f, err := runClient(t, newProfileCommand(), map[string]any{
		"PATCH /api/v1/profiles/kids": policy.Profile{ID: "kids", SafeSearch: true, Security: policy.Security{NewlyRegistered: true}},
	}, "profile", "set", "kids", "safe_search=true", "security.newly_registered=true")
	if err != nil {
		t.Fatal(err)
	}
	if f.bodies[0] != `{"safe_search":true,"security":{"newly_registered":true}}` {
		t.Errorf("patch = %s", f.bodies[0])
	}
	for _, want := range []string{"safe_search", "on", "newly_registered", "younger than 30 days"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}

func TestProfileListAndShowCommands(t *testing.T) {
	profiles := []policy.Profile{
		{ID: "default", Name: "Default", Lists: []string{"threat-intel"}, Security: policy.Security{Rebinding: true}},
		{ID: "tv", Devices: []policy.Device{{Name: "stick", Addrs: []string{"192.168.1.50"}}}},
	}
	out, _, err := runClient(t, newProfileCommand(), map[string]any{
		"GET /api/v1/profiles": api.Profiles{Profiles: profiles},
	}, "profile", "list")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"ID", "default", "threat-intel", "rebinding", "tv"} {
		if !strings.Contains(out, want) {
			t.Errorf("list output missing %q:\n%s", want, out)
		}
	}

	out, _, err = runClient(t, newProfileCommand(), map[string]any{
		"GET /api/v1/profiles/tv": profiles[1],
	}, "profile", "show", "tv", "--json")
	if err != nil {
		t.Fatal(err)
	}
	var got policy.Profile
	if err := json.Unmarshal([]byte(out), &got); err != nil || got.ID != "tv" {
		t.Errorf("show --json = %s (%v)", out, err)
	}
}

func TestProfileCreateDeleteCommands(t *testing.T) {
	_, f, err := runClient(t, newProfileCommand(), map[string]any{
		"POST /api/v1/profiles": policy.Profile{ID: "kids", Name: "Kids"},
	}, "profile", "create", "kids", "--name", "Kids")
	if err != nil {
		t.Fatal(err)
	}
	var p policy.Profile
	if err := json.Unmarshal([]byte(f.bodies[0]), &p); err != nil || p.ID != "kids" || p.Name != "Kids" {
		t.Errorf("create body = %s", f.bodies[0])
	}

	_, f, err = runClient(t, newProfileCommand(), map[string]any{
		"DELETE /api/v1/profiles/kids": nil,
	}, "profile", "delete", "kids")
	if err != nil || f.requests[0] != "DELETE /api/v1/profiles/kids?" {
		t.Errorf("delete: %v %v", f.requests, err)
	}
}

func TestAllowDenyCommands(t *testing.T) {
	resp := map[string]any{
		"POST /api/v1/profiles/default/allow":            policy.Profile{ID: "default"},
		"DELETE /api/v1/profiles/kids/allow/gef.sh":      policy.Profile{ID: "kids"},
		"POST /api/v1/profiles/kids/deny":                policy.Profile{ID: "kids"},
		"DELETE /api/v1/profiles/default/deny/x.example": policy.Profile{ID: "default"},
	}
	tests := []struct {
		cmd  *cobra.Command
		args []string
		want []string
	}{
		{newDomainCommand("allow"), []string{"allow", "gef.sh", "a.example"}, []string{"POST /api/v1/profiles/default/allow?", "POST /api/v1/profiles/default/allow?"}},
		{newDomainCommand("allow"), []string{"allow", "gef.sh", "--profile", "kids", "--remove"}, []string{"DELETE /api/v1/profiles/kids/allow/gef.sh?"}},
		{newDomainCommand("deny"), []string{"deny", "y.example", "--profile", "kids"}, []string{"POST /api/v1/profiles/kids/deny?"}},
		{newDomainCommand("deny"), []string{"deny", "x.example", "--remove"}, []string{"DELETE /api/v1/profiles/default/deny/x.example?"}},
	}
	for _, tt := range tests {
		out, f, err := runClient(t, tt.cmd, resp, tt.args...)
		if err != nil {
			t.Errorf("%q: %v", tt.args, err)
			continue
		}
		if !reflect.DeepEqual(f.requests, tt.want) {
			t.Errorf("%q requests = %q, want %q", tt.args, f.requests, tt.want)
		}
		if !strings.Contains(out, tt.args[1]) {
			t.Errorf("%q output = %q", tt.args, out)
		}
	}

	_, f, _ := runClient(t, newDomainCommand("allow"), resp, "allow", "gef.sh")
	if f.bodies[0] != `{"domain":"gef.sh"}` {
		t.Errorf("allow body = %s", f.bodies[0])
	}
}

func TestLogCommand(t *testing.T) {
	now := time.Date(2026, 11, 1, 12, 0, 0, 0, time.Local)
	page := querylog.Page{Entries: []querylog.Entry{
		{ID: 2, Time: now, Device: "tv", Client: "192.168.1.50", Status: querylog.StatusBlocked, Type: "A", Name: "ads.example", Reason: "list", Source: "threat-intel"},
		{ID: 1, Time: now.Add(-time.Second), Client: "192.168.1.2", Status: querylog.StatusAllowed, Type: "AAAA", Name: "example.com"},
	}}
	out, f, err := runClient(t, newLogCommand(), map[string]any{"GET /api/v1/logs": page}, "log", "--blocked", "-n", "5", "-q", "ads")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(f.requests[0], "status=blocked") || !strings.Contains(f.requests[0], "limit=5") || !strings.Contains(f.requests[0], "q=ads") {
		t.Errorf("request = %s", f.requests[0])
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 3 || !strings.HasPrefix(lines[0], "TIME") {
		t.Fatalf("output:\n%s", out)
	}
	// Oldest first, like tail.
	if !strings.Contains(lines[1], "example.com") || !strings.Contains(lines[2], "ads.example") || !strings.Contains(lines[2], "list (threat-intel)") || !strings.Contains(lines[2], "tv") {
		t.Errorf("output:\n%s", out)
	}
	if strings.Contains(out, "\x1b[") {
		t.Error("colored output when not a terminal")
	}

	if _, _, err := runClient(t, newLogCommand(), nil, "log", "--blocked", "--status", "allowed"); err == nil {
		t.Error("conflicting --blocked and --status accepted")
	}
}

func TestLogCommandFollowJSON(t *testing.T) {
	stream := "event: entry\ndata: {\"id\":3,\"name\":\"live.example\",\"status\":\"allowed\"}\n\n"
	out, f, err := runClient(t, newLogCommand(), map[string]any{
		"GET /api/v1/logs":        querylog.Page{Entries: []querylog.Entry{{ID: 1, Name: "old.example"}}},
		"GET /api/v1/logs/stream": stream,
	}, "log", "-f", "--json", "--profile", "kids")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(f.requests[1], "/logs/stream?profile=kids") {
		t.Errorf("requests = %q", f.requests)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 2 || !strings.Contains(lines[0], "old.example") || !strings.Contains(lines[1], "live.example") {
		t.Errorf("output:\n%s", out)
	}
}

func TestExplainCommand(t *testing.T) {
	out, f, err := runClient(t, newExplainCommand(), map[string]any{
		"GET /api/v1/explain": api.Explanation{
			Name: "ads.example", Type: "A", Profile: "default",
			Decision: api.Decision{Action: api.ActionBlock, Reason: "list", Rule: "ads.example", Source: "threat-intel"},
			Checks: []api.Check{
				{Check: "allow", Result: api.CheckPass},
				{Check: "list", Result: api.CheckMatch, Detail: "blocked by threat-intel"},
				{Check: "rebinding", Result: api.CheckSkip, Detail: "not resolved"},
			},
			Rcode: "NXDOMAIN",
		},
	}, "explain", "ads.example", "--client", "192.168.1.5")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(f.requests[0], "client=192.168.1.5") || !strings.Contains(f.requests[0], "type=A") {
		t.Errorf("request = %s", f.requests[0])
	}
	for _, want := range []string{"ads.example A: BLOCK by list (ads.example from threat-intel)", "✓ allow", "✗ list", "– rebinding", "Answer: NXDOMAIN", "profile default"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}

func TestStatusCommand(t *testing.T) {
	status := api.Status{
		Version:   "v1.0.0",
		Started:   time.Now().Add(-time.Hour),
		Listeners: map[string]string{"dns": "[::]:53", "admin": "127.0.0.1:9090"},
		Upstreams: []string{"https://dns.example/dns-query"},
		Policy:    api.PolicyStatus{Source: "https://central.example/api/v1/policy", ReadOnly: true, Profiles: 3},
		Lists: []blocklist.ListStatus{
			{Name: "threat-intel", Rules: 1234, Loaded: time.Now()},
			{Name: "broken", Error: "404 Not Found"},
		},
		QueryLog: api.QueryLogStatus{Enabled: true, Entries: 42},
		Queries:  map[string]int64{"total": 100, "blocked": 7},
	}
	out, _, err := runClient(t, newStatusCommand(), map[string]any{"GET /api/v1/status": status}, "status")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"v1.0.0", "Uptime", "1h0m0s", "Listener (dns)", "(read-only)", "Profiles", "3", "threat-intel", "1234", "error: 404 Not Found", "100 total, 7 blocked", "42 entries"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}

func TestClientCommand_Unauthorized(t *testing.T) {
	f := &fakeAPI{t: t}
	srv := httptest.NewServer(f)
	defer srv.Close()

	root := &cobra.Command{Use: "doh", SilenceErrors: true}
	root.AddCommand(newStatusCommand())
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	root.SetArgs([]string{"status", "--addr", srv.URL, "--token", "wrong"})
	if err := root.Execute(); err == nil || !strings.Contains(err.Error(), "401") {
		t.Errorf("err = %v, want 401", err)
	}
}

func TestClientFlags_TokenFile(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "admin.token")

	f := &clientFlags{addr: "http://127.0.0.1:9090", tokenFile: file}
	if _, err := f.client(); err == nil || !strings.Contains(err.Error(), "--data-dir") {
		t.Errorf("missing token file err = %v", err)
	}

	if err := os.WriteFile(file, []byte("  abc\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := f.client()
	if err != nil || c.Token != "abc" {
		t.Errorf("token = %q, err = %v", c.Token, err)
	}

	// An explicit token wins, and the file isn't needed.
	f = &clientFlags{token: "explicit", tokenFile: filepath.Join(dir, "missing")}
	if c, err := f.client(); err != nil || c.Token != "explicit" {
		t.Errorf("explicit token = %v, %v", c, err)
	}
}

func TestClientCommandsRegistered(t *testing.T) {
	for _, name := range []string{"status", "ui", "profile", "allow", "deny", "log", "explain", "doctor", "setup", "tenant", "people", "service-account", "services", "schedule"} {
		cmd, _, err := New().Find([]string{name})
		if err != nil || cmd.Name() != name {
			t.Errorf("command %q not registered: %v", name, err)
		}
	}
}
