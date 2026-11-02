package serve

import (
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/picatz/doh/internal/policy"
)

// chromePath returns a Chrome or Chromium to test the UI with: $DOH_CHROME,
// or the first one on the PATH.
func chromePath() string {
	if p := os.Getenv("DOH_CHROME"); p != "" {
		return p
	}
	for _, name := range []string{"google-chrome", "google-chrome-stable", "chromium", "chromium-browser"} {
		if p, err := exec.LookPath(name); err == nil {
			return p
		}
	}
	return ""
}

// TestLayout checks the web UI's layout in a real browser, on a real
// server, for every view at phone, tablet, and desktop widths in both
// themes: nothing scrolls sideways or sticks out, every control is big
// enough to tap, and nothing logs an error. It needs Chrome and Node, and
// is skipped without them; CI has both.
//
// The data is chosen to be hard to lay out: long names, a tenant, a
// service account, and an alert destination with a long URL.
func TestLayout(t *testing.T) {
	if testing.Short() {
		t.Skip("drives a browser")
	}
	chrome, node := chromePath(), ""
	if p, err := exec.LookPath("node"); err == nil {
		node = p
	}
	if chrome == "" || node == "" {
		t.Skip("needs Chrome (or $DOH_CHROME) and Node")
	}

	up, _ := startZone(t, nil)
	s, dataDir := newPolicyServer(t, up, &policy.Policy{
		Tenants: []policy.Tenant{{ID: "smiths", Name: "The Smith family's house by the lake"}},
		Profiles: []policy.Profile{
			{ID: "default"},
			{ID: "kids", Name: "Kids' tablets, the living-room TV, and the games console"},
			{ID: "smiths-kids", Name: "Smith kids", Tenant: "smiths"},
		},
	})
	adminURL := startAdmin(t, s)
	admin := apiClient{t, adminURL, token(t, dataDir, AdminTokenFile)}

	if resp, body := admin.do(http.MethodPost, "/api/v1/service-accounts", `{"name":"Home Assistant on the Raspberry Pi in the garage","role":"reader"}`); resp.StatusCode != http.StatusCreated {
		t.Fatalf("creating a service account = %d %s", resp.StatusCode, body)
	}
	if resp, body := admin.do(http.MethodPost, "/api/v1/alerts/destinations",
		`{"type":"webhook","name":"Home automation","url":"http://127.0.0.1:9/hooks/doh/a-rather-long-path/that-goes-on-and-on?with=query&and=more"}`); resp.StatusCode != http.StatusCreated {
		t.Fatalf("adding an alert destination = %d %s", resp.StatusCode, body)
	}

	link := newSigninLink(t, admin, "admin")
	out, err := exec.CommandContext(t.Context(), node, filepath.Join("..", "webui", "testdata", "layout.mjs"), chrome, link.URL).Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			t.Fatalf("layout.mjs: %v\n%s", err, ee.Stderr)
		}
		t.Fatalf("layout.mjs: %v", err)
	}
	var problems []string
	if err := json.Unmarshal(out, &problems); err != nil {
		t.Fatalf("layout.mjs printed %q: %v", out, err)
	}
	for _, p := range problems {
		t.Error(p)
	}
}
