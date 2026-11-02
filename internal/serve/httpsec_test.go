package serve

import (
	"net/http"
	"strings"
	"testing"

	"github.com/picatz/doh/internal/httpsec"
	"github.com/picatz/doh/internal/policy"
)

// TestAdmin_SecurityHeaders checks every kind of response on the admin
// listener carries the defenses httpsec describes: pages their policy
// with Trusted Types, and everything else the data policy, which renders
// nothing even if opened directly.
func TestAdmin_SecurityHeaders(t *testing.T) {
	up, _ := startZone(t, nil)
	s, dataDir := newPolicyServer(t, up, &policy.Policy{Profiles: []policy.Profile{{ID: "default"}}})
	adminURL := startAdmin(t, s)
	admin := apiClient{t, adminURL, token(t, dataDir, AdminTokenFile)}

	for _, tt := range []struct {
		path string
		page bool
	}{
		{"/", true},
		{"/ui/app.js", true},
		{"/sw.js", true},
		{"/ui/manifest.webmanifest", true},
		{"/alerts/confirm/ABCDEFGHJK", true},
		{"/api/v1/status", false},
		{"/api/v1/no-such-thing", false},
		{"/healthz", false},
		{"/metrics", false},
		{"/auth/session", false},
	} {
		resp, _ := admin.do(http.MethodGet, tt.path, "")
		h := resp.Header
		for k, want := range map[string]string{
			"X-Content-Type-Options":       "nosniff",
			"Referrer-Policy":              "no-referrer",
			"Cross-Origin-Resource-Policy": "same-origin",
			"Permissions-Policy":           httpsec.PermissionsPolicy,
		} {
			if got := h.Get(k); got != want {
				t.Errorf("%s: %s = %q, want %q", tt.path, k, got, want)
			}
		}
		csp := h.Get("Content-Security-Policy")
		switch {
		case tt.page && (!strings.Contains(csp, "require-trusted-types-for 'script'") || !strings.Contains(csp, "frame-ancestors 'none'")):
			t.Errorf("%s: CSP = %q, want the UI's, with Trusted Types", tt.path, csp)
		case !tt.page && csp != httpsec.DataCSP:
			t.Errorf("%s: CSP = %q, want %q", tt.path, csp, httpsec.DataCSP)
		}
	}
}
