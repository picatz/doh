package serve

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/picatz/doh/internal/policy"
)

// hostRequest sends GET path to the admin listener at base, naming host
// in its Host header, with token if it's set.
func hostRequest(t *testing.T, base, host, path, token string) (*http.Response, []byte) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, base+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = host
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return send(t, req)
}

func TestHostGuard_RefusesRebindingHosts(t *testing.T) {
	up, _ := startZone(t, nil)
	s, dataDir := newPolicyServer(t, up, &policy.Policy{Profiles: []policy.Profile{{ID: "default"}}}, func(c *Config) {
		c.Hostname = "dns.example.com"
		c.Admin.Hosts = []string{"doh.example.net", "*.corp.example"}
	})
	base := startAdmin(t, s)
	port := base[strings.LastIndex(base, ":"):]
	admin := token(t, dataDir, AdminTokenFile)

	// Names an attacker on the internet could point at the listener,
	// with or without its port: each refused, saying what to set.
	for _, host := range []string{
		"attacker.example",
		"attacker.example" + port,
		"localhost.attacker.example",
		"127.0.0.1.nip.io",
		"192-168-1-10.sslip.io",
		"lan.attacker.example",
		"local.attacker.example",
		"nas.local.attacker.example",
		"doh.lan.evil.example",
		"pi.home.arpa.evil.example",
		"ts.net.attacker.example",
		"dns.example.com.attacker.example",
		"sub.dns.example.com", // the hostname exactly, not its profiles' names
		"doh.example.net.evil.example",
		"corp.example", // *.corp.example is its subdomains only
		"xcorp.example",
		"attacker.example.",
		"ATTACKER.EXAMPLE",
	} {
		resp, body := hostRequest(t, base, host, "/api/v1/status", admin)
		want, _ := hostOf(host)
		if resp.StatusCode != http.StatusMisdirectedRequest || !strings.Contains(string(body), "--admin-host "+want) {
			t.Errorf("Host %q = %d %s, want 421 naming --admin-host %s", host, resp.StatusCode, body, want)
		}
		// Whatever the path: the UI, sign-in, metrics, and profiling.
		for _, path := range []string{"/", "/auth/session", MetricsPath, PprofPath} {
			if resp, _ := hostRequest(t, base, host, path, ""); resp.StatusCode != http.StatusMisdirectedRequest {
				t.Errorf("Host %q, %s = %d, want 421", host, path, resp.StatusCode)
			}
		}
	}

	// Each class of host it answers to.
	for _, host := range []string{
		"127.0.0.1" + port,
		"[::1]" + port,
		"192.168.1.10",
		"[fd7a:115c:a1e0::1]",
		"localhost" + port,
		"LOCALHOST.",
		"doh.localhost",
		"doh",
		"nas.local",
		"router.home.arpa",
		"doh.internal",
		"doh.lan",
		"pi.localdomain",
		"box.home",
		"doh.tail1234.ts.net",
		"dns.example.com", // --hostname
		"doh.example.net", // --admin-host
		"DOH.EXAMPLE.NET.",
		"admin.corp.example", // --admin-host *.corp.example
		"",
	} {
		if resp, body := hostRequest(t, base, host, "/api/v1/status", admin); resp.StatusCode != http.StatusOK {
			t.Errorf("Host %q = %d %s, want 200", host, resp.StatusCode, body)
		}
	}

	// Load balancers' health checks name whatever they like.
	if resp, _ := hostRequest(t, base, "lb.attacker.example", HealthPath, ""); resp.StatusCode != http.StatusOK {
		t.Errorf("health check at another host = %d, want 200", resp.StatusCode)
	}
}

// Hosts of --admin-origin and --acme-domain are allowed too.
func TestHostGuard_ConfiguredHosts(t *testing.T) {
	c := Config{
		Admin: AdminConfig{Origins: []string{"https://admin.dns.example.com:8443"}, Hosts: []string{"*.example.org", "EXTRA.example."}},
		TLS:   TLSConfig{ACME: ACMEConfig{Domains: []string{"doh.example.com", "dot.example.com"}}},
	}
	s := &Server{adminHosts: adminHostPatterns(c.withDefaults())}
	for host, want := range map[string]bool{
		"admin.dns.example.com": true,
		"doh.example.com":       true, // the first ACME domain, and so the hostname
		"dot.example.com":       true,
		"a.example.org":         true,
		"a.b.example.org":       true,
		"extra.example":         true,
		"example.org":           false,
		"dns.example.com":       false,
		"evil.example":          false,
	} {
		if got := s.configuredHost(host); got != want {
			t.Errorf("configuredHost(%q) = %v, want %v", host, got, want)
		}
	}
}

func TestHostGuard_ValidatesAdminHosts(t *testing.T) {
	for _, bad := range []string{"https://admin.example.com", "admin.example.com:9090", "admin.example.com/ui", "*", "*.", "a*.example.com", "user@admin.example.com", ""} {
		c := Config{Plaintext: true, Admin: AdminConfig{Hosts: []string{bad}}}
		if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "admin host") {
			t.Errorf("--admin-host %q: %v, want refused", bad, err)
		}
	}
	c := Config{Plaintext: true, Admin: AdminConfig{Hosts: []string{"admin.example.com", "*.example.net", "ADMIN.example.org."}}}
	if err := c.Validate(); err != nil {
		t.Errorf("valid hosts: %v", err)
	}
}

// On a private, loopback listener, profiling is open only at a loopback
// host: a local name someone on the network rebinds to 127.0.0.1 gets
// past the host check, but not to the open endpoints.
func TestHostGuard_PrivateProfilingNeedsLoopbackHost(t *testing.T) {
	up, _ := startZone(t, nil)
	s, dataDir := newPolicyServer(t, up, nil, func(c *Config) { c.Admin.Hosts = []string{"doh.example.net"} })
	base := startAdmin(t, s)
	admin := token(t, dataDir, AdminTokenFile)
	u, _ := url.Parse(base)

	for _, host := range []string{u.Host, "localhost:" + u.Port(), "doh.localhost", "doh.example.net"} {
		if resp, _ := hostRequest(t, base, host, VarsPath, ""); resp.StatusCode != http.StatusOK {
			t.Errorf("%s at %q = %d, want 200 without credentials", VarsPath, host, resp.StatusCode)
		}
	}
	for _, host := range []string{"nas.local", "doh", "doh.lan", "192.168.1.10"} {
		if resp, _ := hostRequest(t, base, host, VarsPath, ""); resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s at %q = %d, want 401 without credentials", VarsPath, host, resp.StatusCode)
		}
		if resp, _ := hostRequest(t, base, host, VarsPath, admin); resp.StatusCode != http.StatusOK {
			t.Errorf("%s at %q with the operator's token = %d, want 200", VarsPath, host, resp.StatusCode)
		}
	}
}

func FuzzHostOf(f *testing.F) {
	for _, s := range []string{"localhost:9090", "[::1]:9090", "[::1]", "a.example.", "", "a:b:c", "[", "x/y"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		host, ok := hostOf(raw)
		if !ok {
			return
		}
		if strings.ContainsAny(host, "/@ \\") || len(host) > 255 || host != strings.ToLower(host) {
			t.Errorf("hostOf(%q) = %q", raw, host)
		}
	})
}
