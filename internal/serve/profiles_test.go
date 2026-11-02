package serve

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/miekg/dns"
	"github.com/picatz/doh/internal/api"
	"github.com/picatz/doh/internal/policy"
	"github.com/picatz/doh/internal/querylog"
	"github.com/picatz/doh/pkg/doh"
)

// startZone starts a UDP resolver answering from records, keyed by
// lower-case name and type such as "evil.example. A", and with 192.0.2.1
// for other A queries. It counts the queries it gets.
func startZone(t *testing.T, records map[string]string) (string, *atomic.Int64) {
	t.Helper()

	var count atomic.Int64
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	server := &dns.Server{PacketConn: conn, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		count.Add(1)
		q := req.Question[0]
		resp := new(dns.Msg).SetReply(req)
		if s, ok := records[strings.ToLower(q.Name)+" "+dns.TypeToString[q.Qtype]]; ok {
			rr, err := dns.NewRR(s)
			if err != nil {
				panic(err)
			}
			resp.Answer = append(resp.Answer, rr)
		} else if q.Qtype == dns.TypeA {
			rr, _ := dns.NewRR(q.Name + " 60 IN A 192.0.2.1")
			resp.Answer = append(resp.Answer, rr)
		}
		_ = w.WriteMsg(resp)
	})}

	ready := make(chan struct{})
	server.NotifyStartedFunc = func() { close(ready) }
	go func() { _ = server.ActivateAndServe() }()
	<-ready
	t.Cleanup(func() { _ = server.Shutdown() })

	return conn.LocalAddr().String(), &count
}

// writePolicy writes p as the policy file in dataDir.
func writePolicy(t *testing.T, dataDir string, p *policy.Policy) {
	t.Helper()
	b, err := policy.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, PolicyFile), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// newPolicyServer returns a server with profiles from p, forwarding to
// upstream.
func newPolicyServer(t *testing.T, upstream string, p *policy.Policy, configure ...func(*Config)) (*Server, string) {
	t.Helper()

	dataDir := t.TempDir()
	if p != nil {
		writePolicy(t, dataDir, p)
	}

	config := Config{
		Plaintext: true,
		Upstreams: []string{upstream},
		DataDir:   dataDir,
		Blocklist: BlocklistConfig{CacheDir: t.TempDir()},
		RDAP:      RDAPConfig{BootstrapURL: "http://127.0.0.1:1/unreachable"},
	}
	for _, f := range configure {
		f(&config)
	}

	s, err := New(config, testLogger(t))
	if err != nil {
		t.Fatal(err)
	}
	// Tests never look the server's own name up for real; ones that need
	// its addresses set their own.
	s.selfAddrs.lookup = func(context.Context, string) ([]netip.Addr, error) {
		return nil, errors.New("no lookups in tests")
	}
	t.Cleanup(func() { s.Close() })
	return s, dataDir
}

// dohQuery sends a DoH query to path on the server at addr.
func dohQuery(t *testing.T, addr, path, name string, qtype uint16) (*dns.Msg, error) {
	t.Helper()
	m := new(dns.Msg).SetQuestion(dns.Fqdn(name), qtype)
	m.SetEdns0(1232, false)
	return doh.Query(t.Context(), &http.Client{Transport: &http.Transport{}}, "http://"+addr+path, m)
}

func TestServer_DefaultPolicyCreated(t *testing.T) {
	up, _ := startZone(t, nil)
	s, dataDir := newPolicyServer(t, up, nil)

	b, err := os.ReadFile(filepath.Join(dataDir, PolicyFile))
	if err != nil {
		t.Fatal(err)
	}
	p, err := policy.Unmarshal(b)
	if err != nil {
		t.Fatal(err)
	}
	if def := p.Profile(policy.DefaultProfile); def == nil || !def.Security.Rebinding || !def.Security.Homograph {
		t.Errorf("created policy %+v, want secure defaults", p)
	}

	info, err := os.Stat(filepath.Join(dataDir, PolicyFile))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("policy file mode %v, want 0600", info.Mode().Perm())
	}
	for _, f := range []string{AdminTokenFile, ReaderTokenFile} {
		info, err := os.Stat(filepath.Join(dataDir, f))
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Errorf("%s: %v, mode %v; want a 0600 token", f, err, info.Mode().Perm())
		}
	}
	if !s.tokens.enabled() {
		t.Error("tokens not enabled")
	}
}

func TestServer_InvalidPolicyFileFailsStartup(t *testing.T) {
	dataDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dataDir, PolicyFile), []byte(`{"profiles":[{"id":"Bad ID"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := New(Config{Plaintext: true, DataDir: dataDir}, testLogger(t)); err == nil {
		t.Fatal("New succeeded with an invalid policy file, want an error rather than silently replacing it")
	}
}

func TestServer_ProfilesOverDoH(t *testing.T) {
	up, _ := startZone(t, nil)
	s, _ := newPolicyServer(t, up, &policy.Policy{Profiles: []policy.Profile{
		{ID: "default"},
		{ID: "kids", Deny: []string{"games.example"}},
	}})
	addr := start(t, s)

	if resp, err := dohQuery(t, addr, "/dns-query/kids", "games.example", dns.TypeA); err != nil || resp.Rcode != dns.RcodeNameError {
		t.Errorf("kids profile: %v, %v; want NXDOMAIN", resp, err)
	}
	if resp, err := dohQuery(t, addr, "/dns-query", "games.example", dns.TypeA); err != nil || resp.Rcode != dns.RcodeSuccess {
		t.Errorf("default profile: %v, %v; want NOERROR", resp, err)
	}
	if _, err := dohQuery(t, addr, "/dns-query/kids/tablet", "games.example", dns.TypeA); err != nil {
		t.Errorf("device path: %v", err)
	}

	for _, path := range []string{"/dns-query/nobody", "/dns-query/kids/Bad_Device", "/dns-query/kids/a/b"} {
		resp, err := http.Get("http://" + addr + path + "?dns=AAABAAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404", path, resp.StatusCode)
		}
	}

	page := s.qlog.Query(querylog.Filter{Device: "tablet"})
	if len(page.Entries) != 1 || page.Entries[0].Profile != "kids" || page.Entries[0].Status != querylog.StatusBlocked || page.Entries[0].Reason != "deny" {
		t.Errorf("log for device tablet = %+v, want one blocked kids entry", page.Entries)
	}
}

func TestServer_ClosedWithoutDefaultProfile(t *testing.T) {
	up, count := startZone(t, nil)
	s, _ := newPolicyServer(t, up, &policy.Policy{Profiles: []policy.Profile{
		{ID: "home", Clients: []string{"192.168.1.0/24"}},
	}})
	udp, _ := startDNS(t, s)

	resp := exchange(t, "udp", udp, new(dns.Msg).SetQuestion("example.com.", dns.TypeA))
	if resp.Rcode != dns.RcodeRefused {
		t.Errorf("unknown client got %s, want REFUSED", dns.RcodeToString[resp.Rcode])
	}
	if count.Load() != 0 {
		t.Error("a refused query was forwarded")
	}
}

func TestServer_LocalZonesNotForwarded(t *testing.T) {
	up, count := startZone(t, nil)
	router, routerCount := startZone(t, map[string]string{
		"5.1.168.192.in-addr.arpa. PTR": "5.1.168.192.in-addr.arpa. 60 IN PTR nas.lan.",
	})
	s, _ := newPolicyServer(t, up, policy.Defaults(), func(c *Config) {
		c.Forward = map[string][]string{"168.192.in-addr.arpa": {router}, "lan": {router}}
	})
	udp, _ := startDNS(t, s)

	for _, tt := range []struct {
		name  string
		qtype uint16
		rcode int
	}{
		{"_dns.resolver.arpa.", dns.TypeSVCB, dns.RcodeSuccess}, // RFC 9462: never ask upstream
		{"1.0.0.10.in-addr.arpa.", dns.TypePTR, dns.RcodeNameError},
		{"1.16.172.in-addr.arpa.", dns.TypePTR, dns.RcodeNameError},
		{"1.64.100.in-addr.arpa.", dns.TypePTR, dns.RcodeNameError},
		{"thing.home.arpa.", dns.TypeA, dns.RcodeNameError},
		{"printer.local.", dns.TypeA, dns.RcodeNameError},
		{"x.invalid.", dns.TypeA, dns.RcodeNameError},
		{"app.localhost.", dns.TypeA, dns.RcodeSuccess},
	} {
		resp := exchange(t, "udp", udp, new(dns.Msg).SetQuestion(tt.name, tt.qtype))
		if resp.Rcode != tt.rcode {
			t.Errorf("%s: %s, want %s", tt.name, dns.RcodeToString[resp.Rcode], dns.RcodeToString[tt.rcode])
		}
		if strings.HasSuffix(tt.name, "resolver.arpa.") && len(resp.Answer) != 0 {
			t.Errorf("%s: got answers %v, want none", tt.name, resp.Answer)
		}
	}
	if n := count.Load(); n != 0 {
		t.Errorf("forwarded %d local-zone queries upstream, want 0", n)
	}

	// A forward zone covering a private reverse zone sends it to the router.
	resp := exchange(t, "udp", udp, new(dns.Msg).SetQuestion("5.1.168.192.in-addr.arpa.", dns.TypePTR))
	if len(resp.Answer) != 1 || routerCount.Load() != 1 {
		t.Errorf("forwarded PTR: %v (router queried %d times), want the router's answer", resp, routerCount.Load())
	}
}

func TestServer_Chaos(t *testing.T) {
	up, _ := startZone(t, nil)
	s, _ := newPolicyServer(t, up, &policy.Policy{Profiles: []policy.Profile{
		{ID: "default"},
		{ID: "lab", Devices: []policy.Device{{Name: "bench", Addrs: []string{"127.0.0.1"}}}},
	}})
	udp, _ := startDNS(t, s)

	ch := func(name string) *dns.Msg {
		m := new(dns.Msg).SetQuestion(name, dns.TypeTXT)
		m.Question[0].Qclass = dns.ClassCHAOS
		return exchange(t, "udp", udp, m)
	}

	resp := ch("id.server.")
	if len(resp.Answer) != 1 || resp.Answer[0].(*dns.TXT).Txt[0] != "doh profile=lab device=bench client=127.0.0.1" {
		t.Errorf("id.server = %v", resp.Answer)
	}
	if resp := ch("version.bind."); len(resp.Answer) != 1 || resp.Answer[0].(*dns.TXT).Txt[0] != "doh" {
		t.Errorf("version.bind = %v, want just doh, without a version", resp.Answer)
	}
	if resp := ch("secret.bind."); resp.Rcode != dns.RcodeRefused {
		t.Errorf("unknown CHAOS name: %s, want REFUSED", dns.RcodeToString[resp.Rcode])
	}
}

func TestServer_ResponseChecks(t *testing.T) {
	up, _ := startZone(t, map[string]string{
		"evil.example.com. A":     "evil.example.com. 60 IN A 10.0.0.1",
		"nas.corp.example. A":     "nas.corp.example. 60 IN A 10.0.0.2",
		"strict.bing.com. A":      "strict.bing.com. 60 IN A 203.0.113.7",
		"metrics.shop.example. A": "metrics.shop.example. 60 IN CNAME collect.tracker.example.",
		"cdn.shop.example. A":     "cdn.shop.example. 60 IN CNAME edge.cdn.example.",
		"allowed.example. A":      "allowed.example. 60 IN A 127.0.0.1",
	})
	s, _ := newPolicyServer(t, up, &policy.Policy{Profiles: []policy.Profile{{
		ID:         "default",
		Security:   policy.Security{Rebinding: true},
		Deny:       []string{"tracker.example"},
		Allow:      []string{"allowed.example"},
		SafeSearch: true,
	}}}, func(c *Config) {
		c.Forward = map[string][]string{"corp.example": {up}}
	})
	udp, _ := startDNS(t, s)

	ask := func(name string) *dns.Msg {
		return exchange(t, "udp", udp, new(dns.Msg).SetQuestion(name, dns.TypeA))
	}

	if resp := ask("evil.example.com."); resp.Rcode != dns.RcodeNameError {
		t.Errorf("rebinding answer: %v, want it blocked", resp)
	}
	if resp := ask("nas.corp.example."); resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 1 {
		t.Errorf("forward zone answer: %v, want private addresses allowed for local domains", resp)
	}
	if resp := ask("allowed.example."); resp.Rcode != dns.RcodeSuccess {
		t.Errorf("allowed name: %v, want answer checks skipped", resp)
	}
	if resp := ask("metrics.shop.example."); resp.Rcode != dns.RcodeNameError {
		t.Errorf("cloaked tracker: %v, want the CNAME target's block applied", resp)
	}
	if resp := ask("cdn.shop.example."); resp.Rcode != dns.RcodeSuccess {
		t.Errorf("ordinary CNAME: %v", resp)
	}

	resp := ask("www.bing.com.")
	if len(resp.Answer) != 2 || resp.Answer[0].(*dns.CNAME).Target != "strict.bing.com." || resp.Answer[1].(*dns.A).A.String() != "203.0.113.7" {
		t.Errorf("safe search: %v, want a CNAME to strict.bing.com and its address", resp.Answer)
	}
}

func TestServer_ClientAddr(t *testing.T) {
	s := &Server{}
	for _, p := range []string{"10.0.0.0/8", "::1"} {
		prefix, _ := policy.ParsePrefix(p)
		s.trustedProxies = append(s.trustedProxies, prefix)
	}

	for _, tt := range []struct {
		remote, xff, want string
	}{
		{"203.0.113.5:1234", "", "203.0.113.5"},
		{"203.0.113.5:1234", "192.0.2.9", "203.0.113.5"},      // untrusted peers can't claim another address
		{"10.0.0.2:1234", "192.0.2.9", "192.0.2.9"},           // a trusted proxy's word is taken
		{"10.0.0.2:1234", "6.6.6.6, 192.0.2.9", "192.0.2.9"},  // only the rightmost untrusted hop counts
		{"10.0.0.2:1234", "192.0.2.9, 10.0.0.3", "192.0.2.9"}, // through a chain of trusted proxies
		{"10.0.0.2:1234", "garbage, 10.0.0.3", "10.0.0.3"},    // malformed hops stop the walk
		{"[::1]:1234", "::ffff:192.0.2.4", "192.0.2.4"},       // mapped addresses are unmapped
		{"[::ffff:203.0.113.5]:1234", "192.0.2.9", "203.0.113.5"},
	} {
		r := &http.Request{RemoteAddr: tt.remote, Header: http.Header{}}
		if tt.xff != "" {
			r.Header.Set("X-Forwarded-For", tt.xff)
		}
		if got := s.clientAddr(r); got != netip.MustParseAddr(tt.want) {
			t.Errorf("clientAddr(%s, XFF %q) = %s, want %s", tt.remote, tt.xff, got, tt.want)
		}
	}
}

// apiClient calls the admin API at base with token.
type apiClient struct {
	t     *testing.T
	base  string
	token string
}

func (c apiClient) do(method, path, body string, header ...string) (*http.Response, []byte) {
	c.t.Helper()
	req, err := http.NewRequestWithContext(c.t.Context(), method, c.base+path, strings.NewReader(body))
	if err != nil {
		c.t.Fatal(err)
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	for i := 0; i+1 < len(header); i += 2 {
		req.Header.Set(header[i], header[i+1])
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, b
}

func token(t *testing.T, dataDir, name string) string {
	t.Helper()
	tok, err := readToken(filepath.Join(dataDir, name))
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func TestAdminAPI_Auth(t *testing.T) {
	up, _ := startZone(t, nil)
	s, dataDir := newPolicyServer(t, up, nil)
	base := startAdmin(t, s)

	for _, tt := range []struct {
		desc, token, method, path string
		want                      int
	}{
		{"no token", "", http.MethodGet, "/api/v1/status", http.StatusUnauthorized},
		{"forged token", "doh_admin_forged", http.MethodGet, "/api/v1/status", http.StatusUnauthorized},
		{"reader reads", token(t, dataDir, ReaderTokenFile), http.MethodGet, "/api/v1/policy", http.StatusOK},
		{"reader writes", token(t, dataDir, ReaderTokenFile), http.MethodDelete, "/api/v1/profiles/default", http.StatusForbidden},
		{"admin reads", token(t, dataDir, AdminTokenFile), http.MethodGet, "/api/v1/status", http.StatusOK},
		{"unknown endpoint", token(t, dataDir, AdminTokenFile), http.MethodGet, "/api/v1/nope", http.StatusNotFound},
	} {
		resp, body := apiClient{t, base, tt.token}.do(tt.method, tt.path, "")
		if resp.StatusCode != tt.want {
			t.Errorf("%s: %s %s = %d %s, want %d", tt.desc, tt.method, tt.path, resp.StatusCode, body, tt.want)
		}
		if tt.want == http.StatusUnauthorized && resp.Header.Get("WWW-Authenticate") == "" {
			t.Errorf("%s: no WWW-Authenticate challenge", tt.desc)
		}
	}

	// The token isn't accepted outside the Authorization header.
	resp, _ := apiClient{t, base, ""}.do(http.MethodGet, "/api/v1/status?access_token="+url.QueryEscape(token(t, dataDir, AdminTokenFile)), "")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("token in the query string: %d, want 401", resp.StatusCode)
	}
}

func TestAdminAPI_UnavailableWithoutTokens(t *testing.T) {
	up, _ := startZone(t, nil)
	s, err := New(Config{Plaintext: true, Upstreams: []string{up}}, testLogger(t))
	if err != nil {
		t.Fatal(err)
	}
	resp, _ := apiClient{t, startAdmin(t, s), "anything"}.do(http.MethodGet, "/api/v1/status", "")
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503 without a data directory or token file", resp.StatusCode)
	}
}

func TestAdminAPI_Profiles(t *testing.T) {
	up, _ := startZone(t, nil)
	s, dataDir := newPolicyServer(t, up, &policy.Policy{Profiles: []policy.Profile{{ID: "default"}}})
	c := apiClient{t, startAdmin(t, s), token(t, dataDir, AdminTokenFile)}
	udp, _ := startDNS(t, s)

	resp, body := c.do(http.MethodPost, "/api/v1/profiles", `{"id":"kids","name":"Kids","clients":["127.0.0.1"]}`)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create = %d %s", resp.StatusCode, body)
	}
	if resp, _ := c.do(http.MethodPost, "/api/v1/profiles", `{"id":"kids"}`); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("duplicate create = %d, want 400", resp.StatusCode)
	}
	etag := resp.Header.Get("ETag")

	// A merge patch toggles a feature, keeping everything else.
	resp, body = c.do(http.MethodPatch, "/api/v1/profiles/kids", `{"security":{"bypass":true},"deny":["games.example"]}`,
		"Content-Type", api.MergePatchType, "If-Match", etag)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("patch = %d %s", resp.StatusCode, body)
	}
	var pr policy.Profile
	if err := json.Unmarshal(body, &pr); err != nil || !pr.Security.Bypass || pr.Name != "Kids" || len(pr.Clients) != 1 {
		t.Errorf("patched profile = %+v, %v", pr, err)
	}

	// The change applies to queries immediately.
	if resp := exchange(t, "udp", udp, new(dns.Msg).SetQuestion("games.example.", dns.TypeA)); resp.Rcode != dns.RcodeNameError {
		t.Errorf("after patch: %s, want NXDOMAIN", dns.RcodeToString[resp.Rcode])
	}

	// A stale entity tag is refused, so concurrent edits aren't lost.
	if resp, _ := c.do(http.MethodPatch, "/api/v1/profiles/kids", `{"safe_search":true}`, "If-Match", etag); resp.StatusCode != http.StatusPreconditionFailed {
		t.Errorf("stale If-Match = %d, want 412", resp.StatusCode)
	}

	for _, tt := range []struct{ desc, patch string }{
		{"id change", `{"id":"other"}`},
		{"unknown field", `{"securty":{}}`},
		{"invalid value", `{"block_response":"drop"}`},
		{"invalid json", `{`},
		{"invalid client", `{"clients":["not an ip"]}`},
	} {
		if resp, body := c.do(http.MethodPatch, "/api/v1/profiles/kids", tt.patch); resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%s: %d %s, want 400", tt.desc, resp.StatusCode, body)
		}
	}
	if resp, _ := c.do(http.MethodPatch, "/api/v1/profiles/kids", `{}`, "Content-Type", "text/plain"); resp.StatusCode != http.StatusUnsupportedMediaType {
		t.Errorf("text/plain patch = %d, want 415", resp.StatusCode)
	}

	// Allowing a denied domain moves it from one list to the other.
	resp, body = c.do(http.MethodPost, "/api/v1/profiles/kids/allow", `{"domain":"Games.Example."}`)
	pr = policy.Profile{}
	if err := json.Unmarshal(body, &pr); resp.StatusCode != http.StatusOK || err != nil || len(pr.Deny) != 0 || len(pr.Allow) != 1 || pr.Allow[0] != "games.example" {
		t.Errorf("allow = %d %s", resp.StatusCode, body)
	}
	if resp, _ := c.do(http.MethodPost, "/api/v1/profiles/kids/allow", `{"domain":"not a domain"}`); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("allow invalid domain = %d, want 400", resp.StatusCode)
	}
	if resp, _ := c.do(http.MethodDelete, "/api/v1/profiles/kids/allow/games.example", ""); resp.StatusCode != http.StatusOK {
		t.Errorf("unallow = %d", resp.StatusCode)
	}
	if resp, _ := c.do(http.MethodPost, "/api/v1/profiles/nobody/deny", `{"domain":"x.example"}`); resp.StatusCode != http.StatusNotFound {
		t.Errorf("deny on missing profile = %d, want 404", resp.StatusCode)
	}

	// Changes are saved to the policy file.
	b, err := os.ReadFile(filepath.Join(dataDir, PolicyFile))
	if err != nil {
		t.Fatal(err)
	}
	saved, err := policy.Unmarshal(b)
	if err != nil || saved.Profile("kids") == nil || !saved.Profile("kids").Security.Bypass {
		t.Errorf("saved policy = %s, %v", b, err)
	}

	if resp, _ := c.do(http.MethodDelete, "/api/v1/profiles/kids", ""); resp.StatusCode != http.StatusNoContent {
		t.Errorf("delete = %d", resp.StatusCode)
	}
	if resp, _ := c.do(http.MethodGet, "/api/v1/profiles/kids", ""); resp.StatusCode != http.StatusNotFound {
		t.Errorf("get deleted = %d, want 404", resp.StatusCode)
	}

	// PUT validates the whole policy, listing every problem.
	resp, body = c.do(http.MethodPut, "/api/v1/policy", `{"profiles":[{"id":"Bad"},{"id":"x","lists":["nope"]}]}`)
	var apiErr api.Error
	if err := json.Unmarshal(body, &apiErr); resp.StatusCode != http.StatusBadRequest || err != nil || len(apiErr.Details) != 2 {
		t.Errorf("invalid PUT = %d %s, want 400 with two details", resp.StatusCode, body)
	}
}

func TestAdminAPI_LogsStatsExplain(t *testing.T) {
	up, _ := startZone(t, nil)
	s, dataDir := newPolicyServer(t, up, &policy.Policy{Profiles: []policy.Profile{
		{ID: "default", Deny: []string{"ads.example"}},
		{ID: "quiet", Devices: []policy.Device{{Name: "x", Addrs: []string{"192.0.2.50"}}}, Logging: policy.Logging{Disabled: true}},
	}})
	c := apiClient{t, startAdmin(t, s), token(t, dataDir, ReaderTokenFile)}
	udp, _ := startDNS(t, s)

	// Start streaming before the queries.
	streamResp := func() *http.Response {
		req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, c.base+"/api/v1/logs/stream?status=blocked", nil)
		req.Header.Set("Authorization", "Bearer "+c.token)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { resp.Body.Close() })
		return resp
	}()
	if ct := streamResp.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Fatalf("stream Content-Type %q", ct)
	}

	exchange(t, "udp", udp, new(dns.Msg).SetQuestion("www.example.com.", dns.TypeA))
	exchange(t, "udp", udp, new(dns.Msg).SetQuestion("x.ads.example.", dns.TypeA))

	sc := bufio.NewScanner(streamResp.Body)
	deadline := time.AfterFunc(5*time.Second, func() { streamResp.Body.Close() })
	defer deadline.Stop()
	var streamed querylog.Entry
	for sc.Scan() {
		if data, ok := strings.CutPrefix(sc.Text(), "data: "); ok {
			if err := json.Unmarshal([]byte(data), &streamed); err != nil {
				t.Fatal(err)
			}
			break
		}
	}
	if streamed.Name != "x.ads.example" || streamed.Status != querylog.StatusBlocked {
		t.Errorf("streamed %+v, want the blocked query", streamed)
	}

	_, body := c.do(http.MethodGet, "/api/v1/logs?status=blocked", "")
	var page querylog.Page
	if err := json.Unmarshal(body, &page); err != nil || len(page.Entries) != 1 || page.Entries[0].Reason != "deny" || page.Entries[0].Client != "127.0.0.1" {
		t.Errorf("logs = %s", body)
	}
	if resp, _ := c.do(http.MethodGet, "/api/v1/logs?status=bogus", ""); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("bad filter = %d, want 400", resp.StatusCode)
	}

	_, body = c.do(http.MethodGet, "/api/v1/stats", "")
	var stats querylog.Stats
	if err := json.Unmarshal(body, &stats); err != nil || stats.Total != 2 || stats.ByStatus[querylog.StatusBlocked] != 1 || stats.Clients != 1 || stats.Timeline != nil {
		t.Errorf("stats = %s", body)
	}

	// A timeline, by the hour, as the Overview asks: half an hour ago is
	// one interval, whatever the second it's asked in.
	since := url.QueryEscape(time.Now().Add(-30 * time.Minute).Format(time.RFC3339))
	_, body = c.do(http.MethodGet, "/api/v1/stats?interval=1h&since="+since, "")
	if err := json.Unmarshal(body, &stats); err != nil || len(stats.Timeline) != 1 || stats.Timeline[0].Allowed != 1 || stats.Timeline[0].Blocked != 1 {
		t.Errorf("stats with a timeline = %s", body)
	}
	for _, q := range []string{"interval=1h", "interval=10s&since=" + since, "interval=soon&since=" + since, "interval=1m&since=2020-01-01T00:00:00Z"} {
		if resp, _ := c.do(http.MethodGet, "/api/v1/stats?"+q, ""); resp.StatusCode != http.StatusBadRequest {
			t.Errorf("stats?%s = %d, want 400", q, resp.StatusCode)
		}
	}

	_, body = c.do(http.MethodGet, "/api/v1/explain?name=x.ads.example&type=AAAA", "")
	var exp api.Explanation
	if err := json.Unmarshal(body, &exp); err != nil || exp.Decision.Action != api.ActionBlock || exp.Decision.Reason != "deny" || exp.Profile != "default" || len(exp.Checks) == 0 {
		t.Errorf("explain = %s", body)
	}
	_, body = c.do(http.MethodGet, "/api/v1/explain?name=www.example.com&client=192.0.2.50", "")
	if err := json.Unmarshal(body, &exp); err != nil || exp.Profile != "quiet" || exp.Device != "x" || exp.Decision.Action != api.ActionAllow || len(exp.Answers) != 1 {
		t.Errorf("explain by client = %s", body)
	}
	for _, q := range []string{"name=", "name=a..b", "name=x.example&type=BOGUS", "name=x.example&client=nope", "name=x.example&profile=nobody"} {
		if resp, _ := c.do(http.MethodGet, "/api/v1/explain?"+q, ""); resp.StatusCode/100 != 4 {
			t.Errorf("explain?%s = %d, want a client error", q, resp.StatusCode)
		}
	}
	if n := s.qlog.Len(); n != 2 {
		t.Errorf("explanations were logged: %d entries, want 2", n)
	}

	// Profiles with logging off stay out of the log.
	s.answerDNS(t.Context(), "udp", netip.MustParseAddr("192.0.2.50"), new(dns.Msg).SetQuestion("private.example.", dns.TypeA))
	if page := s.qlog.Query(querylog.Filter{Search: "private"}); len(page.Entries) != 0 {
		t.Errorf("unlogged profile's query was logged: %+v", page.Entries)
	}
}

func TestAdminAPI_PolicyFollowsRemote(t *testing.T) {
	up, _ := startZone(t, nil)

	// The central server.
	central, centralDir := newPolicyServer(t, up, &policy.Policy{Profiles: []policy.Profile{
		{ID: "default", Deny: []string{"central.example"}},
	}})
	centralAPI := apiClient{t, startAdmin(t, central), token(t, centralDir, AdminTokenFile)}

	// A home server following it with the reader token.
	tokenFile := filepath.Join(t.TempDir(), "reader.token")
	if err := os.WriteFile(tokenFile, []byte(token(t, centralDir, ReaderTokenFile)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	home, homeDir := newPolicyServer(t, up, nil, func(c *Config) {
		c.Policy = PolicyConfig{Source: centralAPI.base + "/api/v1/policy", TokenFile: tokenFile}
	})
	homeUDP, _ := startDNS(t, home)

	if resp := exchange(t, "udp", homeUDP, new(dns.Msg).SetQuestion("central.example.", dns.TypeA)); resp.Rcode != dns.RcodeNameError {
		t.Errorf("home server didn't apply the central policy: %s", dns.RcodeToString[resp.Rcode])
	}

	// The home server's own API refuses changes.
	homeAPI := apiClient{t, startAdmin(t, home), token(t, homeDir, AdminTokenFile)}
	if resp, body := homeAPI.do(http.MethodPost, "/api/v1/profiles/default/allow", `{"domain":"central.example"}`); resp.StatusCode != http.StatusConflict {
		t.Errorf("change on follower = %d %s, want 409", resp.StatusCode, body)
	}

	// Changes on the central server reach it on the next sync, and an
	// unchanged policy isn't downloaded again.
	if resp, _ := centralAPI.do(http.MethodPost, "/api/v1/profiles/default/deny", `{"domain":"new.example"}`); resp.StatusCode != http.StatusOK {
		t.Fatal("central change failed")
	}
	p, err := home.store.fetch(t.Context())
	if err != nil || p == nil {
		t.Fatalf("fetch = %v, %v", p, err)
	}
	if err := home.applyPolicy(p); err != nil {
		t.Fatal(err)
	}
	if resp := exchange(t, "udp", homeUDP, new(dns.Msg).SetQuestion("new.example.", dns.TypeA)); resp.Rcode != dns.RcodeNameError {
		t.Error("central change not applied after sync")
	}
	if p, err := home.store.fetch(t.Context()); p != nil || err != nil {
		t.Errorf("refetch of an unchanged policy = %v, %v; want not modified", p, err)
	}

	// The cached copy lets it start while the central server is down.
	if _, err := os.Stat(filepath.Join(homeDir, "policy.remote.json")); err != nil {
		t.Errorf("remote policy not cached: %v", err)
	}

	// A forged token is refused by the central server.
	if err := os.WriteFile(tokenFile, []byte("doh_read_forged"), 0o600); err != nil {
		t.Fatal(err)
	}
	home.store.etag = ""
	if _, err := home.store.fetch(t.Context()); err == nil || !strings.Contains(err.Error(), "401") {
		t.Errorf("fetch with a forged token = %v, want 401", err)
	}
}

func TestPolicyStore_Watch(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		dir := t.TempDir()
		st := &policyStore{path: filepath.Join(dir, PolicyFile), logger: testLogger(t)}
		if _, err := st.load(t.Context()); err != nil {
			t.Fatal(err)
		}

		var applied []*policy.Policy
		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan struct{})
		go func() {
			defer close(done)
			_ = st.watch(ctx, func(p *policy.Policy) error {
				applied = append(applied, p)
				return nil
			})
		}()

		// tick advances the fake clock past the next check, and waits for
		// the watcher to act on it.
		tick := func() {
			time.Sleep(policyFileInterval)
			synctest.Wait()
		}
		// edit replaces the file, with a modification time that differs
		// from the last, as a real edit's would.
		edit := func(content string, age time.Duration) {
			name := filepath.Join(dir, PolicyFile)
			if err := os.WriteFile(name, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			when := time.Unix(1_000_000, 0).Add(age)
			if err := os.Chtimes(name, when, when); err != nil {
				t.Fatal(err)
			}
		}

		tick()
		if len(applied) != 0 {
			t.Fatalf("applied %d policies without an edit", len(applied))
		}

		// Invalid edits are reported and ignored.
		edit(`{"profiles":[{"id":"BAD"}]}`, time.Hour)
		tick()
		if len(applied) != 0 || st.status().Error == "" {
			t.Fatalf("invalid edit: applied %d, error %q", len(applied), st.status().Error)
		}

		// Valid edits apply once, however long they sit unchanged.
		edit(`{"profiles":[{"id":"default","deny":["edited.example"]}]}`, 2*time.Hour)
		tick()
		tick()
		if len(applied) != 1 || applied[0].Profiles[0].Deny[0] != "edited.example" || st.status().Error != "" {
			t.Fatalf("valid edit: applied %+v, error %q", applied, st.status().Error)
		}

		// A deleted file keeps the current policy.
		if err := os.Remove(filepath.Join(dir, PolicyFile)); err != nil {
			t.Fatal(err)
		}
		tick()
		if len(applied) != 1 {
			t.Errorf("deleting the file applied a policy")
		}

		cancel()
		<-done
	})
}

func TestConfig_ValidatePolicy(t *testing.T) {
	for _, tt := range []struct {
		desc   string
		config Config
	}{
		{"remote over http", Config{DNSListen: ":53", Policy: PolicyConfig{Source: "http://doh.example.com/api/v1/policy"}}},
		{"token without url", Config{DNSListen: ":53", Policy: PolicyConfig{Source: "policy.json", TokenFile: "t"}}},
		{"short refresh", Config{DNSListen: ":53", Policy: PolicyConfig{Source: "https://doh.example.com/", Refresh: Duration(time.Second)}}},
		{"forward domain", Config{DNSListen: ":53", Forward: map[string][]string{"bad domain": {"192.168.1.1"}}}},
		{"forward upstream", Config{DNSListen: ":53", Forward: map[string][]string{"lan": {"ftp://x"}}}},
		{"forward empty", Config{DNSListen: ":53", Forward: map[string][]string{"lan": nil}}},
		{"proxy", Config{DNSListen: ":53", TrustedProxies: []string{"nope"}}},
		{"query log", Config{DNSListen: ":53", QueryLog: QueryLogConfig{Memory: -1}}},
	} {
		if err := tt.config.Validate(); err == nil {
			t.Errorf("%s: Validate succeeded, want an error", tt.desc)
		}
	}

	ok := Config{DNSListen: ":53", Policy: PolicyConfig{Source: "http://127.0.0.1:9090/api/v1/policy", TokenFile: "t"}}
	if err := ok.Validate(); err != nil {
		t.Errorf("loopback http policy: %v", err)
	}
}
