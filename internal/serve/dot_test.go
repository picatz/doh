package serve

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json/v2"
	"encoding/xml"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/picatz/doh/internal/api"
	"github.com/picatz/doh/internal/policy"
	"github.com/picatz/doh/internal/querylog"
)

const testHostname = "dns.example.test"

// hostnamePolicy has a default profile, and a kids profile that denies
// games.example.
func hostnamePolicy() *policy.Policy {
	return &policy.Policy{Profiles: []policy.Profile{
		{ID: "default"},
		{ID: "kids", Name: "Kids", Deny: []string{"games.example"}},
	}}
}

// startDoT serves DoT for s on a loopback port, returning its address.
func startDoT(t *testing.T, s *Server) string {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	errc := make(chan error, 1)
	go func() { errc <- s.ServeDoT(t.Context(), ln) }()
	t.Cleanup(func() {
		if err := <-errc; err != nil {
			t.Error(err)
		}
	})

	// No need to wait for it to start: connections queue on the listener
	// until it does.
	return ln.Addr().String()
}

// dotClient returns a DoT client that asks for serverName.
func dotClient(serverName string) *dns.Client {
	return &dns.Client{
		Net:       "tcp-tls",
		Timeout:   5 * time.Second,
		TLSConfig: &tls.Config{ServerName: serverName, InsecureSkipVerify: true, MinVersion: tls.VersionTLS12},
	}
}

func newDoTServer(t *testing.T, p *policy.Policy) *Server {
	t.Helper()
	up, _ := startZone(t, nil)
	certFile, keyFile := writeCert(t, t.TempDir(), testHostname)
	s, _ := newPolicyServer(t, up, p, func(c *Config) {
		c.Plaintext = false
		c.TLS = TLSConfig{CertFile: certFile, KeyFile: keyFile}
		c.DoTListen = "127.0.0.1:0"
		c.Hostname = testHostname
	})
	return s
}

func TestServer_DoTSelectsProfileByServerName(t *testing.T) {
	s := newDoTServer(t, hostnamePolicy())
	addr := startDoT(t, s)

	for _, tt := range []struct {
		serverName string
		rcode      int
		identity   string
	}{
		{"kids." + testHostname, dns.RcodeNameError, "doh profile=kids client=127.0.0.1"},
		{"tablet--kids." + testHostname, dns.RcodeNameError, "doh profile=kids device=tablet client=127.0.0.1"},
		{"KIDS." + testHostname + ".", dns.RcodeNameError, "doh profile=kids client=127.0.0.1"},
		{testHostname, dns.RcodeSuccess, "doh profile=default client=127.0.0.1"},
		{"other.example", dns.RcodeSuccess, "doh profile=default client=127.0.0.1"}, // not under the hostname: by address
		{"nobody." + testHostname, dns.RcodeRefused, ""},                            // names no profile
		{"a--b--c." + testHostname, dns.RcodeRefused, ""},
	} {
		t.Run(tt.serverName, func(t *testing.T) {
			c := dotClient(tt.serverName)
			conn, err := c.Dial(addr)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()

			// Both queries share one connection, as RFC 7858 clients do.
			resp, _, err := c.ExchangeWithConn(new(dns.Msg).SetQuestion("games.example.", dns.TypeA), conn)
			if err != nil {
				t.Fatal(err)
			}
			if resp.Rcode != tt.rcode {
				t.Errorf("games.example: %s, want %s", dns.RcodeToString[resp.Rcode], dns.RcodeToString[tt.rcode])
			}

			if tt.identity == "" {
				return
			}
			id := new(dns.Msg).SetQuestion("id.server.", dns.TypeTXT)
			id.Question[0].Qclass = dns.ClassCHAOS
			resp, _, err = c.ExchangeWithConn(id, conn)
			if err != nil {
				t.Fatal(err)
			}
			if len(resp.Answer) != 1 || resp.Answer[0].(*dns.TXT).Txt[0] != tt.identity {
				t.Errorf("id.server = %v, want %q", resp.Answer, tt.identity)
			}
		})
	}

	if page := s.qlog.Query(querylog.Filter{Search: "games.example"}); len(page.Entries) == 0 || page.Entries[0].Transport != "dot" {
		t.Errorf("DoT queries weren't logged with transport dot: %+v", page.Entries)
	}
}

func TestServer_DoTOffersOnlyDoT(t *testing.T) {
	s := newDoTServer(t, hostnamePolicy())
	addr := startDoT(t, s)

	conn, err := tls.Dial("tcp", addr, &tls.Config{ServerName: testHostname, InsecureSkipVerify: true, NextProtos: []string{"h2", "dot"}})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if p := conn.ConnectionState().NegotiatedProtocol; p != "dot" {
		t.Errorf("negotiated %q, want dot", p)
	}
}

func TestServer_DoHSelectsProfileByHost(t *testing.T) {
	up, _ := startZone(t, nil)
	s, _ := newPolicyServer(t, up, hostnamePolicy(), func(c *Config) { c.Hostname = testHostname })
	addr := start(t, s)

	get := func(host, path string) *http.Response {
		t.Helper()
		// A query for games.example, base64url-encoded.
		q, _ := new(dns.Msg).SetQuestion("games.example.", dns.TypeA).Pack()
		req, _ := http.NewRequest(http.MethodGet, "http://"+addr+path+"?dns="+base64.RawURLEncoding.EncodeToString(q), nil)
		req.Host = host
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { resp.Body.Close() })
		return resp
	}
	rcode := func(resp *http.Response) int {
		t.Helper()
		b, _ := io.ReadAll(resp.Body)
		var m dns.Msg
		if err := m.Unpack(b); err != nil {
			t.Fatalf("status %d: %s", resp.StatusCode, b)
		}
		return m.Rcode
	}

	if got := rcode(get("kids."+testHostname, "/dns-query")); got != dns.RcodeNameError {
		t.Errorf("kids host: %s, want NXDOMAIN", dns.RcodeToString[got])
	}
	if got := rcode(get(testHostname, "/dns-query")); got != dns.RcodeSuccess {
		t.Errorf("bare hostname: %s, want NOERROR", dns.RcodeToString[got])
	}
	// The path takes precedence over the host.
	if got := rcode(get("kids."+testHostname, "/dns-query/default")); got != dns.RcodeSuccess {
		t.Errorf("path over host: %s, want NOERROR", dns.RcodeToString[got])
	}
	if resp := get("nobody."+testHostname, "/dns-query"); resp.StatusCode != http.StatusNotFound {
		t.Errorf("unknown host profile: %d, want 404", resp.StatusCode)
	}
}

func TestProfileFromHost(t *testing.T) {
	s := &Server{config: Config{Hostname: testHostname}}

	for _, tt := range []struct {
		host, profile, device string
		ok                    bool
	}{
		{"kids." + testHostname, "kids", "", true},
		{"tablet--kids." + testHostname, "kids", "tablet", true},
		{"kids." + testHostname + ":443", "kids", "", true},
		{"Kids." + strings.ToUpper(testHostname) + ".", "kids", "", true},
		{testHostname, "", "", false},
		{"a.kids." + testHostname, "", "", false}, // only one label deep
		{"kids.example.com", "", "", false},
		{"kids." + testHostname + "evil.com", "", "", false},
		{"", "", "", false},
		{"bad-device---kids." + testHostname, "bad-device---kids", "", true}, // invalid IDs never match a profile
	} {
		profile, device, ok := s.profileFromHost(tt.host)
		if profile != tt.profile || device != tt.device || ok != tt.ok {
			t.Errorf("profileFromHost(%q) = %q, %q, %v; want %q, %q, %v", tt.host, profile, device, ok, tt.profile, tt.device, tt.ok)
		}
	}

	if _, _, ok := (&Server{}).profileFromHost("kids." + testHostname); ok {
		t.Error("matched a profile without a hostname configured")
	}
}

func TestACMEHostPolicy(t *testing.T) {
	up, _ := startZone(t, nil)
	s, _ := newPolicyServer(t, up, hostnamePolicy(), func(c *Config) { c.Hostname = testHostname })
	allow := s.acmeHostPolicy([]string{testHostname, "other.example"})

	for host, want := range map[string]bool{
		testHostname:                     true,
		"other.example":                  true,
		"kids." + testHostname:           true,
		"tablet--kids." + testHostname:   true,
		"nobody." + testHostname:         false, // no such profile: no certificate request
		"x.kids." + testHostname:         false,
		"random.example":                 false,
		"kids." + testHostname + ".evil": false,
	} {
		if err := allow(t.Context(), host); (err == nil) != want {
			t.Errorf("acmeHostPolicy(%q) = %v, want allowed %v", host, err, want)
		}
	}

	// Deleting a profile stops its certificate being renewed or served.
	if err := s.applyPolicy(&policy.Policy{Profiles: []policy.Profile{{ID: "default"}}}); err != nil {
		t.Fatal(err)
	}
	if err := allow(t.Context(), "kids."+testHostname); err == nil {
		t.Error("deleted profile's host name still allowed")
	}
}

func TestAdminAPI_Setup(t *testing.T) {
	s := newDoTServer(t, hostnamePolicy())
	c := apiClient{t, startAdmin(t, s), token(t, s.config.DataDir, ReaderTokenFile)}

	resp, body := c.do(http.MethodGet, "/api/v1/profiles/kids/setup?device=tablet", "")
	var setup api.Setup
	if err := json.Unmarshal(body, &setup); resp.StatusCode != http.StatusOK || err != nil {
		t.Fatalf("setup = %d %s", resp.StatusCode, body)
	}
	if setup.DoHURL != "https://"+testHostname+"/dns-query/kids/tablet" {
		t.Errorf("DoH URL %q", setup.DoHURL)
	}
	if setup.DoTHost != "tablet--kids."+testHostname {
		t.Errorf("DoT host %q", setup.DoTHost)
	}

	platforms := map[string]api.Platform{}
	for _, p := range setup.Platforms {
		platforms[p.ID] = p
	}
	if !strings.Contains(strings.Join(platforms["android"].Steps, " "), setup.DoTHost) {
		t.Errorf("android steps %q don't name the DoT host", platforms["android"].Steps)
	}
	if platforms["apple"].Download == "" {
		t.Fatal("no Apple configuration profile offered")
	}

	// The configuration profile is well-formed, points at the DoH URL, and
	// keeps its identifiers across downloads, so reinstalling replaces it.
	download := func(path string) (*http.Response, []byte) {
		return c.do(http.MethodGet, path, "")
	}
	resp, first := download(platforms["apple"].Download)
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != api.MobileConfigType {
		t.Fatalf("mobileconfig = %d %s", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	if !strings.Contains(resp.Header.Get("Content-Disposition"), `filename="kids-tablet.mobileconfig"`) {
		t.Errorf("Content-Disposition %q", resp.Header.Get("Content-Disposition"))
	}
	if err := xml.Unmarshal(first, new(struct{})); err != nil {
		t.Errorf("mobileconfig isn't well-formed XML: %v", err)
	}
	for _, want := range []string{setup.DoHURL, "com.apple.dnsSettings.managed", "<string>HTTPS</string>"} {
		if !strings.Contains(string(first), want) {
			t.Errorf("mobileconfig lacks %q:\n%s", want, first)
		}
	}
	if _, again := download(platforms["apple"].Download); string(again) != string(first) {
		t.Error("mobileconfig changed between downloads")
	}
	if _, other := download("/api/v1/profiles/kids/apple.mobileconfig"); string(other) == string(first) {
		t.Error("a different device got the same configuration profile")
	}

	_, tlsConfig := download("/api/v1/profiles/kids/apple.mobileconfig?protocol=tls")
	if !strings.Contains(string(tlsConfig), "<string>TLS</string>") || !strings.Contains(string(tlsConfig), "kids."+testHostname) {
		t.Errorf("DoT mobileconfig:\n%s", tlsConfig)
	}

	for path, want := range map[string]int{
		"/api/v1/profiles/kids/setup?device=Bad_Name":           http.StatusBadRequest,
		"/api/v1/profiles/nobody/setup":                         http.StatusNotFound,
		"/api/v1/profiles/kids/apple.mobileconfig?protocol=ftp": http.StatusBadRequest,
		"/api/v1/profiles/kids/apple.mobileconfig?device=a%2Fb": http.StatusBadRequest,
	} {
		if resp, body := download(path); resp.StatusCode != want {
			t.Errorf("GET %s = %d %s, want %d", path, resp.StatusCode, body, want)
		}
	}
}

func TestAdminAPI_SetupWithoutHostname(t *testing.T) {
	up, _ := startZone(t, nil)
	s, dataDir := newPolicyServer(t, up, hostnamePolicy())
	c := apiClient{t, startAdmin(t, s), token(t, dataDir, ReaderTokenFile)}

	_, body := c.do(http.MethodGet, "/api/v1/profiles/kids/setup", "")
	var setup api.Setup
	if err := json.Unmarshal(body, &setup); err != nil || setup.DoHURL != "" || len(setup.Platforms) == 0 {
		t.Errorf("setup without a hostname = %s", body)
	}
	if resp, _ := c.do(http.MethodGet, "/api/v1/profiles/kids/apple.mobileconfig", ""); resp.StatusCode != http.StatusConflict {
		t.Errorf("mobileconfig without a hostname = %d, want 409", resp.StatusCode)
	}
}

func TestUUIDFor(t *testing.T) {
	a, b := uuidFor("x"), uuidFor("y")
	if a == b || a != uuidFor("x") {
		t.Errorf("uuidFor isn't a stable, distinct mapping: %s %s", a, b)
	}
	if len(a) != 36 || a[14] != '8' || !strings.ContainsRune("89AB", rune(a[19])) {
		t.Errorf("uuidFor(x) = %s, want an RFC 9562 version 8 UUID", a)
	}
}

func TestConfig_ValidateDoT(t *testing.T) {
	for _, c := range []Config{
		{Plaintext: true, DoTListen: ":853"},      // DoT needs a certificate
		{DNSListen: ":53", DoTListen: "853"},      // not an address
		{DNSListen: ":53", Hostname: "localhost"}, // not a domain under which profiles fit
		{DNSListen: ":53", Hostname: "dns example.com"},
	} {
		if err := c.Validate(); err == nil {
			t.Errorf("Validate(%+v) succeeded", c)
		}
	}
}
