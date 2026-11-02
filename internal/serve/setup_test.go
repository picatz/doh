package serve

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"github.com/picatz/doh/internal/cms/cmstest"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/picatz/doh/internal/api"
	"github.com/picatz/doh/internal/devicesetup"
	"github.com/picatz/doh/internal/plist"
	"github.com/picatz/doh/internal/policy"
)

var updateGolden = flag.Bool("update", false, "rewrite golden files in testdata")

// golden compares got with testdata/name, or with -update, rewrites it.
func golden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *updateGolden {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run go test -update to create it)", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("%s differs from what was generated (check, then run go test -run %s -update):\n%s", name, t.Name(), got)
	}
}

// testServerAddr is what the test server's host name resolves to.
var testServerAddr = netip.MustParseAddr("203.0.113.7")

// newSetupServer returns a server with DoH and DoT under testHostname,
// whose name resolves to testServerAddr, and plain DNS on 192.168.1.10,
// with its admin API.
func newSetupServer(t *testing.T, p *policy.Policy) (*Server, apiClient) {
	t.Helper()
	s := newDoTServer(t, p)
	s.selfAddrs.lookup = func(_ context.Context, host string) ([]netip.Addr, error) {
		if host != testHostname {
			t.Errorf("looked up %q", host)
		}
		// Loopback and duplicate answers aren't for devices.
		return []netip.Addr{testServerAddr, netip.MustParseAddr("127.0.0.1"), testServerAddr}, nil
	}
	s.setListener("dns", &net.UDPAddr{IP: net.IPv4(192, 168, 1, 10), Port: 53})
	return s, apiClient{t, startAdmin(t, s), token(t, s.config.DataDir, ReaderTokenFile)}
}

// fullSetup is a setup with every way to connect.
func fullSetup(device string) setupInputs {
	in := setupInputs{
		setup: api.Setup{
			Profile:     "kids",
			Device:      device,
			Hostname:    "dns.example.com",
			DoHURL:      "https://dns.example.com/dns-query/kids",
			DoTHost:     "kids.dns.example.com",
			DNSAddrs:    []string{"192.168.1.10"},
			ServerAddrs: []string{"203.0.113.7"},
		},
		dotPort: "853",
	}
	if device != "" {
		in.setup.DoHURL += "/" + device
		in.setup.DoTHost = device + "--" + in.setup.DoTHost
	}
	return in
}

func TestPlatformsFor(t *testing.T) {
	without := func(in setupInputs, f func(*api.Setup)) setupInputs { f(&in.setup); return in }
	full := fullSetup("tablet")
	tests := []struct {
		name string
		in   setupInputs
		// levels are the protection each platform should get; platforms
		// not listed shouldn't be offered.
		levels map[string]string
	}{
		{"everything", full, map[string]string{
			"apple": "encrypted", "vision-pro": "encrypted", "android": "encrypted",
			"mac": "encrypted", "windows": "encrypted", "linux": "encrypted", "chromeos": "encrypted",
			"apple-tv": "encrypted", "android-tv": "encrypted", "smart-tv": "plain",
			"consoles": "plain", "smart-home": "plain", "browser": "encrypted",
			"router": "plain", "openwrt": "plain", "pfsense": "encrypted", "unifi": "plain",
		}},
		{"encrypted only, from the cloud", without(full, func(s *api.Setup) { s.DNSAddrs = nil }), map[string]string{
			"apple": "encrypted", "vision-pro": "encrypted", "android": "encrypted",
			"mac": "encrypted", "windows": "encrypted", "linux": "encrypted", "chromeos": "encrypted",
			"apple-tv": "encrypted", "android-tv": "encrypted", "smart-tv": "unavailable",
			"consoles": "unavailable", "smart-home": "unavailable", "browser": "encrypted",
			"router": "unavailable", "pfsense": "encrypted",
		}},
		{"DoH without DoT", without(full, func(s *api.Setup) { s.DoTHost = "" }), map[string]string{
			"apple": "encrypted", "vision-pro": "encrypted", "android": "encrypted",
			"mac": "encrypted", "windows": "encrypted", "linux": "plain", "chromeos": "encrypted",
			"apple-tv": "encrypted", "android-tv": "plain", "smart-tv": "plain",
			"consoles": "plain", "smart-home": "plain", "browser": "encrypted",
			"router": "plain", "openwrt": "plain", "pfsense": "plain", "unifi": "plain",
		}},
		{"plain DNS only, on a home network", without(full, func(s *api.Setup) { s.DoHURL, s.DoTHost, s.Hostname, s.ServerAddrs = "", "", "", nil }), map[string]string{
			"android": "plain", "windows": "plain", "linux": "plain", "chromeos": "plain",
			"android-tv": "plain", "smart-tv": "plain", "consoles": "plain", "smart-home": "plain",
			"router": "plain", "openwrt": "plain", "pfsense": "plain", "unifi": "plain",
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			platforms, groups := platformsFor(tt.in)
			got := map[string]string{}
			for _, p := range platforms {
				if _, dup := got[p.ID]; dup {
					t.Errorf("platform %s offered twice", p.ID)
				}
				got[p.ID] = p.Protection.Level
				checkPlatform(t, tt.in.setup, p)
			}
			for id, want := range tt.levels {
				if got[id] != want {
					t.Errorf("%s: protection %q, want %q", id, got[id], want)
				}
			}
			for id := range got {
				if _, ok := tt.levels[id]; !ok {
					t.Errorf("%s offered, but shouldn't be", id)
				}
			}

			// Platforms come in their groups' order, and every group listed
			// has platforms.
			var seen []string
			for _, p := range platforms {
				if len(seen) == 0 || seen[len(seen)-1] != p.Group {
					if slices.Contains(seen, p.Group) {
						t.Errorf("group %s isn't contiguous", p.Group)
					}
					seen = append(seen, p.Group)
				}
			}
			var listed []string
			for _, g := range groups {
				listed = append(listed, g.ID)
			}
			if !slices.Equal(seen, listed) {
				t.Errorf("groups %v, platforms in %v", listed, seen)
			}
		})
	}

	// With everything, every group is there, in order.
	_, groups := platformsFor(full)
	var ids []string
	for _, g := range groups {
		ids = append(ids, g.ID)
	}
	if want := []string{api.GroupPhones, api.GroupComputers, api.GroupTV, api.GroupConsoles, api.GroupSmartHome, api.GroupBrowsers, api.GroupNetwork}; !slices.Equal(ids, want) {
		t.Errorf("groups = %v, want %v", ids, want)
	}
}

// checkPlatform checks what every platform should have.
func checkPlatform(t *testing.T, setup api.Setup, p api.Platform) {
	t.Helper()
	if p.Group == "" || p.Name == "" || len(p.Steps) == 0 || p.Protection == nil || p.Protection.Summary == "" {
		t.Errorf("%s is incomplete: %+v", p.ID, p)
		return
	}
	level := p.Protection.Level
	if level != api.ProtectionUnavailable && (p.Check == "" || p.Identified == "") {
		t.Errorf("%s: no check or identification", p.ID)
	}
	switch level {
	case api.ProtectionEncrypted:
		if p.Protection.Protocol != "https" && p.Protection.Protocol != "tls" {
			t.Errorf("%s: encrypted with protocol %q", p.ID, p.Protection.Protocol)
		}
	case api.ProtectionPlain:
		if p.Protection.Protocol != "dns" || !strings.HasPrefix(p.Identified, "By its address") {
			t.Errorf("%s: plain DNS, protocol %q, identified %q", p.ID, p.Protection.Protocol, p.Identified)
		}
		if !slices.ContainsFunc(p.Notes, func(n string) bool { return strings.Contains(n, "isn't encrypted") }) && p.ID != "pfsense" {
			t.Errorf("%s: plain DNS without saying it isn't encrypted", p.ID)
		}
	case api.ProtectionUnavailable:
		if p.Protection.Protocol != "" {
			t.Errorf("%s: unavailable with protocol %q", p.ID, p.Protection.Protocol)
		}
	default:
		t.Errorf("%s: protection level %q", p.ID, level)
	}

	// Steps give the settings the server actually has.
	text := strings.Join(p.Steps, " ")
	if level == api.ProtectionPlain && len(setup.DNSAddrs) > 0 && !strings.Contains(text, setup.DNSAddrs[0]) {
		t.Errorf("%s: plain DNS steps don't give the address %s: %q", p.ID, setup.DNSAddrs[0], text)
	}
	if level == api.ProtectionEncrypted && !strings.Contains(text, setup.DoHURL) && !strings.Contains(text, setup.DoTHost) && len(p.Downloads) == 0 {
		t.Errorf("%s: encrypted, but neither steps nor downloads give the settings", p.ID)
	}
	if setup.Device != "" && level != api.ProtectionUnavailable && p.ID != "pfsense" && !strings.Contains(p.Identified, setup.Device) && !strings.HasPrefix(p.Identified, "By its address") {
		t.Errorf("%s: identified %q doesn't name the device", p.ID, p.Identified)
	}

	// Downloads are files the API serves, for this profile and device.
	if p.Download != "" && (len(p.Downloads) == 0 || p.Download != p.Downloads[0].Path) {
		t.Errorf("%s: Download %q isn't the first of Downloads", p.ID, p.Download)
	}
	for _, d := range p.Downloads {
		u, err := url.Parse(d.Path)
		if err != nil || !strings.HasPrefix(u.Path, api.Prefix+"/profiles/"+setup.Profile+"/") || d.Name == "" || d.File == "" || d.ContentType == "" {
			t.Errorf("%s: download %+v", p.ID, d)
			continue
		}
		file := u.Path[strings.LastIndex(u.Path, "/")+1:]
		if file != mobileConfigFile && !slices.Contains(setupFiles, file) {
			t.Errorf("%s: download of unknown file %q", p.ID, file)
		}
		if setup.Device != "" && file != devicesetup.OpenWrtFile && u.Query().Get("device") != setup.Device {
			t.Errorf("%s: download %s isn't for device %s", p.ID, d.Path, setup.Device)
		}
	}
}

func TestPlatformsFor_TenantsAreNotToldToChangeTheServer(t *testing.T) {
	in := fullSetup("")
	in.setup.DNSAddrs = nil // so the unavailable platforms say what to do
	in.tenant = true
	platforms, _ := platformsFor(in)
	for _, p := range platforms {
		for _, step := range p.Steps {
			if strings.Contains(step, "--") {
				t.Errorf("%s: tenant's step %q mentions a server flag", p.ID, step)
			}
		}
	}

	none, _ := platformsFor(setupInputs{setup: api.Setup{Profile: "p"}, tenant: true})
	if len(none) != 1 || none[0].ID != "none" || strings.Contains(none[0].Steps[0], "--") {
		t.Errorf("nothing to set up, for a tenant = %+v", none)
	}
}

func TestPlatformsFor_PlainDNSIdentification(t *testing.T) {
	identified := func(in setupInputs) string {
		platforms, _ := platformsFor(in)
		i := slices.IndexFunc(platforms, func(p api.Platform) bool { return p.ID == "smart-tv" })
		return platforms[i].Identified
	}
	in := fullSetup("")
	if s := identified(in); !strings.Contains(s, "Add the device's address to this profile's devices") || !strings.Contains(s, "DHCP reservation") {
		t.Errorf("unlisted profile: %q", s)
	}
	in.listed = true
	if s := identified(in); !strings.Contains(s, "gets the addresses in its devices and clients") {
		t.Errorf("listed profile: %q", s)
	}
	in.isDefault = true
	if s := identified(in); !strings.Contains(s, "the default profile") {
		t.Errorf("default profile: %q", s)
	}
}

func TestSelfAddrs(t *testing.T) {
	var lookups int
	answer := []netip.Addr{netip.MustParseAddr("::ffff:203.0.113.7"), netip.MustParseAddr("fe80::1"), netip.MustParseAddr("2001:db8::7%eth0"), netip.IPv4Unspecified()}
	c := selfAddrs{lookup: func(ctx context.Context, host string) ([]netip.Addr, error) {
		lookups++
		if _, ok := ctx.Deadline(); !ok {
			t.Error("lookup without a deadline")
		}
		return answer, nil
	}}
	want := []netip.Addr{netip.MustParseAddr("203.0.113.7"), netip.MustParseAddr("2001:db8::7")}
	if got := c.get(t.Context(), "dns.example.com"); !slices.Equal(got, want) {
		t.Errorf("get = %v, want %v", got, want)
	}
	c.get(t.Context(), "dns.example.com")
	if lookups != 1 {
		t.Errorf("%d lookups, want 1: answers are remembered", lookups)
	}
	c.get(t.Context(), "other.example.com")
	if lookups != 2 {
		t.Errorf("a new name wasn't looked up")
	}
	if got := c.get(t.Context(), ""); got != nil {
		t.Errorf("no name: %v", got)
	}

	// Answers are bounded.
	answer = nil
	for i := range 50 {
		answer = append(answer, netip.AddrFrom4([4]byte{198, 51, 100, byte(i + 1)}))
	}
	c.expires = time.Time{}
	if got := c.get(t.Context(), "dns.example.com"); len(got) != devicesetup.MaxAddrs {
		t.Errorf("%d addresses, want at most %d", len(got), devicesetup.MaxAddrs)
	}
}

func TestAdminAPI_SetupDescribesEveryPlatform(t *testing.T) {
	_, c := newSetupServer(t, hostnamePolicy())
	var setup api.Setup
	if resp, body := c.do(http.MethodGet, "/api/v1/profiles/kids/setup?device=tablet", ""); resp.StatusCode != http.StatusOK || !decodeInto(body, &setup) {
		t.Fatalf("setup = %d %s", resp.StatusCode, body)
	}
	if !slices.Equal(setup.ServerAddrs, []string{testServerAddr.String()}) || !slices.Equal(setup.DNSAddrs, []string{"192.168.1.10"}) {
		t.Errorf("server addrs %v, DNS addrs %v", setup.ServerAddrs, setup.DNSAddrs)
	}
	if len(setup.Groups) != 7 {
		t.Errorf("groups = %v, want all 7", setup.Groups)
	}
	for _, p := range setup.Platforms {
		checkPlatform(t, setup, p)
	}
}

// mobileConfigVariants are the Apple configuration profiles to test, by
// golden file, with the query that asks for each.
var mobileConfigVariants = []struct{ golden, query, protocol string }{
	{"kids-tablet.mobileconfig", "", "HTTPS"},
	{"kids-tablet-tls.mobileconfig", "&protocol=tls", "TLS"},
	{"kids-tablet-locked.mobileconfig", "&lock=true", "HTTPS"},
}

func TestMobileConfig_Variants(t *testing.T) {
	_, c := newSetupServer(t, hostnamePolicy())

	var setup api.Setup
	_, body := c.do(http.MethodGet, "/api/v1/profiles/kids/setup?device=tablet", "")
	decodeInto(body, &setup)
	apple := setup.Platforms[slices.IndexFunc(setup.Platforms, func(p api.Platform) bool { return p.ID == "apple" })]
	if len(apple.Downloads) != 3 {
		t.Fatalf("Apple downloads = %+v, want DoH, DoT, and locked", apple.Downloads)
	}

	var identifiers []string
	for i, v := range mobileConfigVariants {
		path := "/api/v1/profiles/kids/apple.mobileconfig?device=tablet" + v.query
		if got := apple.Downloads[i].Path; !sameRequest(got, path) {
			t.Errorf("download %d = %s, want %s", i, got, path)
		}
		resp, b := c.do(http.MethodGet, path, "")
		if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != api.MobileConfigType {
			t.Fatalf("%s = %d %s %s", path, resp.StatusCode, resp.Header.Get("Content-Type"), b)
		}
		// The server signs profiles with its certificate; the golden file
		// is the profile inside the signature, which doesn't change.
		if m, err := cmstest.Decode(b); err == nil {
			b = m.Content
		}
		golden(t, v.golden, b)

		root, payload := parseMobileConfig(t, b)
		dns := lookup[plist.Dict](t, payload, "DNSSettings")
		if p := lookup[plist.String](t, dns, "DNSProtocol"); string(p) != v.protocol {
			t.Errorf("%s: DNSProtocol %q, want %q", v.golden, p, v.protocol)
		}
		switch v.protocol {
		case "HTTPS":
			if u := lookup[plist.String](t, dns, "ServerURL"); string(u) != setup.DoHURL {
				t.Errorf("%s: ServerURL %q, want %q", v.golden, u, setup.DoHURL)
			}
		case "TLS":
			if n := lookup[plist.String](t, dns, "ServerName"); string(n) != setup.DoTHost {
				t.Errorf("%s: ServerName %q, want %q", v.golden, n, setup.DoTHost)
			}
		}
		_, locked := payload.Lookup("ProhibitDisablement")
		if locked != strings.Contains(v.query, "lock=true") {
			t.Errorf("%s: ProhibitDisablement present = %v", v.golden, locked)
		}
		// Every variant replaces the others when installed.
		identifiers = append(identifiers, string(lookup[plist.String](t, root, "PayloadIdentifier"))+" "+string(lookup[plist.String](t, payload, "PayloadIdentifier")))
	}
	if len(slices.Compact(slices.Clone(identifiers))) != 1 {
		t.Errorf("variants have different identifiers, so they'd install side by side: %v", identifiers)
	}

	// Other devices get other identifiers, so they don't replace each other.
	_, other := c.do(http.MethodGet, "/api/v1/profiles/kids/apple.mobileconfig?device=phone", "")
	if m, err := cmstest.Decode(other); err == nil {
		other = m.Content
	}
	root, _ := parseMobileConfig(t, other)
	if id := string(lookup[plist.String](t, root, "PayloadIdentifier")); strings.HasPrefix(identifiers[0], id+" ") {
		t.Errorf("another device got identifier %s too", id)
	}

	for path, want := range map[string]int{
		"/api/v1/profiles/kids/apple.mobileconfig?lock=maybe":   http.StatusBadRequest,
		"/api/v1/profiles/kids/apple.mobileconfig?lock=false":   http.StatusOK,
		"/api/v1/profiles/nobody/apple.mobileconfig?lock=true":  http.StatusNotFound,
		"/api/v1/profiles/kids/apple.mobileconfig?protocol=tls": http.StatusOK,
	} {
		if resp, body := c.do(http.MethodGet, path, ""); resp.StatusCode != want {
			t.Errorf("GET %s = %d %s, want %d", path, resp.StatusCode, body, want)
		}
	}
}

// sameRequest reports whether two API paths ask for the same thing,
// whatever their query's order.
func sameRequest(a, b string) bool {
	ua, err1 := url.Parse(a)
	ub, err2 := url.Parse(b)
	return err1 == nil && err2 == nil && ua.Path == ub.Path && ua.Query().Encode() == ub.Query().Encode()
}

// parseMobileConfig parses a configuration profile, checking its frame,
// and returns it and its one DNS settings payload.
func parseMobileConfig(t *testing.T, b []byte) (root, payload plist.Dict) {
	t.Helper()
	v, err := plist.Unmarshal(b)
	if err != nil {
		t.Fatalf("configuration profile doesn't parse: %v\n%s", err, b)
	}
	root, ok := v.(plist.Dict)
	if !ok {
		t.Fatalf("configuration profile is a %T", v)
	}
	if typ := lookup[plist.String](t, root, "PayloadType"); typ != "Configuration" {
		t.Errorf("PayloadType %q", typ)
	}
	if removal := lookup[plist.Bool](t, root, "PayloadRemovalDisallowed"); removal {
		t.Error("the profile can't be removed")
	}
	uuid := regexp.MustCompile(`^[0-9A-F]{8}-[0-9A-F]{4}-8[0-9A-F]{3}-[89AB][0-9A-F]{3}-[0-9A-F]{12}$`)
	if u := lookup[plist.String](t, root, "PayloadUUID"); !uuid.MatchString(string(u)) {
		t.Errorf("PayloadUUID %q", u)
	}
	content := lookup[plist.Array](t, root, "PayloadContent")
	if len(content) != 1 {
		t.Fatalf("%d payloads, want 1", len(content))
	}
	payload, ok = content[0].(plist.Dict)
	if !ok {
		t.Fatalf("payload is a %T", content[0])
	}
	if typ := lookup[plist.String](t, payload, "PayloadType"); typ != "com.apple.dnsSettings.managed" {
		t.Errorf("payload type %q", typ)
	}
	if u := lookup[plist.String](t, payload, "PayloadUUID"); !uuid.MatchString(string(u)) {
		t.Errorf("payload UUID %q", u)
	}
	return root, payload
}

// lookup returns d's key, which must be a T.
func lookup[T plist.Value](t *testing.T, d plist.Dict, key string) T {
	t.Helper()
	v, ok := d.Lookup(key)
	tv, isT := v.(T)
	if !ok || !isT {
		t.Fatalf("%s = %#v, want a %T", key, v, *new(T))
	}
	return tv
}

func TestAdminAPI_SetupFiles(t *testing.T) {
	_, c := newSetupServer(t, hostnamePolicy())

	for _, tt := range []struct {
		path, filename string
		want           []string
	}{
		{"/api/v1/profiles/kids/doh-setup.ps1?device=laptop", "doh-setup.ps1", []string{
			"$Template = 'https://" + testHostname + "/dns-query/kids/laptop'",
			"[string[]] $ServerAddress = @('203.0.113.7')",
		}},
		{"/api/v1/profiles/kids/doh.conf?device=laptop", "doh.conf", []string{
			"\nDNS=203.0.113.7#laptop--kids." + testHostname + "\n",
			"\nDNSOverTLS=yes\n",
		}},
		{"/api/v1/profiles/kids/doh-openwrt.sh", "doh-openwrt.sh", []string{
			"uci add_list dhcp.lan.dhcp_option='6,192.168.1.10'",
			"from profile kids's setup",
		}},
	} {
		resp, body := c.do(http.MethodGet, tt.path, "")
		if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != api.TextFileType {
			t.Errorf("%s = %d %q %s", tt.path, resp.StatusCode, resp.Header.Get("Content-Type"), body)
			continue
		}
		if got := resp.Header.Get("Content-Disposition"); got != `attachment; filename="`+tt.filename+`"` {
			t.Errorf("%s: Content-Disposition %q", tt.path, got)
		}
		if resp.Header.Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("%s: no nosniff", tt.path)
		}
		for _, want := range tt.want {
			if !strings.Contains(string(body), want) {
				t.Errorf("%s lacks %q:\n%s", tt.path, want, body)
			}
		}
	}

	for path, want := range map[string]int{
		"/api/v1/profiles/kids/doh-setup.ps1?device=Bad_Name": http.StatusBadRequest,
		"/api/v1/profiles/nobody/doh.conf":                    http.StatusNotFound,
		"/api/v1/profiles/kids/doh-openwrt.sh?device=a%2Fb":   http.StatusBadRequest,
		"/api/v1/profiles/kids/passwd":                        http.StatusNotFound,
	} {
		if resp, body := c.do(http.MethodGet, path, ""); resp.StatusCode != want {
			t.Errorf("GET %s = %d %s, want %d", path, resp.StatusCode, body, want)
		}
	}
}

func TestAdminAPI_SetupFilesNeedWhatTheyUse(t *testing.T) {
	// A server with DoH and DoT, whose name doesn't resolve, and no plain
	// DNS: Linux needs an address, and OpenWrt plain DNS.
	s := newDoTServer(t, hostnamePolicy())
	c := apiClient{t, startAdmin(t, s), token(t, s.config.DataDir, ReaderTokenFile)}
	for path, want := range map[string]int{
		"/api/v1/profiles/kids/doh-setup.ps1":  http.StatusOK, // looks the name up when it runs
		"/api/v1/profiles/kids/doh.conf":       http.StatusConflict,
		"/api/v1/profiles/kids/doh-openwrt.sh": http.StatusConflict,
	} {
		if resp, body := c.do(http.MethodGet, path, ""); resp.StatusCode != want {
			t.Errorf("GET %s = %d %s, want %d", path, resp.StatusCode, body, want)
		}
	}
	_, script := c.do(http.MethodGet, "/api/v1/profiles/kids/doh-setup.ps1", "")
	if !strings.Contains(string(script), "$ServerAddress = @()") {
		t.Errorf("script without known addresses:\n%s", script)
	}

	// Without a host name, nothing encrypted can be made.
	up, _ := startZone(t, nil)
	plain, dataDir := newPolicyServer(t, up, hostnamePolicy())
	c = apiClient{t, startAdmin(t, plain), token(t, dataDir, ReaderTokenFile)}
	for _, path := range []string{"/api/v1/profiles/kids/doh-setup.ps1", "/api/v1/profiles/kids/doh.conf"} {
		if resp, _ := c.do(http.MethodGet, path, ""); resp.StatusCode != http.StatusConflict {
			t.Errorf("GET %s without a host name = %d, want 409", path, resp.StatusCode)
		}
	}
}

func TestSetupFiles_TenantsOwnProfilesOnly(t *testing.T) {
	f := newTenantFixture(t)
	for _, file := range append([]string{mobileConfigFile}, setupFiles...) {
		if status := f.smith.do(http.MethodGet, "/api/v1/profiles/lab/"+file, "", nil); status != http.StatusNotFound {
			t.Errorf("tenant's download of the operator's %s = %d, want 404", file, status)
		}
		// Their own profile is theirs; this server has nothing encrypted
		// to offer, but the refusal isn't about whose it is.
		if status := f.smith.do(http.MethodGet, "/api/v1/profiles/smith-home/"+file, "", nil); status == http.StatusNotFound || status == http.StatusForbidden {
			t.Errorf("tenant's download of their own %s = %d", file, status)
		}
	}
}

func TestSetupLinks_PageAndFiles(t *testing.T) {
	s, _ := newSetupServer(t, hostnamePolicy())
	admin := apiClient{t, startAdmin(t, s), token(t, s.config.DataDir, AdminTokenFile)}
	resp, body := admin.do(http.MethodPost, "/api/v1/profiles/kids/setup-links?device=tablet", "")
	var link api.SetupLink
	if resp.StatusCode != http.StatusCreated || !decodeInto(body, &link) {
		t.Fatalf("create = %d %s", resp.StatusCode, body)
	}
	u, _ := url.Parse(link.URL)

	get := func(path string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "https://"+testHostname+path, nil))
		return rec
	}

	// The page shows every group, and offers every file under the link.
	page := get(u.Path)
	html := page.Body.String()
	for _, g := range groupNames {
		if !strings.Contains(html, `<h2 class="group">`+htmlText(g.Name)+`</h2>`) {
			t.Errorf("page lacks group %q", g.Name)
		}
	}
	for _, want := range []string{
		`href="` + u.Path + `/doh-setup.ps1"`,
		`href="` + u.Path + `/doh.conf"`,
		`href="` + u.Path + `/doh-openwrt.sh"`,
		`href="` + u.Path + `/apple.mobileconfig?protocol=tls"`,
		`href="` + u.Path + `/apple.mobileconfig?lock=true"`,
		`class="badge encrypted">Encrypted<`,
		`class="badge plain">Plain DNS<`,
		"Check it's working", "How doh knows it",
	} {
		if !strings.Contains(html, want) {
			t.Errorf("page lacks %s", want)
		}
	}
	if strings.Contains(html, "/api/v1/") || strings.Contains(html, "device=") {
		t.Error("page links to the admin API, or lets the query name the device")
	}

	// Files are for the link's device, whatever the query says.
	for file, want := range map[string]string{
		"doh-setup.ps1":                   "/dns-query/kids/tablet'",
		"doh.conf":                        "#tablet--kids." + testHostname,
		"doh-openwrt.sh":                  "6,192.168.1.10",
		"apple.mobileconfig?lock=true":    "ProhibitDisablement",
		"apple.mobileconfig?protocol=tls": "<string>tablet--kids." + testHostname + "</string>",
		"doh-setup.ps1?device=other":      "/dns-query/kids/tablet'",
		"apple.mobileconfig?device=other": "/dns-query/kids/tablet<",
		"doh.conf?device=other&profile=x": "#tablet--kids." + testHostname,
	} {
		rec := get(u.Path + "/" + file)
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), want) || !strings.HasPrefix(rec.Header().Get("Content-Disposition"), "attachment; ") {
			t.Errorf("%s = %d %q, lacks %q", file, rec.Code, rec.Header().Get("Content-Disposition"), want)
		}
		if rec.Header().Get("Cache-Control") != "no-store" {
			t.Errorf("%s: Cache-Control %q", file, rec.Header().Get("Cache-Control"))
		}
	}

	// Expired links serve no files.
	s.setupLinks.now = func() time.Time { return time.Now().Add(SetupLinkTTL) }
	for _, file := range append([]string{mobileConfigFile}, setupFiles...) {
		if rec := get(u.Path + "/" + file); rec.Code != http.StatusNotFound || strings.Contains(rec.Body.String(), testHostname) {
			t.Errorf("%s from an expired link = %d", file, rec.Code)
		}
	}
}

// htmlText escapes s as html/template escapes text.
func htmlText(s string) string {
	return strings.NewReplacer("&", "&amp;", "'", "&#39;").Replace(s)
}

// decodeInto decodes JSON b into v, reporting whether it could.
func decodeInto(b []byte, v any) bool { return json.Unmarshal(b, v) == nil }
