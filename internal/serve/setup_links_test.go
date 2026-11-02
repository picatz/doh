package serve

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/picatz/doh/internal/api"
	"github.com/picatz/doh/internal/policy"
	"github.com/picatz/doh/internal/qr"
)

func TestSetupLinks(t *testing.T) {
	s := newDoTServer(t, hostnamePolicy())
	admin := apiClient{t, startAdmin(t, s), token(t, s.config.DataDir, AdminTokenFile)}

	resp, body := admin.do(http.MethodPost, "/api/v1/profiles/kids/setup-links?device=tablet", "")
	var link api.SetupLink
	if err := json.Unmarshal(body, &link); resp.StatusCode != http.StatusCreated || err != nil {
		t.Fatalf("create = %d %s", resp.StatusCode, body)
	}
	u, err := url.Parse(link.URL)
	if err != nil || u.Scheme != "https" || u.Host != testHostname || !strings.HasPrefix(u.Path, setupPath) || len(strings.TrimPrefix(u.Path, setupPath)) != 22 {
		t.Fatalf("link = %q, want https://%s%s<code>", link.URL, testHostname, setupPath)
	}
	if d := time.Until(link.Expires); d < SetupLinkTTL-time.Minute || d > SetupLinkTTL {
		t.Errorf("expires in %v, want %v", d, SetupLinkTTL)
	}
	// The QR code is the link's, with a quiet zone.
	code, err := qr.Encode([]byte(link.URL), qr.M)
	if err != nil {
		t.Fatal(err)
	}
	if link.QR == nil || link.QR.Size != code.Size()+8 || link.QR.Path != code.SVGPath(4) {
		t.Errorf("QR = %+v, want the link's code", link.QR)
	}

	// On the public listener: the page, then the profile it installs.
	get := func(path string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "https://"+testHostname+path, nil))
		return rec
	}
	page := get(u.Path)
	if page.Code != http.StatusOK || !strings.Contains(page.Header().Get("Content-Type"), "text/html") {
		t.Fatalf("page = %d %q", page.Code, page.Header().Get("Content-Type"))
	}
	for _, want := range []string{"Protect this device", "<strong>tablet</strong>", u.Path + "/apple.mobileconfig", "https://" + testHostname + "/dns-query/kids/tablet", "Android"} {
		if !strings.Contains(page.Body.String(), want) {
			t.Errorf("page lacks %q", want)
		}
	}
	for header, want := range map[string]string{"Cache-Control": "no-store", "Referrer-Policy": "no-referrer", "X-Robots-Tag": "noindex"} {
		if got := page.Header().Get(header); got != want {
			t.Errorf("%s = %q, want %q", header, got, want)
		}
	}
	if csp := page.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'none'") || strings.Contains(csp, "script-src") {
		t.Errorf("CSP = %q, want no scripts at all", csp)
	}
	cfg := get(u.Path + "/apple.mobileconfig")
	if cfg.Code != http.StatusOK || cfg.Header().Get("Content-Type") != api.MobileConfigType || !strings.Contains(cfg.Body.String(), "/dns-query/kids/tablet") {
		t.Errorf("mobileconfig = %d %q", cfg.Code, cfg.Header().Get("Content-Type"))
	}

	// Unknown, malformed, and other files are refused, without hinting why.
	for _, path := range []string{setupPath + "AAAAAAAAAAAAAAAAAAAAAA", setupPath + "short", u.Path + "/passwd"} {
		if rec := get(path); rec.Code != http.StatusNotFound {
			t.Errorf("%s = %d, want 404", path, rec.Code)
		}
	}
	// Dot segments are cleaned away before any setup handler sees them.
	if rec := get(setupPath + "../admin"); rec.Code == http.StatusOK {
		t.Errorf("a dot-segment path was served")
	}

	// Links expire.
	s.setupLinks.now = func() time.Time { return time.Now().Add(SetupLinkTTL) }
	if rec := get(u.Path); rec.Code != http.StatusNotFound || !strings.Contains(rec.Body.String(), "expired") {
		t.Errorf("expired link = %d", rec.Code)
	}

	// Readers can't make links, and other profiles' rules apply as usual.
	reader := apiClient{t, admin.base, token(t, s.config.DataDir, ReaderTokenFile)}
	if resp, _ := reader.do(http.MethodPost, "/api/v1/profiles/kids/setup-links", ""); resp.StatusCode != http.StatusForbidden {
		t.Errorf("reader create = %d, want 403", resp.StatusCode)
	}
	for _, path := range []string{"/api/v1/profiles/nobody/setup-links", "/api/v1/profiles/kids/setup-links?device=Not_Valid"} {
		if resp, _ := admin.do(http.MethodPost, path, ""); resp.StatusCode/100 != 4 {
			t.Errorf("%s = %d, want a client error", path, resp.StatusCode)
		}
	}
}

func TestSetupLinks_NeedAPublicName(t *testing.T) {
	up, _ := startZone(t, nil)
	s, dataDir := newPolicyServer(t, up, &policy.Policy{Profiles: []policy.Profile{{ID: "default"}}})
	admin := apiClient{t, startAdmin(t, s), token(t, dataDir, AdminTokenFile)}
	if resp, body := admin.do(http.MethodPost, "/api/v1/profiles/default/setup-links", ""); resp.StatusCode != http.StatusConflict || !strings.Contains(string(body), "--hostname") {
		t.Errorf("create without a host name = %d %s, want 409 naming --hostname", resp.StatusCode, body)
	}
}

func TestSetupLinks_Bounded(t *testing.T) {
	l := newSetupLinks()
	for range maxSetupLinks + 50 {
		if _, _, err := l.create("p", ""); err != nil {
			t.Fatal(err)
		}
	}
	if n := len(l.links); n > maxSetupLinks {
		t.Errorf("%d links kept, want at most %d", n, maxSetupLinks)
	}
}

func TestSetupLinks_TenantsOwnProfilesOnly(t *testing.T) {
	f := newTenantFixture(t)
	if status := f.smith.do(http.MethodPost, "/api/v1/profiles/lab/setup-links", "", nil); status != http.StatusNotFound {
		t.Errorf("tenant link to the operator's profile = %d, want 404", status)
	}
}
