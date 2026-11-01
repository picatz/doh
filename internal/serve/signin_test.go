package serve

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"

	"github.com/picatz/doh/internal/api"
	"github.com/picatz/doh/internal/policy"
	"github.com/picatz/doh/internal/webauthn"
	"github.com/picatz/doh/internal/webauthn/webauthntest"
)

// uiBrowser is a browser on the admin UI, at localhost.
type uiBrowser struct {
	t      *testing.T
	base   string // http://localhost:{port}
	client *http.Client
}

func newUIBrowser(t *testing.T, adminURL string) *uiBrowser {
	t.Helper()
	u, err := url.Parse(adminURL)
	if err != nil {
		t.Fatal(err)
	}
	jar, _ := cookiejar.New(nil)
	return &uiBrowser{t: t, base: "http://localhost:" + u.Port(), client: &http.Client{
		Jar: jar,
		// Don't follow redirects, so tests can see them.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

// do sends a same-origin request, as the UI's own scripts would.
func (b *uiBrowser) do(method, path, body string, out any) int {
	b.t.Helper()
	req, err := http.NewRequestWithContext(b.t.Context(), method, b.base+path, strings.NewReader(body))
	if err != nil {
		b.t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Origin", b.base)
	resp, err := b.client.Do(req)
	if err != nil {
		b.t.Fatal(err)
	}
	defer resp.Body.Close()
	if out != nil && resp.StatusCode < 300 {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			b.t.Fatal(err)
		}
	}
	return resp.StatusCode
}

// signIn opens a sign-in link's URL as the UI would: by posting the code in
// its fragment.
func (b *uiBrowser) signIn(link api.SigninLink) {
	b.t.Helper()
	_, code, ok := strings.Cut(link.URL, "#signin=")
	if !ok {
		b.t.Fatalf("link %q has no code", link.URL)
	}
	if status := b.do(http.MethodPost, "/auth/link", `{"code":"`+code+`"}`, nil); status != http.StatusOK {
		b.t.Fatalf("signing in with a link = %d", status)
	}
}

func newSigninLink(t *testing.T, c apiClient, role string) api.SigninLink {
	t.Helper()
	resp, body := c.do(http.MethodPost, "/api/v1/signin-links", `{"role":"`+role+`"}`)
	var link api.SigninLink
	if err := json.Unmarshal(body, &link); resp.StatusCode != http.StatusCreated || err != nil {
		t.Fatalf("creating a sign-in link = %d %s", resp.StatusCode, body)
	}
	return link
}

func TestAdmin_BrowserSignIn(t *testing.T) {
	up, _ := startZone(t, nil)
	s, dataDir := newPolicyServer(t, up, &policy.Policy{Profiles: []policy.Profile{{ID: "default"}}})
	adminURL := startAdmin(t, s)
	admin := apiClient{t, adminURL, token(t, dataDir, AdminTokenFile)}
	reader := apiClient{t, adminURL, token(t, dataDir, ReaderTokenFile)}

	// Only admins make links; links open the UI at localhost.
	if resp, _ := reader.do(http.MethodPost, "/api/v1/signin-links", `{}`); resp.StatusCode != http.StatusForbidden {
		t.Errorf("reader token made a sign-in link: %d", resp.StatusCode)
	}
	link := newSigninLink(t, admin, "admin")
	if !strings.HasPrefix(link.URL, "http://localhost:") || link.PasskeyRequired {
		t.Errorf("link = %+v", link)
	}

	b := newUIBrowser(t, adminURL)
	if status := b.do(http.MethodGet, "/api/v1/status", "", nil); status != http.StatusUnauthorized {
		t.Fatalf("signed-out browser reached the API: %d", status)
	}
	b.signIn(link)

	// The session works for the API, reads and writes.
	if status := b.do(http.MethodGet, "/api/v1/status", "", nil); status != http.StatusOK {
		t.Fatalf("signed-in browser = %d", status)
	}
	if status := b.do(http.MethodPost, "/api/v1/profiles/default/deny", `{"domain":"x.example"}`, nil); status != http.StatusOK {
		t.Errorf("signed-in admin change = %d", status)
	}

	// But not from another site, even with the cookie.
	req, _ := http.NewRequest(http.MethodPost, b.base+"/api/v1/profiles/default/deny", strings.NewReader(`{"domain":"y.example"}`))
	req.Header.Set("Origin", "https://evil.example")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	resp, err := b.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("cross-site change with a session = %d, want 403", resp.StatusCode)
	}

	// Reader links make reader sessions.
	rb := newUIBrowser(t, adminURL)
	rb.signIn(newSigninLink(t, admin, "reader"))
	if status := rb.do(http.MethodGet, "/api/v1/policy", "", nil); status != http.StatusOK {
		t.Errorf("reader session read = %d", status)
	}
	if status := rb.do(http.MethodPost, "/api/v1/profiles/default/deny", `{"domain":"z.example"}`, nil); status != http.StatusForbidden {
		t.Errorf("reader session change = %d, want 403", status)
	}

	// Add a passkey; then links need one to finish, and people are listed.
	auth := &webauthntest.Authenticator{}
	var reg webauthn.RegistrationOptions
	if status := b.do(http.MethodPost, "/auth/passkey/register", `{"name":"Laptop","person":"Alice"}`, &reg); status != http.StatusOK {
		t.Fatalf("begin passkey = %d", status)
	}
	created, err := auth.Create(reg.Options.PublicKey, webauthntest.Response{Origin: b.base})
	if err != nil {
		t.Fatal(err)
	}
	if status := b.do(http.MethodPost, "/auth/passkey/register/"+reg.ID, string(created), nil); status != http.StatusCreated {
		t.Fatalf("finish passkey = %d", status)
	}

	_, body := admin.do(http.MethodGet, "/api/v1/people", "")
	var people api.People
	if err := json.Unmarshal(body, &people); err != nil || len(people.People) != 1 || people.People[0].Name != "Alice" {
		t.Fatalf("people = %s", body)
	}
	if strings.Contains(string(body), "credential") {
		t.Error("the people listing exposes credential records")
	}

	link = newSigninLink(t, admin, "admin")
	if !link.PasskeyRequired {
		t.Error("link doesn't say a passkey is required")
	}
	pending := newUIBrowser(t, adminURL)
	pending.signIn(link)
	if status := pending.do(http.MethodGet, "/api/v1/status", "", nil); status != http.StatusUnauthorized {
		t.Errorf("a link alone reached the API once passkeys exist: %d", status)
	}

	var login webauthn.LoginOptions
	pending.do(http.MethodPost, "/auth/passkey/login", "", &login)
	assertion, err := auth.Get(login.Options.PublicKey, webauthntest.Response{Origin: pending.base})
	if err != nil {
		t.Fatal(err)
	}
	if status := pending.do(http.MethodPost, "/auth/passkey/login/"+login.ID, string(assertion), nil); status != http.StatusOK {
		t.Fatalf("passkey after link = %d", status)
	}
	if status := pending.do(http.MethodGet, "/api/v1/status", "", nil); status != http.StatusOK {
		t.Errorf("link and passkey didn't reach the API: %d", status)
	}

	// Removing Alice signs her out everywhere, and links work alone again,
	// so an operator who loses every passkey can recover with the token.
	id := people.People[0].ID
	if resp, _ := admin.do(http.MethodDelete, "/api/v1/people/"+id, ""); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete person = %d", resp.StatusCode)
	}
	if status := pending.do(http.MethodGet, "/api/v1/status", "", nil); status != http.StatusUnauthorized {
		t.Errorf("removed person's session still works: %d", status)
	}
	if link := newSigninLink(t, admin, "admin"); link.PasskeyRequired {
		t.Error("passkeys still required after removing everyone")
	}
}

func TestAdmin_RedirectsLoopbackIPToLocalhost(t *testing.T) {
	up, _ := startZone(t, nil)
	s, _ := newPolicyServer(t, up, nil)
	adminURL := startAdmin(t, s)

	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Get(adminURL + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(adminURL, "http://"))
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "http://localhost:"+port+"/" {
		t.Errorf("GET %s/ = %d to %q, want a redirect to localhost", adminURL, resp.StatusCode, resp.Header.Get("Location"))
	}
}

func TestAdmin_SigninOffWithoutOrigin(t *testing.T) {
	up, _ := startZone(t, nil)
	s, _ := newPolicyServer(t, up, nil)

	// A non-loopback listener without --admin-origin has no browser
	// sign-in; tokens still work.
	if err := s.configureSignin(&net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 9090}); err != nil {
		t.Fatal(err)
	}
	if s.signin.Load() != nil {
		t.Error("browser sign-in on without an origin")
	}
}
