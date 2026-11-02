package signin

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/picatz/doh/internal/webauthn"
	"github.com/picatz/doh/internal/webauthn/webauthntest"
)

// clock is an adjustable time source.
type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

// fixture is a sign-in service served over HTTP.
type fixture struct {
	t       *testing.T
	service *Service
	clock   *clock
	url     string // where the server listens
	origin  string // the origin browsers see, on localhost
}

func newFixture(t *testing.T, path string) *fixture {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, port, _ := net.SplitHostPort(ln.Addr().String())

	// Start at the real time: cookie jars expire cookies by it.
	c := &clock{now: time.Now()}
	service, err := New(Config{Origins: []string{"http://localhost:" + port}, Path: path, Now: c.Now})
	if err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewUnstartedServer(service.Handler())
	srv.Listener.Close()
	srv.Listener = ln
	srv.Start()
	t.Cleanup(srv.Close)

	return &fixture{t: t, service: service, clock: c, url: srv.URL, origin: "http://localhost:" + port}
}

// browser is a browser with its own cookies and authenticator.
type browser struct {
	f      *fixture
	client *http.Client
	auth   *webauthntest.Authenticator
}

func (f *fixture) browser() *browser {
	jar, err := cookiejar.New(nil)
	if err != nil {
		f.t.Fatal(err)
	}
	return &browser{f: f, client: &http.Client{Jar: jar}, auth: &webauthntest.Authenticator{}}
}

// post sends body as JSON (or raw bytes) and decodes the response into
// out, returning the status.
func (b *browser) post(path string, body, out any) int {
	b.f.t.Helper()
	var r io.Reader
	switch body := body.(type) {
	case nil:
		r = strings.NewReader("{}")
	case []byte:
		r = bytes.NewReader(body)
	default:
		encoded, err := json.Marshal(body)
		if err != nil {
			b.f.t.Fatal(err)
		}
		r = bytes.NewReader(encoded)
	}
	resp, err := b.client.Post(b.f.url+path, "application/json", r)
	if err != nil {
		b.f.t.Fatal(err)
	}
	defer resp.Body.Close()
	if out != nil && resp.StatusCode < 300 {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			b.f.t.Fatal(err)
		}
	}
	return resp.StatusCode
}

func (b *browser) status() SessionStatus {
	b.f.t.Helper()
	resp, err := b.client.Get(b.f.url + Prefix + "/session")
	if err != nil {
		b.f.t.Fatal(err)
	}
	defer resp.Body.Close()
	var st SessionStatus
	if err := json.NewDecoder(resp.Body).Decode(&st); err != nil {
		b.f.t.Fatal(err)
	}
	return st
}

func (b *browser) useLink(code string) int {
	return b.post(Prefix+"/link", map[string]string{"code": code}, nil)
}

func (f *fixture) link(role Role) string {
	f.t.Helper()
	code, _, err := f.service.NewLink(role, "")
	if err != nil {
		f.t.Fatal(err)
	}
	return code
}

// addPasskey registers a passkey from b's session.
func (b *browser) addPasskey(name, person string) int {
	b.f.t.Helper()
	var options webauthn.RegistrationOptions
	if status := b.post(Prefix+"/passkey/register", map[string]string{"name": name, "person": person}, &options); status != http.StatusOK {
		return status
	}
	response, err := b.auth.Create(options.Options.PublicKey, webauthntest.Response{Origin: b.f.origin})
	if err != nil {
		b.f.t.Fatal(err)
	}
	return b.post(Prefix+"/passkey/register/"+options.ID, response, nil)
}

// signInWithPasskey signs in with b's authenticator, with r editing the
// response.
func (b *browser) signInWithPasskey(r webauthntest.Response) int {
	b.f.t.Helper()
	var options webauthn.LoginOptions
	if status := b.post(Prefix+"/passkey/login", nil, &options); status != http.StatusOK {
		b.f.t.Fatalf("begin login: %d", status)
	}
	if r.Origin == "" {
		r.Origin = b.f.origin
	}
	response, err := b.auth.Get(options.Options.PublicKey, r)
	if err != nil {
		b.f.t.Fatal(err)
	}
	return b.post(Prefix+"/passkey/login/"+options.ID, response, nil)
}

func TestSignIn_LinkThenPasskey(t *testing.T) {
	f := newFixture(t, filepath.Join(t.TempDir(), "people.json"))
	alice := f.browser()

	// With no passkeys yet, a link signs in on its own.
	if status := alice.useLink(f.link(RoleAdmin)); status != http.StatusOK {
		t.Fatalf("link = %d", status)
	}
	st := alice.status()
	if !st.SignedIn || st.Session.Method != "link" || st.Session.Role != RoleAdmin || st.PasskeysRequired {
		t.Fatalf("after link: %+v", st)
	}

	// Adding a passkey makes Alice a person, under a new session ID.
	before := alice.client.Jar.Cookies(mustURL(t, f.url))
	if status := alice.addPasskey("MacBook", "Alice"); status != http.StatusCreated {
		t.Fatalf("add passkey = %d", status)
	}
	st = alice.status()
	if !st.SignedIn || st.Session.Person == "" || st.Session.Name != "Alice" || !st.PasskeysRequired {
		t.Fatalf("after adding a passkey: %+v", st)
	}
	stale := f.browser()
	stale.client.Jar.SetCookies(mustURL(t, f.url), before)
	if stale.status().Session != nil {
		t.Error("the session ID didn't change when the session became Alice's")
	}

	// Now a link alone isn't enough: it needs a passkey to complete.
	bob := f.browser()
	bob.auth = alice.auth // Alice's passkey, on another browser
	if status := bob.useLink(f.link(RoleAdmin)); status != http.StatusOK {
		t.Fatalf("second link = %d", status)
	}
	if st := bob.status(); st.SignedIn || !st.Session.Pending {
		t.Fatalf("link with passkeys required: %+v, want pending", st)
	}
	if status := bob.addPasskey("Phone", "Mallory"); status != http.StatusUnauthorized {
		t.Errorf("pending session added a passkey: %d", status)
	}
	if status := bob.signInWithPasskey(webauthntest.Response{}); status != http.StatusOK {
		t.Fatalf("completing with a passkey = %d", status)
	}
	if st := bob.status(); !st.SignedIn || st.Session.Method != "link+passkey" || st.Session.Name != "Alice" {
		t.Errorf("after completing: %+v", st)
	}

	// A passkey signs in on its own, too.
	carol := f.browser()
	carol.auth = alice.auth
	if status := carol.signInWithPasskey(webauthntest.Response{}); status != http.StatusOK {
		t.Fatalf("passkey sign-in = %d", status)
	}
	if st := carol.status(); !st.SignedIn || st.Session.Method != "passkey" || st.Session.Role != RoleAdmin {
		t.Errorf("after passkey sign-in: %+v", st)
	}

	// Signing out ends the session.
	if status := carol.post(Prefix+"/signout", nil, nil); status != http.StatusNoContent {
		t.Errorf("sign out = %d", status)
	}
	if carol.status().Session != nil {
		t.Error("signed out session still live")
	}
}

func TestSignIn_RejectsBadLinks(t *testing.T) {
	f := newFixture(t, "")
	b := f.browser()

	code := f.link(RoleAdmin)
	if status := b.useLink(code); status != http.StatusOK {
		t.Fatalf("link = %d", status)
	}
	if status := f.browser().useLink(code); status != http.StatusUnauthorized {
		t.Errorf("replayed link = %d, want 401", status)
	}
	if status := f.browser().useLink("forged-" + code[7:]); status != http.StatusUnauthorized {
		t.Errorf("forged link = %d, want 401", status)
	}
	if status := f.browser().useLink(""); status != http.StatusUnauthorized {
		t.Errorf("empty link = %d, want 401", status)
	}

	expired := f.link(RoleAdmin)
	f.clock.Advance(DefaultLinkTTL)
	if status := f.browser().useLink(expired); status != http.StatusUnauthorized {
		t.Errorf("expired link = %d, want 401", status)
	}

	if _, _, err := f.service.NewLink("root", ""); err == nil {
		t.Error("NewLink accepted an invalid role")
	}
}

func TestSignIn_ReaderLink(t *testing.T) {
	f := newFixture(t, "")
	b := f.browser()
	if status := b.useLink(f.link(RoleReader)); status != http.StatusOK {
		t.Fatal(status)
	}
	if st := b.status(); st.Session.Role != RoleReader {
		t.Errorf("role %q, want reader", st.Session.Role)
	}
	if b.addPasskey("Laptop", "Reader") != http.StatusCreated {
		t.Fatal("reader couldn't add a passkey")
	}
	if p := f.service.People(); len(p) != 1 || p[0].Role != RoleReader {
		t.Errorf("people = %+v, want a reader", p)
	}
}

func TestSignIn_RejectsBadAssertions(t *testing.T) {
	f := newFixture(t, "")
	alice := f.browser()
	alice.useLink(f.link(RoleAdmin))
	if alice.addPasskey("Key", "Alice") != http.StatusCreated {
		t.Fatal("setup failed")
	}

	attacker := func() *browser {
		b := f.browser()
		b.auth = alice.auth
		return b
	}

	for _, tt := range []struct {
		desc string
		r    webauthntest.Response
	}{
		{"phishing origin", webauthntest.Response{Origin: "https://doh-login.example"}},
		{"forged signature", webauthntest.Response{Signature: func(b []byte) []byte { b[len(b)-1] ^= 0xff; return b }}},
		{"wrong ceremony type", webauthntest.Response{ClientData: func(m map[string]any) { m["type"] = "webauthn.create" }}},
		{"cross origin", webauthntest.Response{ClientData: func(m map[string]any) { m["crossOrigin"] = true }}},
	} {
		b := attacker()
		if status := b.signInWithPasskey(tt.r); status != http.StatusUnauthorized {
			t.Errorf("%s: %d, want 401", tt.desc, status)
		}
		if b.status().SignedIn {
			t.Errorf("%s: signed in", tt.desc)
		}
	}

	// A response is good for one ceremony, in the browser that began it.
	b := attacker()
	var options webauthn.LoginOptions
	b.post(Prefix+"/passkey/login", nil, &options)
	response, err := b.auth.Get(options.Options.PublicKey, webauthntest.Response{Origin: f.origin})
	if err != nil {
		t.Fatal(err)
	}
	other := attacker()
	other.post(Prefix+"/passkey/login", nil, nil) // a pending session of its own
	if status := other.post(Prefix+"/passkey/login/"+options.ID, response, nil); status != http.StatusUnauthorized {
		t.Errorf("finished another browser's ceremony: %d", status)
	}
	// Another browser's attempt doesn't consume the ceremony, so it can't
	// cancel the rightful sign-in; but the response works only once.
	if status := b.post(Prefix+"/passkey/login/"+options.ID, response, nil); status != http.StatusOK {
		t.Errorf("rightful browser couldn't finish its ceremony: %d", status)
	}
	if status := b.post(Prefix+"/passkey/login/"+options.ID, response, nil); status != http.StatusUnauthorized {
		t.Errorf("replayed response = %d, want 401", status)
	}
	if status := f.browser().post(Prefix+"/passkey/login/"+options.ID, response, nil); status != http.StatusUnauthorized {
		t.Errorf("finished without a session: %d", status)
	}
}

func TestSignIn_RefusesCrossOriginRequests(t *testing.T) {
	f := newFixture(t, "")
	code := f.link(RoleAdmin)

	req, _ := http.NewRequest(http.MethodPost, f.url+Prefix+"/link", strings.NewReader(`{"code":"`+code+`"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://evil.example")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("cross-site POST = %d, want 403", resp.StatusCode)
	}

	// The refused request didn't consume the link.
	if status := f.browser().useLink(code); status != http.StatusOK {
		t.Errorf("link after a refused cross-site use = %d", status)
	}
}

func TestSessions_Expire(t *testing.T) {
	f := newFixture(t, "")

	idle := f.browser()
	idle.useLink(f.link(RoleAdmin))
	f.clock.Advance(DefaultIdleTimeout - time.Minute)
	if !idle.status().SignedIn {
		t.Fatal("expired before the idle timeout")
	}
	f.clock.Advance(DefaultIdleTimeout - time.Minute) // each use resets the idle timer
	if !idle.status().SignedIn {
		t.Fatal("use didn't reset the idle timer")
	}
	f.clock.Advance(DefaultIdleTimeout)
	if idle.status().SignedIn {
		t.Error("idle session still live")
	}

	busy := f.browser()
	busy.useLink(f.link(RoleAdmin))
	for elapsed := time.Duration(0); elapsed < DefaultLifetime; elapsed += time.Hour {
		f.clock.Advance(time.Hour)
		busy.status()
	}
	if busy.status().SignedIn {
		t.Error("session outlived its lifetime")
	}
}

func TestPeople_Persisted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "people.json")
	f := newFixture(t, path)
	b := f.browser()
	b.useLink(f.link(RoleAdmin))
	if b.addPasskey("YubiKey", "Alice") != http.StatusCreated {
		t.Fatal("add failed")
	}
	if b.signInWithPasskey(webauthntest.Response{}) != http.StatusOK {
		t.Fatal("sign-in failed")
	}

	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("people file: %v, mode %v", err, info.Mode().Perm())
	}

	reloaded, err := New(Config{Origins: []string{f.origin}, Path: path})
	if err != nil {
		t.Fatal(err)
	}
	people := reloaded.People()
	if len(people) != 1 || people[0].Name != "Alice" || len(people[0].Passkeys) != 1 {
		t.Fatalf("reloaded people = %+v", people)
	}
	k := people[0].Passkeys[0]
	if k.Name != "YubiKey" || k.LastUsed.IsZero() {
		t.Errorf("reloaded passkey = %+v", k)
	}
	if len(k.Credential.PublicKey) != 0 {
		t.Error("People exposed credential records")
	}
	if !reloaded.HasPasskeys("") {
		t.Error("reloaded service doesn't require passkeys")
	}

	// A corrupt file is an error, not an empty list that would make links
	// sign in without passkeys again.
	if err := os.WriteFile(path, []byte(`{"version":1,"people":[{"id":"x","role":"root"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := New(Config{Origins: []string{f.origin}, Path: path}); err == nil {
		t.Error("loaded a person with an invalid role")
	}
}

func TestDeletePerson_EndsSessions(t *testing.T) {
	f := newFixture(t, "")
	b := f.browser()
	b.useLink(f.link(RoleAdmin))
	b.addPasskey("Key", "Alice")
	id := b.status().Session.Person

	if err := f.service.DeletePerson(t.Context(), id); err != nil {
		t.Fatal(err)
	}
	if b.status().Session != nil {
		t.Error("deleted person's session is still live")
	}
	if f.service.HasPasskeys("") {
		t.Error("passkeys still required with no one left")
	}
	if err := f.service.DeletePerson(t.Context(), id); err != ErrNotFound {
		t.Errorf("deleting again = %v, want ErrNotFound", err)
	}
}

func TestCookie(t *testing.T) {
	f := newFixture(t, "")
	b := f.browser()

	req, _ := http.NewRequest(http.MethodPost, f.url+Prefix+"/link", strings.NewReader(`{"code":"`+f.link(RoleAdmin)+`"}`))
	resp, err := b.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	cookies := resp.Cookies()
	if len(cookies) != 1 {
		t.Fatalf("cookies = %v", cookies)
	}
	c := cookies[0]
	if c.Name != "doh-session" || !c.HttpOnly || c.SameSite != http.SameSiteStrictMode || c.Path != "/" || len(c.Value) < 40 {
		t.Errorf("cookie = %+v", c)
	}

	secure, err := New(Config{Origins: []string{"https://admin.example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	if secure.cookieName() != "__Host-doh-session" || !secure.secure {
		t.Error("HTTPS origins don't get a __Host- Secure cookie")
	}
}

func TestNew_RejectsOrigins(t *testing.T) {
	for _, origins := range [][]string{
		nil,
		{"http://192.168.1.10:9090"}, // IP addresses can't be RP IDs
		{"https://a.example.com", "https://b.example.com"}, // different hosts
		{"https://admin.example.com/ui"},                   // a path isn't an origin
		{"ftp://admin.example.com"},
	} {
		if _, err := New(Config{Origins: origins}); err == nil {
			t.Errorf("New(%q) succeeded", origins)
		}
	}
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestSessions_PendingFloodDoesNotEvictSignedIn(t *testing.T) {
	f := newFixture(t, "")
	admin := f.browser()
	admin.useLink(f.link(RoleAdmin))

	// Anyone can start passkey sign-ins, each with a pending session.
	for range maxPendingSessions * 2 {
		var options webauthn.LoginOptions
		if status := f.browser().post(Prefix+"/passkey/login", nil, &options); status != http.StatusOK {
			t.Fatalf("begin login = %d", status)
		}
	}

	if !admin.status().SignedIn {
		t.Error("a flood of pending sign-ins signed out a complete session")
	}
	m := f.service.sessions.(*memorySessions)
	m.mu.Lock()
	pending := m.count(true)
	m.mu.Unlock()
	if pending > maxPendingSessions {
		t.Errorf("%d pending sessions, want at most %d", pending, maxPendingSessions)
	}
}

func TestSignIn_TenantsRequirePasskeysSeparately(t *testing.T) {
	f := newFixture(t, "")

	// The operator has a passkey, so the operator's links need one.
	op := f.browser()
	op.useLink(f.link(RoleAdmin))
	if op.addPasskey("Laptop", "Operator") != http.StatusCreated {
		t.Fatal("operator passkey failed")
	}

	// A newly invited family has none yet, so their link signs in alone,
	// and their first passkey makes them a person of their tenant.
	code, _, err := f.service.NewLink(RoleAdmin, "smiths")
	if err != nil {
		t.Fatal(err)
	}
	smith := f.browser()
	if smith.useLink(code) != http.StatusOK {
		t.Fatal("tenant link failed")
	}
	st := smith.status()
	if !st.SignedIn || st.Session.Tenant != "smiths" {
		t.Fatalf("tenant link session = %+v, want signed in to smiths", st)
	}
	if smith.addPasskey("Phone", "Sam Smith") != http.StatusCreated {
		t.Fatal("tenant passkey failed")
	}
	if st := smith.status(); st.Session.Tenant != "smiths" || st.Session.Name != "Sam Smith" {
		t.Errorf("after adding a passkey: %+v", st.Session)
	}
	for _, p := range f.service.People() {
		if p.Name == "Sam Smith" && p.Tenant != "smiths" {
			t.Errorf("person %+v isn't in the smiths tenant", p)
		}
	}

	// Now the Smiths' links need a passkey too, and finishing with one
	// makes the session theirs.
	code, _, _ = f.service.NewLink(RoleAdmin, "smiths")
	again := f.browser()
	again.auth = smith.auth
	again.useLink(code)
	if st := again.status(); !st.Session.Pending {
		t.Fatalf("tenant with passkeys: %+v, want pending", st)
	}
	if again.signInWithPasskey(webauthntest.Response{}) != http.StatusOK {
		t.Fatal("finishing with the tenant's passkey failed")
	}
	if st := again.status(); !st.SignedIn || st.Session.Tenant != "smiths" {
		t.Errorf("finished session = %+v", st.Session)
	}

	// A passkey's owner decides the session's tenant: the operator's
	// passkey signs in as the operator, whatever link started it.
	code, _, _ = f.service.NewLink(RoleReader, "smiths")
	mixed := f.browser()
	mixed.auth = op.auth
	mixed.useLink(code)
	if mixed.signInWithPasskey(webauthntest.Response{}) != http.StatusOK {
		t.Fatal("operator passkey failed")
	}
	if st := mixed.status(); st.Session.Tenant != "" || st.Session.Role != RoleAdmin {
		t.Errorf("session after the operator's passkey = %+v, want the operator", st.Session)
	}
}
