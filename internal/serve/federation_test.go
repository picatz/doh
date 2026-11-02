package serve

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/picatz/doh/internal/api"
	"github.com/picatz/doh/internal/ratelimit"
	"github.com/picatz/doh/internal/serviceaccount"
	"github.com/picatz/jose/pkg/header"
	"github.com/picatz/jose/pkg/josetest"
	"github.com/picatz/jose/pkg/jwa"
	"github.com/picatz/jose/pkg/jwk"
	"github.com/picatz/jose/pkg/jwt"
)

const (
	githubIssuer  = "https://token.actions.githubusercontent.com"
	testAudience  = "https://dns.example.com"
	githubSubject = "repo:octo/app:ref:refs/heads/main"
)

// testClock is a settable time source.
type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *testClock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.now }
func (c *testClock) Add(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

// syncBuffer is a buffer safe for concurrent writes, for logs.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string { b.mu.Lock(); defer b.mu.Unlock(); return b.buf.String() }

// workloads is a fixture for workload identity federation: the tenant
// fixture, an identity provider publishing its keys over HTTPS, a clock
// for the service account store, and the server's log.
type workloads struct {
	*tenantFixture
	key     crypto.Signer // the provider's signing key
	jwksURL string
	clock   *testClock
	log     *syncBuffer
}

func newWorkloads(t *testing.T) *workloads {
	t.Helper()
	w := &workloads{key: josetest.Key(t, jwa.ES256), clock: &testClock{now: time.Now()}, log: &syncBuffer{}}

	value, err := jwk.PublicValue(w.key.Public())
	if err != nil {
		t.Fatal(err)
	}
	set, err := json.Marshal(jwk.Set{Keys: []jwk.Key{value}})
	if err != nil {
		t.Fatal(err)
	}
	idp := httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) { rw.Write(set) }))
	t.Cleanup(idp.Close)
	w.jwksURL = idp.URL + "/jwks"

	w.tenantFixture = newTenantFixture(t, func(s *Server) {
		store, err := serviceaccount.Open(filepath.Join(s.config.DataDir, ServiceAccountsFile), serviceaccount.WithClock(w.clock.Now))
		if err != nil {
			t.Fatal(err)
		}
		s.accounts = store
		s.federation.Client = idp.Client()
		s.exchangeLimiter = &ratelimit.Limiter{Rate: 1000, Burst: 1000}
		s.logger = slog.New(slog.NewTextHandler(io.MultiWriter(w.log, t.Output()), nil))
	})
	return w
}

// claims returns claims the default rule accepts.
func (w *workloads) claims() jwt.ClaimsSet {
	now := time.Now()
	return jwt.ClaimsSet{
		jwt.Issuer:         githubIssuer,
		jwt.Audience:       testAudience,
		jwt.Subject:        githubSubject,
		jwt.IssuedAt:       now,
		jwt.ExpirationTime: now.Add(5 * time.Minute),
		"repository_id":    "123456",
	}
}

// token returns an identity token from the provider, with claims changed
// by change.
func (w *workloads) token(t *testing.T, change func(jwt.ClaimsSet)) string {
	t.Helper()
	claims := w.claims()
	if change != nil {
		change(claims)
	}
	return josetest.Token(t, w.key, claims)
}

// rule returns the JSON of a trust rule for the provider's default
// token.
func (w *workloads) rule() string {
	return fmt.Sprintf(`{"issuer":%q,"jwks_url":%q,"audience":%q,"subject":%q,"claims":{"repository_id":"123456"}}`, githubIssuer, w.jwksURL, testAudience, githubSubject)
}

// trust adds the default rule to account as c.
func (w *workloads) trust(t *testing.T, c apiClient, account string) serviceaccount.TrustRule {
	t.Helper()
	resp, b := c.do(http.MethodPost, "/api/v1/service-accounts/"+account+"/federation", w.rule())
	var r serviceaccount.TrustRule
	if err := json.Unmarshal(b, &r); resp.StatusCode != http.StatusCreated || err != nil {
		t.Fatalf("add trust rule = %d %s", resp.StatusCode, b)
	}
	return r
}

// exchange sends a token exchange form, returning the response and its
// body.
func (w *workloads) exchange(t *testing.T, form url.Values) (*http.Response, []byte) {
	t.Helper()
	return apiClient{t, w.operator.base, ""}.do(http.MethodPost, "/api/v1/token", form.Encode(), "Content-Type", "application/x-www-form-urlencoded")
}

// exchangeForm returns a valid exchange of token for account.
func exchangeForm(account, token string) url.Values {
	return api.TokenExchangeRequest{SubjectToken: token, Audience: account}.Form()
}

// accessToken exchanges token for account's access token, failing the
// test if that fails.
func (w *workloads) accessToken(t *testing.T, account, token string) (apiClient, api.TokenResponse) {
	t.Helper()
	resp, b := w.exchange(t, exchangeForm(account, token))
	var tr api.TokenResponse
	if err := json.Unmarshal(b, &tr); resp.StatusCode != http.StatusOK || err != nil {
		t.Fatalf("exchange = %d %s", resp.StatusCode, b)
	}
	return apiClient{t, w.operator.base, tr.AccessToken}, tr
}

// createBareAccount makes a service account without keys as c.
func createBareAccount(t *testing.T, c apiClient, body string) serviceaccount.Account {
	t.Helper()
	resp, b := c.do(http.MethodPost, "/api/v1/service-accounts", body)
	var a serviceaccount.Account
	if err := json.Unmarshal(b, &a); resp.StatusCode != http.StatusCreated || err != nil {
		t.Fatalf("create service account = %d %s", resp.StatusCode, b)
	}
	return a
}

func TestTokenExchange_TenantScopedAccess(t *testing.T) {
	w := newWorkloads(t)

	// The smiths' admin makes a reader for their CI, and trusts its
	// workflow on main.
	var bot serviceaccount.Account
	if status := w.smith.do(http.MethodPost, "/api/v1/service-accounts", `{"name":"CI"}`, &bot); status != http.StatusCreated {
		t.Fatalf("create = %d", status)
	}
	var rule serviceaccount.TrustRule
	if status := w.smith.do(http.MethodPost, "/api/v1/service-accounts/"+bot.ID+"/federation", w.rule(), &rule); status != http.StatusCreated {
		t.Fatalf("add rule = %d", status)
	}
	if rule.Issuer != githubIssuer || rule.CreatedBy == "" || len(rule.ID) != 16 {
		t.Errorf("rule = %+v", rule)
	}
	var rules api.TrustRules
	if status := w.smith.do(http.MethodGet, "/api/v1/service-accounts/"+bot.ID+"/federation", "", &rules); status != http.StatusOK || len(rules.Rules) != 1 || rules.Rules[0].ID != rule.ID {
		t.Errorf("list rules = %d %+v", status, rules)
	}

	// The workflow exchanges its identity token for an access token.
	resp, b := w.exchange(t, exchangeForm(bot.ID, w.token(t, nil)))
	var tr api.TokenResponse
	if err := json.Unmarshal(b, &tr); resp.StatusCode != http.StatusOK || err != nil {
		t.Fatalf("exchange = %d %s", resp.StatusCode, b)
	}
	if !strings.HasPrefix(tr.AccessToken, serviceaccount.AccessTokenPrefix) || tr.TokenType != "Bearer" ||
		tr.IssuedTokenType != api.TokenTypeAccessToken || tr.ExpiresIn != int(serviceaccount.DefaultTokenLifetime/time.Second) {
		t.Errorf("exchange = %+v", tr)
	}
	if resp.Header.Get("Cache-Control") != "no-store" || resp.Header.Get("Pragma") != "no-cache" {
		t.Errorf("exchange cache headers = %q, %q", resp.Header.Get("Cache-Control"), resp.Header.Get("Pragma"))
	}
	if log := w.log.String(); !strings.Contains(log, "admin: access token issued") || !strings.Contains(log, githubSubject) {
		t.Errorf("issuing wasn't logged with the workload's subject:\n%s", log)
	}

	// It sees only the smiths' profiles, and can only read them.
	key := apiClient{t, w.operator.base, tr.AccessToken}
	resp, b = key.do(http.MethodGet, "/api/v1/profiles", "")
	var profiles api.Profiles
	if err := json.Unmarshal(b, &profiles); resp.StatusCode != http.StatusOK || err != nil || len(profiles.Profiles) != 1 || profiles.Profiles[0].ID != "smith-home" {
		t.Fatalf("access token lists %d %s", resp.StatusCode, b)
	}
	if resp, _ := key.do(http.MethodGet, "/api/v1/profiles/lab", ""); resp.StatusCode != http.StatusNotFound {
		t.Errorf("access token reads the operator's profile: %d", resp.StatusCode)
	}
	if resp, _ := key.do(http.MethodPatch, "/api/v1/profiles/smith-home", `{"safe_search":true}`); resp.StatusCode != http.StatusForbidden {
		t.Errorf("reader's access token changed a profile: %d", resp.StatusCode)
	}

	// Other tenants' accounts' rules look like they don't exist.
	op := createBareAccount(t, w.operator, `{"name":"Deploys","role":"admin"}`)
	opRule := w.trust(t, w.operator, op.ID)
	for _, tt := range []struct{ method, path, body string }{
		{http.MethodGet, "/api/v1/service-accounts/" + op.ID + "/federation", ""},
		{http.MethodPost, "/api/v1/service-accounts/" + op.ID + "/federation", w.rule()},
		{http.MethodDelete, "/api/v1/service-accounts/" + op.ID + "/federation/" + opRule.ID, ""},
	} {
		if status := w.smith.do(tt.method, tt.path, tt.body, nil); status != http.StatusNotFound {
			t.Errorf("tenant %s %s = %d, want 404", tt.method, tt.path, status)
		}
	}
	if a, _ := w.s.accounts.Account(op.ID); len(a.Federation) != 1 {
		t.Error("a tenant changed the operator's trust rules")
	}

	// Tenants' rules must use https, never the server's loopback.
	loopback := fmt.Sprintf(`{"issuer":"http://127.0.0.1:9090","audience":%q,"subject":"x"}`, testAudience)
	if status := w.smith.do(http.MethodPost, "/api/v1/service-accounts/"+bot.ID+"/federation", loopback, nil); status != http.StatusBadRequest {
		t.Errorf("tenant loopback rule = %d, want 400", status)
	}
	if log := w.log.String(); !strings.Contains(log, "admin: service account trust rule added") {
		t.Errorf("adding a rule wasn't logged:\n%s", log)
	}
}

func TestTokenExchange_CantManageIdentities(t *testing.T) {
	w := newWorkloads(t)
	bot := createBareAccount(t, w.operator, `{"name":"Deploys","role":"admin"}`)
	rule := w.trust(t, w.operator, bot.ID)
	key, _ := w.accessToken(t, bot.ID, w.token(t, nil))

	// Even an operator admin's access token can't mint more credentials,
	// trust more workloads, or remove its own limits.
	for _, tt := range []struct{ method, path, body string }{
		{http.MethodPost, "/api/v1/signin-links", `{}`},
		{http.MethodGet, "/api/v1/people", ""},
		{http.MethodGet, "/api/v1/service-accounts", ""},
		{http.MethodPost, "/api/v1/service-accounts/" + bot.ID + "/keys", `{}`},
		{http.MethodGet, "/api/v1/service-accounts/" + bot.ID + "/federation", ""},
		{http.MethodPost, "/api/v1/service-accounts/" + bot.ID + "/federation", w.rule()},
		{http.MethodDelete, "/api/v1/service-accounts/" + bot.ID + "/federation/" + rule.ID, ""},
	} {
		if resp, b := key.do(tt.method, tt.path, tt.body); resp.StatusCode != http.StatusForbidden {
			t.Errorf("access token %s %s = %d %s, want 403", tt.method, tt.path, resp.StatusCode, b)
		}
	}

	// It can do its job, though.
	if resp, b := key.do(http.MethodPost, "/api/v1/profiles/lab/deny", `{"domain":"bot.example"}`); resp.StatusCode != http.StatusOK {
		t.Errorf("admin access token couldn't change a profile: %d %s", resp.StatusCode, b)
	}
}

// signed returns a compact JWS of claims, signed with alg by key.
func signed(t *testing.T, alg jwa.Algorithm, key any, claims jwt.ClaimsSet) string {
	t.Helper()
	token, err := jwt.New(header.Parameters{header.Algorithm: alg}, claims, key)
	if err != nil {
		t.Fatal(err)
	}
	return token.String()
}

func TestTokenExchange_Refusals(t *testing.T) {
	w := newWorkloads(t)
	bot := createBareAccount(t, w.operator, `{"name":"Deploys","role":"admin"}`)
	w.trust(t, w.operator, bot.ID)
	smithBot := createBareAccount(t, w.operator, `{"name":"CI","tenant":"smiths"}`)

	// An unsigned token, and one signed with HMAC using the provider's
	// public key as the secret, as in the classic algorithm confusion.
	enc := func(v any) string { b, _ := json.Marshal(v); return base64.RawURLEncoding.EncodeToString(b) }
	plain := w.claims()
	plain[jwt.IssuedAt], plain[jwt.ExpirationTime] = time.Now().Unix(), time.Now().Add(5*time.Minute).Unix()
	unsigned := enc(map[string]string{"alg": "none", "typ": "JWT"}) + "." + enc(plain) + "."
	public, err := x509.MarshalPKIXPublicKey(w.key.Public())
	if err != nil {
		t.Fatal(err)
	}
	confused := signed(t, jwa.HS256, public, w.claims())
	stranger := josetest.Token(t, josetest.Key(t, jwa.ES256), w.claims())

	with := func(change func(url.Values)) url.Values {
		form := exchangeForm(bot.ID, w.token(t, nil))
		change(form)
		return form
	}
	claim := func(name string, value any) url.Values {
		return exchangeForm(bot.ID, w.token(t, func(c jwt.ClaimsSet) {
			if value == nil {
				delete(c, name)
			} else {
				c[name] = value
			}
		}))
	}

	refused := "the subject token wasn't accepted for this service account"
	for _, tt := range []struct {
		name   string
		form   url.Values
		status int
		code   string
	}{
		{"wrong issuer", claim(jwt.Issuer, "https://evil.example"), 400, errInvalidGrant},
		{"wrong audience", claim(jwt.Audience, "https://other.example"), 400, errInvalidGrant},
		{"no audience", claim(jwt.Audience, nil), 400, errInvalidGrant},
		{"wrong subject", claim(jwt.Subject, "repo:octo/app:ref:refs/heads/evil"), 400, errInvalidGrant},
		{"missing claim", claim("repository_id", nil), 400, errInvalidGrant},
		{"mismatched claim", claim("repository_id", "654321"), 400, errInvalidGrant},
		{"numeric claim", claim("repository_id", 123456), 400, errInvalidGrant},
		{"expired", claim(jwt.ExpirationTime, time.Now().Add(-2*time.Minute)), 400, errInvalidGrant},
		{"no expiry", claim(jwt.ExpirationTime, nil), 400, errInvalidGrant},
		{"not yet valid", claim(jwt.NotBefore, time.Now().Add(10*time.Minute)), 400, errInvalidGrant},
		{"issued in the future", claim(jwt.IssuedAt, time.Now().Add(10*time.Minute)), 400, errInvalidGrant},
		{"lives too long", claim(jwt.ExpirationTime, time.Now().Add(48*time.Hour)), 400, errInvalidGrant},
		{"alg none", exchangeForm(bot.ID, unsigned), 400, errInvalidGrant},
		{"HS256 with the public key", exchangeForm(bot.ID, confused), 400, errInvalidGrant},
		{"unknown key", exchangeForm(bot.ID, stranger), 400, errInvalidGrant},
		{"tampered", exchangeForm(bot.ID, w.token(t, nil)+"A"), 400, errInvalidGrant},
		{"garbage", exchangeForm(bot.ID, "not a token"), 400, errInvalidGrant},
		{"unknown account", exchangeForm("aaaaaaaaaaaaaaaa", w.token(t, nil)), 400, errInvalidGrant},
		{"another account, without a matching rule", exchangeForm(smithBot.ID, w.token(t, nil)), 400, errInvalidGrant},
		{"malformed account", exchangeForm("../../people", w.token(t, nil)), 400, errInvalidTarget},
		{"no account", with(func(f url.Values) { f.Del("audience") }), 400, errInvalidRequest},
		{"no subject token", with(func(f url.Values) { f.Del("subject_token") }), 400, errInvalidRequest},
		{"no subject token type", with(func(f url.Values) { f.Del("subject_token_type") }), 400, errInvalidRequest},
		{"access token as subject", with(func(f url.Values) { f.Set("subject_token_type", api.TokenTypeAccessToken) }), 400, errInvalidRequest},
		{"wrong grant type", with(func(f url.Values) { f.Set("grant_type", "client_credentials") }), 400, errUnsupportedGrantType},
		{"no grant type", with(func(f url.Values) { f.Del("grant_type") }), 400, errInvalidRequest},
		{"repeated parameter", with(func(f url.Values) { f.Add("audience", smithBot.ID) }), 400, errInvalidRequest},
		{"actor token", with(func(f url.Values) { f.Set("actor_token", "x") }), 400, errInvalidRequest},
		{"refresh token requested", with(func(f url.Values) { f.Set("requested_token_type", "urn:ietf:params:oauth:token-type:refresh_token") }), 400, errInvalidRequest},
		{"scope", with(func(f url.Values) { f.Set("scope", "admin") }), 400, errInvalidScope},
		{"resource", with(func(f url.Values) { f.Set("resource", "https://elsewhere.example") }), 400, errInvalidTarget},
	} {
		resp, b := w.exchange(t, tt.form)
		var e api.OAuthError
		if err := json.Unmarshal(b, &e); resp.StatusCode != tt.status || err != nil || e.Error != tt.code {
			t.Errorf("%s: %d %s, want %d %s", tt.name, resp.StatusCode, b, tt.status, tt.code)
			continue
		}
		// Refused identity tokens all look the same, whatever the reason.
		if tt.code == errInvalidGrant && e.Description != refused {
			t.Errorf("%s: description %q reveals more than a refusal", tt.name, e.Description)
		}
		if resp.Header.Get("Cache-Control") != "no-store" {
			t.Errorf("%s: Cache-Control %q", tt.name, resp.Header.Get("Cache-Control"))
		}
	}
	// The reasons are in the log, for the operator.
	for _, want := range []string{"admin: token exchange refused", "no such service account", "signature verification failed", "subject or claims don't match", `algorithm \"HS256\" is not accepted`} {
		if !strings.Contains(w.log.String(), want) {
			t.Errorf("the log lacks %q", want)
		}
	}

	// Other ways to send the request are refused.
	c := apiClient{t, w.operator.base, ""}
	if resp, b := c.do(http.MethodPost, "/api/v1/token", `{"grant_type":"`+api.GrantTypeTokenExchange+`"}`, "Content-Type", "application/json"); resp.StatusCode != http.StatusBadRequest || !strings.Contains(string(b), errInvalidRequest) {
		t.Errorf("JSON exchange = %d %s", resp.StatusCode, b)
	}
	if resp, _ := c.do(http.MethodGet, "/api/v1/token?"+exchangeForm(bot.ID, w.token(t, nil)).Encode(), ""); resp.StatusCode != http.StatusMethodNotAllowed || resp.Header.Get("Allow") != http.MethodPost {
		t.Errorf("GET exchange = %d", resp.StatusCode)
	}
	big := exchangeForm(bot.ID, strings.Repeat("a", maxExchangeBody))
	if resp, b := w.exchange(t, big); resp.StatusCode != http.StatusBadRequest || !strings.Contains(string(b), errInvalidRequest) {
		t.Errorf("oversized exchange = %d %s", resp.StatusCode, b)
	}

	// And the right one still works, as either token type.
	form := exchangeForm(bot.ID, w.token(t, nil))
	form.Set("subject_token_type", api.TokenTypeIDToken)
	form.Set("requested_token_type", api.TokenTypeAccessToken)
	if resp, b := w.exchange(t, form); resp.StatusCode != http.StatusOK {
		t.Errorf("valid id_token exchange = %d %s", resp.StatusCode, b)
	}
}

func TestTokenExchange_RefusedWithoutTheirTenant(t *testing.T) {
	w := newWorkloads(t)
	a, err := w.s.accounts.Create(serviceaccount.NewAccount{Name: "orphan", Tenant: "ghosts", Role: serviceaccount.RoleAdmin})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.s.accounts.AddTrustRule(a.ID, serviceaccount.TrustRule{Issuer: githubIssuer, JWKSURL: w.jwksURL, Audience: testAudience, Subject: githubSubject}); err != nil {
		t.Fatal(err)
	}
	if resp, b := w.exchange(t, exchangeForm(a.ID, w.token(t, nil))); resp.StatusCode != http.StatusBadRequest || !strings.Contains(string(b), errInvalidGrant) {
		t.Errorf("exchange for a tenant that doesn't exist = %d %s", resp.StatusCode, b)
	}
}

func TestTokenExchange_AccessTokensExpire(t *testing.T) {
	w := newWorkloads(t)
	bot := createBareAccount(t, w.operator, `{"name":"Deploys"}`)
	body := fmt.Sprintf(`{"issuer":%q,"jwks_url":%q,"audience":%q,"subject":%q,"token_lifetime":600}`, githubIssuer, w.jwksURL, testAudience, githubSubject)
	if resp, b := w.operator.do(http.MethodPost, "/api/v1/service-accounts/"+bot.ID+"/federation", body); resp.StatusCode != http.StatusCreated {
		t.Fatalf("add rule = %d %s", resp.StatusCode, b)
	}
	key, tr := w.accessToken(t, bot.ID, w.token(t, nil))
	if tr.ExpiresIn != 600 {
		t.Errorf("expires_in = %d, want the rule's 600", tr.ExpiresIn)
	}

	w.clock.Add(10*time.Minute - time.Second)
	if resp, _ := key.do(http.MethodGet, "/api/v1/status", ""); resp.StatusCode != http.StatusOK {
		t.Fatalf("access token before it expires = %d", resp.StatusCode)
	}
	w.clock.Add(time.Second)
	if resp, _ := key.do(http.MethodGet, "/api/v1/status", ""); resp.StatusCode != http.StatusUnauthorized || !strings.HasPrefix(resp.Header.Get("WWW-Authenticate"), "Bearer") {
		t.Errorf("expired access token = %d %q", resp.StatusCode, resp.Header.Get("WWW-Authenticate"))
	}

	// A forged one is refused too.
	forged := apiClient{t, w.operator.base, serviceaccount.AccessTokenPrefix + strings.Repeat("A", 43)}
	if resp, _ := forged.do(http.MethodGet, "/api/v1/status", ""); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("forged access token = %d", resp.StatusCode)
	}
}

func TestTokenExchange_Revocation(t *testing.T) {
	w := newWorkloads(t)
	works := func(c apiClient) bool {
		t.Helper()
		resp, _ := c.do(http.MethodGet, "/api/v1/profiles", "")
		return resp.StatusCode == http.StatusOK
	}

	// Removing the rule revokes the tokens it issued.
	bot := createBareAccount(t, w.operator, `{"name":"Deploys"}`)
	rule := w.trust(t, w.operator, bot.ID)
	key, _ := w.accessToken(t, bot.ID, w.token(t, nil))
	if !works(key) {
		t.Fatal("access token refused")
	}
	if resp, _ := w.operator.do(http.MethodDelete, "/api/v1/service-accounts/"+bot.ID+"/federation/"+rule.ID, ""); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("remove rule = %d", resp.StatusCode)
	}
	if works(key) {
		t.Error("access token works after its rule was removed")
	}
	if resp, _ := w.exchange(t, exchangeForm(bot.ID, w.token(t, nil))); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("exchange after the rule was removed = %d", resp.StatusCode)
	}
	if resp, _ := w.operator.do(http.MethodDelete, "/api/v1/service-accounts/"+bot.ID+"/federation/"+rule.ID, ""); resp.StatusCode != http.StatusNotFound {
		t.Errorf("removing a removed rule = %d, want 404", resp.StatusCode)
	}

	// Deleting the account revokes them too.
	w.trust(t, w.operator, bot.ID)
	key, _ = w.accessToken(t, bot.ID, w.token(t, nil))
	if resp, _ := w.operator.do(http.MethodDelete, "/api/v1/service-accounts/"+bot.ID, ""); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete account = %d", resp.StatusCode)
	}
	if works(key) {
		t.Error("access token works after its account was deleted")
	}

	// So does deleting the account's tenant.
	smithBot := createBareAccount(t, w.operator, `{"name":"CI","tenant":"smiths"}`)
	w.trust(t, w.operator, smithBot.ID)
	key, _ = w.accessToken(t, smithBot.ID, w.token(t, nil))
	if !works(key) {
		t.Fatal("tenant's access token refused")
	}
	if resp, b := w.operator.do(http.MethodDelete, "/api/v1/profiles/smith-home", ""); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete profile = %d %s", resp.StatusCode, b)
	}
	if resp, b := w.operator.do(http.MethodDelete, "/api/v1/tenants/smiths", ""); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete tenant = %d %s", resp.StatusCode, b)
	}
	if works(key) {
		t.Error("access token works after its tenant was deleted")
	}
	if log := w.log.String(); !strings.Contains(log, "admin: service account trust rule removed") {
		t.Errorf("removing a rule wasn't logged:\n%s", log)
	}
}

func TestTokenExchange_RateLimited(t *testing.T) {
	w := newWorkloads(t)
	w.s.exchangeLimiter = &ratelimit.Limiter{Rate: 0.001, Burst: 3}
	bot := createBareAccount(t, w.operator, `{"name":"Deploys"}`)
	w.trust(t, w.operator, bot.ID)

	// Successes don't count against the limit.
	for range 5 {
		w.accessToken(t, bot.ID, w.token(t, nil))
	}

	bad := exchangeForm(bot.ID, w.token(t, func(c jwt.ClaimsSet) { c[jwt.Subject] = "repo:evil/app:ref:refs/heads/main" }))
	for i := range 3 {
		if resp, _ := w.exchange(t, bad); resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("failure %d = %d, want 400", i, resp.StatusCode)
		}
	}
	// Then even a valid exchange waits.
	resp, b := w.exchange(t, exchangeForm(bot.ID, w.token(t, nil)))
	var e api.OAuthError
	if err := json.Unmarshal(b, &e); resp.StatusCode != http.StatusTooManyRequests || err != nil || e.Error != errSlowDown || resp.Header.Get("Retry-After") == "" {
		t.Errorf("exchange after too many failures = %d %s", resp.StatusCode, b)
	}
}

func TestTrustRules_AudienceDefaultsToTheAdminOrigin(t *testing.T) {
	up, _ := startZone(t, nil)
	s, dataDir := newPolicyServer(t, up, nil, func(c *Config) { c.Admin.Origins = []string{"https://admin.dns.example.com"} })
	base := startAdmin(t, s)
	operator := apiClient{t, base, token(t, dataDir, AdminTokenFile)}

	bot := createBareAccount(t, operator, `{"name":"Deploys"}`)
	body := fmt.Sprintf(`{"issuer":%q,"subject":%q}`, githubIssuer, githubSubject)
	resp, b := operator.do(http.MethodPost, "/api/v1/service-accounts/"+bot.ID+"/federation", body)
	var r serviceaccount.TrustRule
	if err := json.Unmarshal(b, &r); resp.StatusCode != http.StatusCreated || err != nil || r.Audience != "https://admin.dns.example.com" {
		t.Errorf("add rule without an audience = %d %s", resp.StatusCode, b)
	}
}

func TestTrustRules_AudienceRequiredWithoutAnOrigin(t *testing.T) {
	f := newTenantFixture(t)
	bot := createBareAccount(t, f.operator, `{"name":"Deploys"}`)
	body := fmt.Sprintf(`{"issuer":%q,"subject":%q}`, githubIssuer, githubSubject)
	if resp, b := f.operator.do(http.MethodPost, "/api/v1/service-accounts/"+bot.ID+"/federation", body); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("add rule without an audience = %d %s", resp.StatusCode, b)
	}
	if resp, _ := f.operator.do(http.MethodGet, "/api/v1/service-accounts/nobody/federation", ""); resp.StatusCode != http.StatusNotFound {
		t.Errorf("rules of an unknown account = %d", resp.StatusCode)
	}
}
