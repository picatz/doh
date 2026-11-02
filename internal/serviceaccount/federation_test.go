package serviceaccount

import (
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

const githubIssuer = "https://token.actions.githubusercontent.com"

func githubRule() TrustRule {
	return TrustRule{
		Issuer:   githubIssuer,
		Audience: "https://dns.example.com",
		Subject:  "repo:octo/app:ref:refs/heads/main",
		Claims:   map[string]string{"repository_id": "123456"},
	}
}

func TestTrustRule_Validation(t *testing.T) {
	s, _, _ := newStore(t)
	op, _ := s.Create(NewAccount{Name: "CI", Role: RoleAdmin})
	tenant, _ := s.Create(NewAccount{Name: "CI", Tenant: "smiths", Role: RoleAdmin})

	valid := []func(*TrustRule){
		func(r *TrustRule) {},
		func(r *TrustRule) { r.Claims = nil },
		func(r *TrustRule) { r.JWKSURL = "https://keys.example/jwks?v=1" },
		func(r *TrustRule) { r.Subject = "repo:octo/app:ref:refs/heads/*" },
		func(r *TrustRule) { r.Subject = "repo:octo/*" },
		func(r *TrustRule) { r.Subject = "system:serviceaccount:ci:deployer" },
		func(r *TrustRule) { r.Issuer = "https://accounts.example/" },
		func(r *TrustRule) { r.TokenLifetime = 60 },
		func(r *TrustRule) { r.TokenLifetime = 3600 },
	}
	for i, change := range valid {
		r := githubRule()
		change(&r)
		if _, err := s.AddTrustRule(tenant.ID, r); err != nil {
			t.Errorf("valid rule %d (%+v): %v", i, r, err)
		}
		// Make room for the next.
		a, _ := s.Account(tenant.ID)
		for _, r := range a.Federation {
			if err := s.DeleteTrustRule(tenant.ID, r.ID); err != nil {
				t.Fatal(err)
			}
		}
	}

	invalid := map[string]func(*TrustRule){
		"no issuer":            func(r *TrustRule) { r.Issuer = "" },
		"http issuer":          func(r *TrustRule) { r.Issuer = "http://issuer.example" },
		"relative issuer":      func(r *TrustRule) { r.Issuer = "token.actions.githubusercontent.com" },
		"issuer userinfo":      func(r *TrustRule) { r.Issuer = "https://user:pass@issuer.example" },
		"issuer fragment":      func(r *TrustRule) { r.Issuer = "https://issuer.example/#x" },
		"issuer query":         func(r *TrustRule) { r.Issuer = "https://issuer.example/?x=1" },
		"issuer other scheme":  func(r *TrustRule) { r.Issuer = "file:///etc/passwd" },
		"long issuer":          func(r *TrustRule) { r.Issuer = "https://issuer.example/" + strings.Repeat("a", 512) },
		"http JWKS":            func(r *TrustRule) { r.JWKSURL = "http://keys.example/jwks" },
		"JWKS fragment":        func(r *TrustRule) { r.JWKSURL = "https://keys.example/jwks#k" },
		"tenant loopback":      func(r *TrustRule) { r.Issuer = "http://127.0.0.1:8080" },
		"tenant loopback JWKS": func(r *TrustRule) { r.JWKSURL = "http://localhost/jwks" },
		"no audience":          func(r *TrustRule) { r.Audience = "" },
		"spaced audience":      func(r *TrustRule) { r.Audience = " aud" },
		"no subject":           func(r *TrustRule) { r.Subject = "" },
		"control subject":      func(r *TrustRule) { r.Subject = "repo:octo/app\n" },
		"bare wildcard":        func(r *TrustRule) { r.Subject = "*" },
		"namespace wildcard":   func(r *TrustRule) { r.Subject = "repo:*" },
		"mid wildcard":         func(r *TrustRule) { r.Subject = "repo:octo/*:ref:refs/heads/main" },
		"two wildcards":        func(r *TrustRule) { r.Subject = "repo:octo/app:*/*" },
		"partial wildcard":     func(r *TrustRule) { r.Subject = "repo:octo/app*" },
		"reserved claim":       func(r *TrustRule) { r.Claims = map[string]string{"sub": "x"} },
		"empty claim":          func(r *TrustRule) { r.Claims = map[string]string{"ref": ""} },
		"unnamed claim":        func(r *TrustRule) { r.Claims = map[string]string{"": "x"} },
		"short lifetime":       func(r *TrustRule) { r.TokenLifetime = 59 },
		"long lifetime":        func(r *TrustRule) { r.TokenLifetime = 3601 },
		"negative lifetime":    func(r *TrustRule) { r.TokenLifetime = -1 },
		"too many claims": func(r *TrustRule) {
			r.Claims = map[string]string{}
			for i := range MaxRuleClaims + 1 {
				r.Claims[strings.Repeat("c", i+1)] = "v"
			}
		},
	}
	for name, change := range invalid {
		r := githubRule()
		change(&r)
		if _, err := s.AddTrustRule(tenant.ID, r); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: AddTrustRule = %v, want ErrInvalid", name, err)
		}
	}

	// The operator's own accounts may use loopback http, for local
	// providers and tests; never other http.
	r := githubRule()
	r.Issuer, r.JWKSURL = "http://127.0.0.1:8080", "http://localhost:8080/jwks"
	if _, err := s.AddTrustRule(op.ID, r); err != nil {
		t.Errorf("operator loopback rule: %v", err)
	}
	r.Issuer = "http://10.0.0.1"
	if _, err := s.AddTrustRule(op.ID, r); !errors.Is(err, ErrInvalid) {
		t.Errorf("operator plain http rule: %v", err)
	}

	if _, err := s.AddTrustRule("nobody", githubRule()); !errors.Is(err, ErrNotFound) {
		t.Errorf("rule for an unknown account: %v", err)
	}
}

func TestTrustRule_Limit(t *testing.T) {
	s, _, _ := newStore(t)
	a, _ := s.Create(NewAccount{Name: "CI", Role: RoleAdmin})
	for range MaxTrustRules {
		if _, err := s.AddTrustRule(a.ID, githubRule()); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.AddTrustRule(a.ID, githubRule()); !errors.Is(err, ErrLimit) {
		t.Errorf("rule beyond the limit: %v", err)
	}
}

func TestTrustRule_Matches(t *testing.T) {
	exact := githubRule()
	wild := githubRule()
	wild.Subject = "repo:octo/app:ref:refs/heads/*"

	claims := func(sub string, extra ...string) map[string]any {
		c := map[string]any{"sub": sub, "repository_id": "123456"}
		for i := 0; i+1 < len(extra); i += 2 {
			if extra[i+1] == "" {
				delete(c, extra[i])
			} else {
				c[extra[i]] = extra[i+1]
			}
		}
		return c
	}

	for _, tt := range []struct {
		name   string
		rule   TrustRule
		claims map[string]any
		want   bool
	}{
		{"exact", exact, claims("repo:octo/app:ref:refs/heads/main"), true},
		{"other branch", exact, claims("repo:octo/app:ref:refs/heads/dev"), false},
		{"prefix only", exact, claims("repo:octo/app:ref:refs/heads/main2"), false},
		{"case differs", exact, claims("repo:Octo/app:ref:refs/heads/main"), false},
		{"no subject", exact, map[string]any{"repository_id": "123456"}, false},
		{"numeric subject", exact, map[string]any{"sub": 1.0, "repository_id": "123456"}, false},
		{"missing claim", exact, claims("repo:octo/app:ref:refs/heads/main", "repository_id", ""), false},
		{"wrong claim", exact, claims("repo:octo/app:ref:refs/heads/main", "repository_id", "654321"), false},
		{"non-string claim", exact, map[string]any{"sub": "repo:octo/app:ref:refs/heads/main", "repository_id": 123456.0}, false},
		{"extra claims ignored", exact, claims("repo:octo/app:ref:refs/heads/main", "actor", "someone"), true},
		{"wildcard branch", wild, claims("repo:octo/app:ref:refs/heads/feature/x"), true},
		{"wildcard needs something", wild, claims("repo:octo/app:ref:refs/heads/"), false},
		{"wildcard other repo", wild, claims("repo:octo/app2:ref:refs/heads/main"), false},
		{"wildcard tags", wild, claims("repo:octo/app:ref:refs/tags/v1"), false},
		{"literal star", exact, claims("*"), false},
	} {
		if got := tt.rule.Matches(tt.claims); got != tt.want {
			t.Errorf("%s: Matches = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestAccessTokens(t *testing.T) {
	s, c, _ := newStore(t)
	a, _ := s.Create(NewAccount{Name: "CI", Tenant: "smiths", Role: RoleAdmin})
	r := githubRule()
	r.TokenLifetime = 600
	rule, err := s.AddTrustRule(a.ID, r)
	if err != nil {
		t.Fatal(err)
	}

	at, secret, err := s.IssueToken(a.ID, rule.ID, "repo:octo/app:ref:refs/heads/main")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(secret, AccessTokenPrefix) || len(secret) != len(AccessTokenPrefix)+43 || !IsAccessToken(secret) || IsSecret(secret) {
		t.Fatalf("access token %q", secret)
	}
	if at.Expires.Sub(at.Issued) != 10*time.Minute || at.Issuer != githubIssuer {
		t.Fatalf("issued %+v", at)
	}

	got, gt, ok := s.AuthenticateToken(secret)
	if !ok || got.ID != a.ID || gt.Rule != rule.ID || got.Tenant != "smiths" {
		t.Fatalf("AuthenticateToken = %+v, %+v, %v", got, gt, ok)
	}

	// Forged, altered, and other credentials are refused.
	for _, forged := range []string{
		"",
		AccessTokenPrefix,
		secret[:len(secret)-1] + "A",
		secret[:len(secret)-1],
		secret + "A",
		strings.ToUpper(secret),
		strings.Replace(secret, AccessTokenPrefix, SecretPrefix, 1),
		AccessTokenPrefix + strings.Repeat("!", 43),
	} {
		if forged == secret {
			continue
		}
		if _, _, ok := s.AuthenticateToken(forged); ok {
			t.Errorf("AuthenticateToken(%q) accepted", forged)
		}
	}
	if _, _, ok := s.Authenticate(secret); ok {
		t.Error("an access token authenticated as a key")
	}

	// It expires.
	c.Add(10*time.Minute - time.Second)
	if _, _, ok := s.AuthenticateToken(secret); !ok {
		t.Fatal("refused before it expired")
	}
	c.Add(time.Second)
	if _, _, ok := s.AuthenticateToken(secret); ok {
		t.Fatal("accepted once expired")
	}

	// Tokens of an unknown account or rule aren't issued.
	if _, _, err := s.IssueToken("nobody", rule.ID, "x"); !errors.Is(err, ErrNotFound) {
		t.Errorf("IssueToken for an unknown account: %v", err)
	}
	if _, _, err := s.IssueToken(a.ID, "0000000000000000", "x"); !errors.Is(err, ErrNotFound) {
		t.Errorf("IssueToken for an unknown rule: %v", err)
	}
}

func TestAccessTokens_Revocation(t *testing.T) {
	s, _, _ := newStore(t)
	issue := func(a Account) (TrustRule, string) {
		t.Helper()
		r, err := s.AddTrustRule(a.ID, githubRule())
		if err != nil {
			t.Fatal(err)
		}
		_, secret, err := s.IssueToken(a.ID, r.ID, "sub")
		if err != nil {
			t.Fatal(err)
		}
		return r, secret
	}

	// Removing the rule revokes its tokens, not the others'.
	a, _ := s.Create(NewAccount{Name: "CI", Role: RoleAdmin})
	r1, t1 := issue(a)
	_, t2 := issue(a)
	if err := s.DeleteTrustRule(a.ID, r1.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := s.AuthenticateToken(t1); ok {
		t.Error("token of a removed rule works")
	}
	if _, _, ok := s.AuthenticateToken(t2); !ok {
		t.Error("token of a remaining rule was revoked")
	}
	if err := s.DeleteTrustRule(a.ID, r1.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("removing a removed rule: %v", err)
	}

	// Deleting the account revokes the rest.
	if err := s.Delete(a.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := s.AuthenticateToken(t2); ok {
		t.Error("token of a deleted account works")
	}

	// So does deleting its tenant.
	b, _ := s.Create(NewAccount{Name: "CI", Tenant: "smiths", Role: RoleAdmin})
	_, t3 := issue(b)
	if _, err := s.DeleteTenant("smiths"); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := s.AuthenticateToken(t3); ok {
		t.Error("token of a deleted tenant's account works")
	}
	if n := len(s.tokens); n != 0 {
		t.Errorf("%d revoked tokens still kept", n)
	}
}

func TestAccessTokens_Bounded(t *testing.T) {
	s, c, _ := newStore(t)
	s.maxTokens = 3
	a, _ := s.Create(NewAccount{Name: "CI", Role: RoleAdmin})
	r, _ := s.AddTrustRule(a.ID, githubRule())

	var secrets []string
	for range 3 {
		_, secret, err := s.IssueToken(a.ID, r.ID, "sub")
		if err != nil {
			t.Fatal(err)
		}
		secrets = append(secrets, secret)
		c.Add(time.Second)
	}
	// A fourth forgets the oldest.
	_, fourth, _ := s.IssueToken(a.ID, r.ID, "sub")
	if _, _, ok := s.AuthenticateToken(secrets[0]); ok {
		t.Error("the oldest token outlived the bound")
	}
	for _, secret := range append(secrets[1:], fourth) {
		if _, _, ok := s.AuthenticateToken(secret); !ok {
			t.Error("a newer token was forgotten")
		}
	}

	// Expired tokens go first, before any that still work.
	c.Add(DefaultTokenLifetime)
	_, fresh, _ := s.IssueToken(a.ID, r.ID, "sub")
	if len(s.tokens) != 1 {
		t.Errorf("%d tokens kept, want only the fresh one", len(s.tokens))
	}
	if _, _, ok := s.AuthenticateToken(fresh); !ok {
		t.Error("fresh token refused")
	}
}

func TestTrustRule_Persistence(t *testing.T) {
	s, c, path := newStore(t)
	a, _ := s.Create(NewAccount{Name: "CI", Tenant: "smiths", Role: RoleAdmin})
	r := githubRule()
	r.JWKSURL = githubIssuer + "/.well-known/jwks"
	r.TokenLifetime = 1800
	r.CreatedBy = "kent"
	added, err := s.AddTrustRule(a.ID, r)
	if err != nil {
		t.Fatal(err)
	}
	if len(added.ID) != 16 || !added.Created.Equal(c.Now()) {
		t.Fatalf("added %+v", added)
	}
	_, secret, _ := s.IssueToken(a.ID, added.ID, "sub")

	// Changing the returned rule changes nothing in the store.
	added.Claims["repository_id"] = "forged"

	reopened, err := Open(path, WithClock(c.Now))
	if err != nil {
		t.Fatal(err)
	}
	got, _ := reopened.Account(a.ID)
	if len(got.Federation) != 1 {
		t.Fatalf("reopened rules = %+v", got.Federation)
	}
	g := got.Federation[0]
	if g.ID != added.ID || g.Issuer != r.Issuer || g.JWKSURL != r.JWKSURL || g.Audience != r.Audience || g.Subject != r.Subject ||
		g.Claims["repository_id"] != "123456" || g.TokenLifetime != 1800 || g.CreatedBy != "kent" || !g.Created.Equal(added.Created) {
		t.Errorf("reopened rule = %+v, want %+v", g, r)
	}

	// Access tokens live only in memory: by design, they don't survive.
	if _, _, ok := reopened.AuthenticateToken(secret); ok {
		t.Error("an access token survived reopening")
	}

	// A file from before federation still loads, and one with an invalid
	// rule doesn't.
	old := `{"version":1,"accounts":[{"id":"aaaaaaaaaaaaaaaa","name":"x","role":"reader","created":"2026-01-01T00:00:00Z","keys":[]}]}`
	if err := os.WriteFile(path, []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path); err != nil {
		t.Errorf("a file without federation: %v", err)
	}
	bad := `{"version":1,"accounts":[{"id":"aaaaaaaaaaaaaaaa","name":"x","tenant":"t","role":"reader","created":"2026-01-01T00:00:00Z","keys":[],
		"federation":[{"id":"0123456789abcdef","issuer":"http://127.0.0.1","audience":"a","subject":"s","created":"2026-01-01T00:00:00Z"}]}]}`
	if err := os.WriteFile(path, []byte(bad), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path); err == nil {
		t.Error("a tenant's loopback rule loaded")
	}
}
