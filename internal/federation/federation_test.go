package federation

import (
	"crypto"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/picatz/doh/internal/serviceaccount"
	"github.com/picatz/jose/pkg/header"
	"github.com/picatz/jose/pkg/josetest"
	"github.com/picatz/jose/pkg/jwa"
	"github.com/picatz/jose/pkg/jwk"
	"github.com/picatz/jose/pkg/jwt"
)

// provider is an identity provider: it serves an OpenID Connect discovery
// document and a JWK Set, and counts requests for each.
type provider struct {
	*httptest.Server
	key       crypto.Signer
	doc       map[string]string // the discovery document; nil for the default
	discovery atomic.Int64
	jwks      atomic.Int64
}

func newProvider(t testing.TB) *provider {
	t.Helper()
	p := &provider{key: josetest.Key(t, jwa.ES256)}
	value, err := jwk.PublicValue(p.key.Public())
	if err != nil {
		t.Fatal(err)
	}
	value[jwk.KeyID] = josetest.KeyID(t, p.key.Public())
	set, err := json.Marshal(jwk.Set{Keys: []jwk.Key{value}})
	if err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		p.discovery.Add(1)
		doc := p.doc
		if doc == nil {
			doc = map[string]string{"issuer": p.URL, "jwks_uri": p.URL + "/jwks"}
		}
		json.NewEncoder(w).Encode(doc)
	})
	mux.HandleFunc("GET /jwks", func(w http.ResponseWriter, r *http.Request) {
		p.jwks.Add(1)
		w.Write(set)
	})
	p.Server = httptest.NewServer(mux)
	t.Cleanup(p.Close)
	return p
}

// claims returns valid claims for p's rule.
func (p *provider) claims() jwt.ClaimsSet {
	now := time.Now()
	return jwt.ClaimsSet{
		jwt.Issuer:         p.URL,
		jwt.Audience:       "https://dns.example.com",
		jwt.Subject:        "repo:octo/app:ref:refs/heads/main",
		jwt.IssuedAt:       now,
		jwt.ExpirationTime: now.Add(5 * time.Minute),
		"repository_id":    "123456",
	}
}

func (p *provider) rule() serviceaccount.TrustRule {
	return serviceaccount.TrustRule{
		ID:       "0123456789abcdef",
		Issuer:   p.URL,
		Audience: "https://dns.example.com",
		Subject:  "repo:octo/app:ref:refs/heads/main",
		Claims:   map[string]string{"repository_id": "123456"},
	}
}

func TestVerify_Discovery(t *testing.T) {
	p := newProvider(t)
	v := &Verifier{}

	rule, claims, err := v.Verify(t.Context(), []serviceaccount.TrustRule{p.rule()}, josetest.Token(t, p.key, p.claims()))
	if err != nil {
		t.Fatal(err)
	}
	if rule.ID != p.rule().ID || claims[jwt.Subject] != "repo:octo/app:ref:refs/heads/main" {
		t.Errorf("Verify = %+v, %v", rule, claims)
	}

	// The discovery document and keys are cached.
	if _, _, err := v.Verify(t.Context(), []serviceaccount.TrustRule{p.rule()}, josetest.Token(t, p.key, p.claims())); err != nil {
		t.Fatal(err)
	}
	if d, k := p.discovery.Load(), p.jwks.Load(); d != 1 || k != 1 {
		t.Errorf("fetched discovery %d and keys %d times, want once each", d, k)
	}
}

func TestVerify_DiscoveryRefusals(t *testing.T) {
	for name, doc := range map[string]func(p *provider) map[string]string{
		"another issuer": func(p *provider) map[string]string {
			return map[string]string{"issuer": "https://elsewhere.example", "jwks_uri": p.URL + "/jwks"}
		},
		"keys on another host": func(p *provider) map[string]string {
			return map[string]string{"issuer": p.URL, "jwks_uri": strings.Replace(p.URL, "127.0.0.1", "localhost", 1) + "/jwks"}
		},
		"keys on another port": func(p *provider) map[string]string {
			return map[string]string{"issuer": p.URL, "jwks_uri": "http://127.0.0.1:1/jwks"}
		},
		"no keys": func(p *provider) map[string]string {
			return map[string]string{"issuer": p.URL}
		},
	} {
		t.Run(name, func(t *testing.T) {
			p := newProvider(t)
			p.doc = doc(p)
			_, _, err := (&Verifier{}).Verify(t.Context(), []serviceaccount.TrustRule{p.rule()}, josetest.Token(t, p.key, p.claims()))
			if !errors.Is(err, ErrRefused) || !errors.Is(err, ErrKeysUnavailable) {
				t.Errorf("Verify = %v, want refused for unavailable keys", err)
			}
			if p.jwks.Load() != 0 {
				t.Error("fetched keys the discovery document wasn't trusted for")
			}
		})
	}
}

func TestVerify_DiscoveryNoRedirects(t *testing.T) {
	p := newProvider(t)
	redirect := httptest.NewServer(http.RedirectHandler(p.URL+"/.well-known/openid-configuration", http.StatusFound))
	t.Cleanup(redirect.Close)

	r := p.rule()
	r.Issuer = redirect.URL
	claims := p.claims()
	claims[jwt.Issuer] = redirect.URL
	if _, _, err := (&Verifier{}).Verify(t.Context(), []serviceaccount.TrustRule{r}, josetest.Token(t, p.key, claims)); !errors.Is(err, ErrKeysUnavailable) {
		t.Errorf("Verify = %v", err)
	}
	if p.discovery.Load() != 0 {
		t.Error("followed a redirect")
	}
}

func TestVerify_DiscoveryRetriesSparingly(t *testing.T) {
	p := newProvider(t)
	p.doc = map[string]string{"issuer": "https://elsewhere.example"}
	var mu sync.Mutex
	now := time.Now()
	v := &Verifier{Now: func() time.Time { mu.Lock(); defer mu.Unlock(); return now }}
	verify := func() error {
		_, _, err := v.Verify(t.Context(), []serviceaccount.TrustRule{p.rule()}, josetest.Token(t, p.key, p.claims()))
		return err
	}

	for range 5 {
		if err := verify(); err == nil {
			t.Fatal("verified without keys")
		}
	}
	if n := p.discovery.Load(); n != 1 {
		t.Errorf("discovery tried %d times in a minute, want once", n)
	}

	// Once the provider is fixed, a minute later, it works.
	p.doc = nil
	mu.Lock()
	now = now.Add(retryAfter)
	mu.Unlock()
	if err := verify(); err != nil {
		t.Fatalf("after the retry interval: %v", err)
	}
}

func TestVerify_Refusals(t *testing.T) {
	p := newProvider(t)
	rsa := josetest.Key(t, jwa.RS256)
	jwks := josetest.JWKS(t, p.key.Public(), rsa.Public())
	rule := p.rule()
	rule.JWKSURL = jwks.URL

	sign := func(alg jwa.Algorithm, key any, change func(jwt.ClaimsSet)) string {
		t.Helper()
		claims := p.claims()
		if change != nil {
			change(claims)
		}
		token, err := jwt.New(header.Parameters{header.Algorithm: alg}, claims, key)
		if err != nil {
			t.Fatal(err)
		}
		return token.String()
	}

	// RS256, the most common, is accepted with the configured JWKS URL.
	if _, _, err := (&Verifier{}).Verify(t.Context(), []serviceaccount.TrustRule{rule}, sign(jwa.RS256, rsa, nil)); err != nil {
		t.Fatalf("RS256: %v", err)
	}

	for name, token := range map[string]string{
		"PS256 isn't on the allowlist": sign(jwa.PS256, rsa, nil),
		"lives over a day":             sign(jwa.ES256, p.key, func(c jwt.ClaimsSet) { c[jwt.ExpirationTime] = time.Now().Add(25 * time.Hour) }),
		"issued long ago": sign(jwa.ES256, p.key, func(c jwt.ClaimsSet) {
			c[jwt.IssuedAt] = time.Now().Add(-48 * time.Hour)
			c[jwt.ExpirationTime] = time.Now().Add(time.Hour)
		}),
		"lives over a day without iat": sign(jwa.ES256, p.key, func(c jwt.ClaimsSet) {
			delete(c, jwt.IssuedAt)
			c[jwt.ExpirationTime] = time.Now().Add(25 * time.Hour)
		}),
		"oversized": sign(jwa.ES256, p.key, func(c jwt.ClaimsSet) { c["padding"] = strings.Repeat("a", MaxTokenSize) }),
		"not a JWT": "not.a.jwt",
	} {
		if _, _, err := (&Verifier{}).Verify(t.Context(), []serviceaccount.TrustRule{rule}, token); !errors.Is(err, ErrRefused) {
			t.Errorf("%s: Verify = %v, want refused", name, err)
		}
	}
}

func TestVerify_RulesByIssuer(t *testing.T) {
	p, other := newProvider(t), newProvider(t)
	v := &Verifier{}
	theirs := other.rule()

	// A token for one provider never fetches another's keys.
	_, _, err := v.Verify(t.Context(), []serviceaccount.TrustRule{theirs}, josetest.Token(t, p.key, p.claims()))
	if !errors.Is(err, ErrRefused) || other.discovery.Load()+p.discovery.Load() != 0 {
		t.Errorf("Verify = %v after %d fetches", err, other.discovery.Load()+p.discovery.Load())
	}

	// The first rule that matches wins; others are skipped.
	wrongAudience, wild, exact := p.rule(), p.rule(), p.rule()
	wrongAudience.ID, wrongAudience.Audience = "1111111111111111", "https://other.example"
	wild.ID, wild.Subject = "2222222222222222", "repo:octo/app:ref:*"
	exact.ID = "3333333333333333"
	rule, _, err := v.Verify(t.Context(), []serviceaccount.TrustRule{theirs, wrongAudience, wild, exact}, josetest.Token(t, p.key, p.claims()))
	if err != nil || rule.ID != wild.ID {
		t.Errorf("Verify = %s, %v; want the wildcard rule", rule.ID, err)
	}
}
