package serve

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/picatz/doh/internal/api"
	"github.com/picatz/doh/internal/client"
	"github.com/picatz/doh/internal/policy"
	"github.com/picatz/doh/internal/serviceaccount"
	"github.com/picatz/jose/pkg/dpop"
	"github.com/picatz/jose/pkg/header"
	"github.com/picatz/jose/pkg/josetest"
	"github.com/picatz/jose/pkg/jwa"
	"github.com/picatz/jose/pkg/jwk"
	"github.com/picatz/jose/pkg/jws"
)

// prover holds a DPoP key, and signs proofs with it.
type prover struct {
	key    crypto.Signer
	signer *dpop.Signer
}

func newProver(t *testing.T, alg jwa.Algorithm, opts ...dpop.SignerOption) prover {
	t.Helper()
	key := josetest.Key(t, alg)
	signer, err := dpop.NewSigner(key, opts...)
	if err != nil {
		t.Fatal(err)
	}
	return prover{key: key, signer: signer}
}

// proof signs a proof for method and uri, bound to token if it's set.
func (p prover) proof(t *testing.T, method, uri, token string) string {
	t.Helper()
	proof, err := p.signer.Proof(method, uri, dpop.ProofOptions{AccessToken: token})
	if err != nil {
		t.Fatal(err)
	}
	return proof
}

// public returns p's public JWK.
func (p prover) public(t *testing.T) jwk.Key {
	t.Helper()
	v, err := jwk.PublicValue(p.key.Public())
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// proofClaims returns the claims of a good proof for method and uri,
// bound to token.
func proofClaims(method, uri, token string) map[string]any {
	jti := make([]byte, 16)
	_, _ = rand.Read(jti)
	return map[string]any{
		"jti": base64.RawURLEncoding.EncodeToString(jti),
		"htm": method,
		"htu": uri,
		"iat": time.Now().Unix(),
		"ath": dpop.AccessTokenHash(token),
	}
}

// signProof signs claims with key under h, as a JWS.
func signProof(t *testing.T, h jws.Header, claims map[string]any, key any) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	s, err := jws.New(h, payload, key)
	if err != nil {
		t.Fatal(err)
	}
	return s.String()
}

// rawJWS encodes a JWS by hand, signed (or not) by sign, for headers jws
// won't sign with.
func rawJWS(t *testing.T, h map[string]any, claims map[string]any, sign func(input string) []byte) string {
	t.Helper()
	enc := func(v any) string {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return base64.RawURLEncoding.EncodeToString(b)
	}
	input := enc(h) + "." + enc(claims)
	return input + "." + base64.RawURLEncoding.EncodeToString(sign(input))
}

// dpopRequest sends method path as c would, with the credential sent
// with scheme, and each of proofs in a DPoP header.
func dpopRequest(t *testing.T, c apiClient, method, path, scheme string, proofs ...string) (*http.Response, []byte) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), method, c.base+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if c.token != "" {
		req.Header.Set("Authorization", scheme+" "+c.token)
	}
	for _, p := range proofs {
		req.Header.Add("DPoP", p)
	}
	return send(t, req)
}

func send(t *testing.T, req *http.Request) (*http.Response, []byte) {
	t.Helper()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, b
}

// boundKey makes a service account and a key for it bound to p's key,
// as c, returning a client that uses the key.
func boundKey(t *testing.T, c apiClient, p prover) (serviceaccount.Account, apiClient) {
	t.Helper()
	a := createBareAccount(t, c, `{"name":"Bound","role":"admin"}`)
	resp, b := c.do(http.MethodPost, "/api/v1/service-accounts/"+a.ID+"/keys", `{"jkt":"`+p.signer.Thumbprint()+`"}`)
	var k api.NewKey
	if err := json.Unmarshal(b, &k); resp.StatusCode != http.StatusCreated || err != nil {
		t.Fatalf("add bound key = %d %s", resp.StatusCode, b)
	}
	if k.Key.JKT != p.signer.Thumbprint() {
		t.Fatalf("key bound to %q, want %q", k.Key.JKT, p.signer.Thumbprint())
	}
	return a, apiClient{t, c.base, k.Secret}
}

// wantRefused checks that resp is a 401 whose DPoP challenge names code.
func wantRefused(t *testing.T, what string, resp *http.Response, body []byte, code string) {
	t.Helper()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("%s = %d %s, want 401", what, resp.StatusCode, body)
		return
	}
	var dpopChallenge string
	for _, c := range resp.Header.Values("WWW-Authenticate") {
		if strings.HasPrefix(c, "DPoP ") {
			dpopChallenge = c
		}
	}
	if !strings.Contains(dpopChallenge, `error="`+code+`"`) || !strings.Contains(dpopChallenge, `algs="ES256 EdDSA RS256"`) {
		t.Errorf("%s: challenges %q, want a DPoP one with error %s and algs", what, resp.Header.Values("WWW-Authenticate"), code)
	}
}

func TestDPoP_BoundKey(t *testing.T) {
	f := newTenantFixture(t)
	p := newProver(t, jwa.ES256)
	_, key := boundKey(t, f.operator, p)
	path := "/api/v1/status"
	uri := key.base + path

	// The key works with a fresh proof by its key, each time.
	for range 2 {
		if resp, b := dpopRequest(t, key, http.MethodGet, path, "DPoP", p.proof(t, http.MethodGet, uri, key.token)); resp.StatusCode != http.StatusOK {
			t.Fatalf("bound key with a proof = %d %s", resp.StatusCode, b)
		}
	}
	// And to make changes: the proof covers the method.
	if resp, b := dpopRequest(t, key, http.MethodPost, "/api/v1/profiles/lab/deny", "DPoP", p.proof(t, http.MethodPost, key.base+"/api/v1/profiles/lab/deny", key.token)); resp.StatusCode != http.StatusBadRequest {
		// No body, so the request is malformed: but it got past authorization.
		t.Errorf("bound key POST = %d %s, want 400 for the missing body", resp.StatusCode, b)
	}

	other := newProver(t, jwa.ES256)
	ec := p.key.(*ecdsa.PrivateKey)
	privateJWK, err := jwk.PublicValue(ec.Public())
	if err != nil {
		t.Fatal(err)
	}
	privateJWK["d"] = base64.RawURLEncoding.EncodeToString(ec.D.FillBytes(make([]byte, 32)))
	good := func() map[string]any { return proofClaims(http.MethodGet, uri, key.token) }
	h := func(change func(jws.Header)) jws.Header {
		h := jws.Header{header.Type: dpop.Type, header.Algorithm: jwa.ES256, header.JSONWebKey: p.public(t)}
		if change != nil {
			change(h)
		}
		return h
	}
	without := func(name string) map[string]any { c := good(); delete(c, name); return c }
	with := func(name string, v any) map[string]any { c := good(); c[name] = v; return c }
	past, err := dpop.NewSigner(p.key, dpop.WithClock(func() time.Time { return time.Now().Add(-proofMaxAge - 10*time.Second) }))
	if err != nil {
		t.Fatal(err)
	}
	future, err := dpop.NewSigner(p.key, dpop.WithClock(func() time.Time { return time.Now().Add(proofLeeway + 10*time.Second) }))
	if err != nil {
		t.Fatal(err)
	}
	signedBy := func(s *dpop.Signer, method, uri, token string) func() string {
		return func() string {
			proof, err := s.Proof(method, uri, dpop.ProofOptions{AccessToken: token})
			if err != nil {
				t.Fatal(err)
			}
			return proof
		}
	}
	hmacSign := func(secret []byte) func(string) []byte {
		return func(input string) []byte {
			m := hmac.New(sha256.New, secret)
			m.Write([]byte(input))
			return m.Sum(nil)
		}
	}
	publicBytes, _ := json.Marshal(p.public(t))

	for _, tt := range []struct {
		desc   string
		scheme string
		proofs func() []string
		code   string
	}{
		{"no proof", "DPoP", func() []string { return nil }, errInvalidProof},
		{"the Bearer scheme, with a proof", "Bearer", func() []string { return []string{p.proof(t, http.MethodGet, uri, key.token)} }, errInvalidToken},
		{"the Bearer scheme, without one", "Bearer", func() []string { return nil }, errInvalidToken},
		{"two proofs", "DPoP", func() []string {
			return []string{p.proof(t, http.MethodGet, uri, key.token), p.proof(t, http.MethodGet, uri, key.token)}
		}, errInvalidProof},
		{"a proof by another key", "DPoP", func() []string { return []string{other.proof(t, http.MethodGet, uri, key.token)} }, errInvalidProof},
		{"the bound key's jwk, signed by another", "DPoP", func() []string { return []string{signProof(t, h(nil), good(), other.key)} }, errInvalidProof},
		{"another method", "DPoP", func() []string { return []string{p.proof(t, http.MethodPost, uri, key.token)} }, errInvalidProof},
		{"another path", "DPoP", func() []string { return []string{p.proof(t, http.MethodGet, key.base+"/api/v1/profiles", key.token)} }, errInvalidProof},
		{"a path prefix", "DPoP", func() []string { return []string{p.proof(t, http.MethodGet, key.base+"/api/v1", key.token)} }, errInvalidProof},
		{"https, not http", "DPoP", func() []string {
			return []string{p.proof(t, http.MethodGet, strings.Replace(uri, "http://", "https://", 1), key.token)}
		}, errInvalidProof},
		{"another host", "DPoP", func() []string {
			return []string{p.proof(t, http.MethodGet, strings.Replace(uri, "127.0.0.1", "localhost", 1), key.token)}
		}, errInvalidProof},
		{"another port", "DPoP", func() []string { return []string{p.proof(t, http.MethodGet, "http://127.0.0.1:1"+path, key.token)} }, errInvalidProof},
		{"an htu with credentials", "DPoP", func() []string {
			return []string{signProof(t, h(nil), with("htu", "http://user@"+strings.TrimPrefix(uri, "http://")), p.key)}
		}, errInvalidProof},
		{"no htu", "DPoP", func() []string { return []string{signProof(t, h(nil), without("htu"), p.key)} }, errInvalidProof},
		{"no htm", "DPoP", func() []string { return []string{signProof(t, h(nil), without("htm"), p.key)} }, errInvalidProof},
		{"a stale iat", "DPoP", func() []string { return []string{signedBy(past, http.MethodGet, uri, key.token)()} }, errInvalidProof},
		{"a future iat", "DPoP", func() []string { return []string{signedBy(future, http.MethodGet, uri, key.token)()} }, errInvalidProof},
		{"no iat", "DPoP", func() []string { return []string{signProof(t, h(nil), without("iat"), p.key)} }, errInvalidProof},
		{"no jti", "DPoP", func() []string { return []string{signProof(t, h(nil), without("jti"), p.key)} }, errInvalidProof},
		{"no ath", "DPoP", func() []string { return []string{p.proof(t, http.MethodGet, uri, "")} }, errInvalidProof},
		{"another token's ath", "DPoP", func() []string { return []string{p.proof(t, http.MethodGet, uri, key.token+"x")} }, errInvalidProof},
		{"alg none", "DPoP", func() []string {
			return []string{rawJWS(t, map[string]any{"typ": dpop.Type, "alg": "none", "jwk": p.public(t)}, good(), func(string) []byte { return nil })}
		}, errInvalidProof},
		{"HMAC with the public key as its secret", "DPoP", func() []string {
			return []string{rawJWS(t, map[string]any{"typ": dpop.Type, "alg": "HS256", "jwk": p.public(t)}, good(), hmacSign(publicBytes))}
		}, errInvalidProof},
		{"a malformed JWT", "DPoP", func() []string { return []string{"not.a.jwt"} }, errInvalidProof},
		{"garbage", "DPoP", func() []string { return []string{"garbage"} }, errInvalidProof},
		{"typ JWT", "DPoP", func() []string {
			return []string{signProof(t, h(func(h jws.Header) { h[header.Type] = "JWT" }), good(), p.key)}
		}, errInvalidProof},
		{"no typ", "DPoP", func() []string {
			return []string{signProof(t, h(func(h jws.Header) { delete(h, header.Type) }), good(), p.key)}
		}, errInvalidProof},
		{"a private key in its jwk", "DPoP", func() []string {
			return []string{signProof(t, h(func(h jws.Header) { h[header.JSONWebKey] = privateJWK }), good(), p.key)}
		}, errInvalidProof},
		{"no jwk", "DPoP", func() []string {
			return []string{signProof(t, h(func(h jws.Header) { delete(h, header.JSONWebKey) }), good(), p.key)}
		}, errInvalidProof},
	} {
		resp, b := dpopRequest(t, key, http.MethodGet, path, tt.scheme, tt.proofs()...)
		wantRefused(t, tt.desc, resp, b, tt.code)
		if strings.Contains(string(b), "ath") || strings.Contains(string(b), "htu") || strings.Contains(string(b), "jkt") {
			t.Errorf("%s: the refusal says which check failed: %s", tt.desc, b)
		}
	}

	// A proof is accepted once.
	proof := p.proof(t, http.MethodGet, uri, key.token)
	if resp, b := dpopRequest(t, key, http.MethodGet, path, "DPoP", proof); resp.StatusCode != http.StatusOK {
		t.Fatalf("first use = %d %s", resp.StatusCode, b)
	}
	resp, b := dpopRequest(t, key, http.MethodGet, path, "DPoP", proof)
	wantRefused(t, "a replayed proof", resp, b, errInvalidProof)

	// A proof within the window is fine; the query isn't covered.
	recent, err := dpop.NewSigner(p.key, dpop.WithClock(func() time.Time { return time.Now().Add(-proofMaxAge / 2) }))
	if err != nil {
		t.Fatal(err)
	}
	if resp, b := dpopRequest(t, key, http.MethodGet, path+"?x=1", "DPoP", signedBy(recent, http.MethodGet, uri+"?y=2", key.token)()); resp.StatusCode != http.StatusOK {
		t.Errorf("a recent proof = %d %s", resp.StatusCode, b)
	}

	// The scheme is case-insensitive.
	if resp, b := dpopRequest(t, key, http.MethodGet, path, "dpop", p.proof(t, http.MethodGet, uri, key.token)); resp.StatusCode != http.StatusOK {
		t.Errorf("lower-case scheme = %d %s", resp.StatusCode, b)
	}
}

func TestDPoP_KeyAlgorithms(t *testing.T) {
	f := newTenantFixture(t)
	for _, tt := range []struct {
		alg  jwa.Algorithm
		opts []dpop.SignerOption
		ok   bool
	}{
		{jwa.ES256, nil, true},
		{jwa.EdDSA, nil, true},
		{jwa.RS256, []dpop.SignerOption{dpop.WithAlgorithm(jwa.RS256)}, true},
		{jwa.PS256, nil, false},
		{jwa.ES384, nil, false},
	} {
		p := newProver(t, tt.alg, tt.opts...)
		_, key := boundKey(t, f.operator, p)
		resp, b := dpopRequest(t, key, http.MethodGet, "/api/v1/status", "DPoP", p.proof(t, http.MethodGet, key.base+"/api/v1/status", key.token))
		if tt.ok && resp.StatusCode != http.StatusOK {
			t.Errorf("%s = %d %s, want it accepted", tt.alg, resp.StatusCode, b)
		}
		if !tt.ok {
			wantRefused(t, string(tt.alg), resp, b, errInvalidProof)
		}
	}
}

func TestDPoP_UnboundCredentialsUnaffected(t *testing.T) {
	f := newTenantFixture(t)
	_, key := createAccount(t, f.operator, `{"name":"Plain"}`)
	p := newProver(t, jwa.ES256)
	uri := key.base + "/api/v1/status"

	for _, c := range []apiClient{key, f.operator} {
		if resp, b := c.do(http.MethodGet, "/api/v1/status", ""); resp.StatusCode != http.StatusOK {
			t.Errorf("unbound credential as a bearer token = %d %s", resp.StatusCode, b)
		}
		// Sent with the DPoP scheme, it's refused: there's no key to
		// check the proof against.
		resp, b := dpopRequest(t, c, http.MethodGet, "/api/v1/status", "DPoP", p.proof(t, http.MethodGet, uri, c.token))
		wantRefused(t, "an unbound credential with the DPoP scheme", resp, b, errInvalidToken)
	}

	// Unknown credentials are refused under either scheme.
	forged := apiClient{t, key.base, serviceaccount.SecretPrefix + "0123456789abcdef_" + strings.Repeat("A", 43)}
	resp, b := dpopRequest(t, forged, http.MethodGet, "/api/v1/status", "DPoP", p.proof(t, http.MethodGet, uri, forged.token))
	wantRefused(t, "a forged key with the DPoP scheme", resp, b, errInvalidToken)
}

func TestDPoP_KeyNotMarkedUsedWithoutAProof(t *testing.T) {
	f := newTenantFixture(t)
	p := newProver(t, jwa.ES256)
	a, key := boundKey(t, f.operator, p)

	if resp, _ := key.do(http.MethodGet, "/api/v1/status", ""); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("bound key as a bearer token = %d", resp.StatusCode)
	}
	if got, _ := f.s.accounts.Account(a.ID); !got.Keys[0].LastUsed.IsZero() {
		t.Errorf("a refused key was marked used at %v", got.Keys[0].LastUsed)
	}
	if resp, _ := dpopRequest(t, key, http.MethodGet, "/api/v1/status", "DPoP", p.proof(t, http.MethodGet, key.base+"/api/v1/status", key.token)); resp.StatusCode != http.StatusOK {
		t.Fatalf("bound key with a proof = %d", resp.StatusCode)
	}
	if got, _ := f.s.accounts.Account(a.ID); got.Keys[0].LastUsed.IsZero() {
		t.Error("an accepted key wasn't marked used")
	}
}

func TestDPoP_BadThumbprintRefused(t *testing.T) {
	f := newTenantFixture(t)
	a := createBareAccount(t, f.operator, `{"name":"Bound"}`)
	for _, jkt := range []string{"short", strings.Repeat("A", 42) + "=", strings.Repeat("!", 43), strings.Repeat("A", 42) + "B"} {
		if resp, b := f.operator.do(http.MethodPost, "/api/v1/service-accounts/"+a.ID+"/keys", `{"jkt":"`+jkt+`"}`); resp.StatusCode != http.StatusBadRequest {
			t.Errorf("key bound to %q = %d %s, want 400", jkt, resp.StatusCode, b)
		}
	}
}

func TestDPoP_RotateBindsTheNewKey(t *testing.T) {
	f := newTenantFixture(t)
	p := newProver(t, jwa.ES256)
	a, old := boundKey(t, f.operator, p)
	next := newProver(t, jwa.ES256)
	k := strings.Split(strings.TrimPrefix(old.token, serviceaccount.SecretPrefix), "_")[0]

	resp, b := f.operator.do(http.MethodPost, "/api/v1/service-accounts/"+a.ID+"/keys/"+k+"/rotate", `{"jkt":"`+next.signer.Thumbprint()+`"}`)
	var nk api.NewKey
	if err := json.Unmarshal(b, &nk); resp.StatusCode != http.StatusCreated || err != nil || nk.Key.JKT != next.signer.Thumbprint() {
		t.Fatalf("rotate = %d %s", resp.StatusCode, b)
	}
	key := apiClient{t, old.base, nk.Secret}
	uri := key.base + "/api/v1/status"
	resp, b = dpopRequest(t, key, http.MethodGet, "/api/v1/status", "DPoP", p.proof(t, http.MethodGet, uri, key.token))
	wantRefused(t, "the new key with the old key's proof", resp, b, errInvalidProof)
	if resp, b := dpopRequest(t, key, http.MethodGet, "/api/v1/status", "DPoP", next.proof(t, http.MethodGet, uri, key.token)); resp.StatusCode != http.StatusOK {
		t.Errorf("the new key with its own proof = %d %s", resp.StatusCode, b)
	}
}

// TestDPoP_AdminOrigin checks the htu a proof must name behind a proxy:
// the configured origin, or the listener itself on a loopback address,
// never a host the request merely claims.
func TestDPoP_AdminOrigin(t *testing.T) {
	up, _ := startZone(t, nil)
	s, dataDir := newPolicyServer(t, up, &policy.Policy{Profiles: []policy.Profile{{ID: "default"}}}, func(c *Config) {
		c.Admin.Origins = []string{"https://admin.example.com", "https://admin.example.com:8443"}
	})
	base := startAdmin(t, s)
	operator := apiClient{t, base, token(t, dataDir, AdminTokenFile)}
	p := newProver(t, jwa.ES256)
	_, key := boundKey(t, operator, p)
	path := "/api/v1/status"

	get := func(host, htu string) (*http.Response, []byte) {
		t.Helper()
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, base+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		if host != "" {
			req.Host = host
		}
		req.Header.Set("Authorization", "DPoP "+key.token)
		req.Header.Set("DPoP", p.proof(t, http.MethodGet, htu, key.token))
		return send(t, req)
	}
	for _, htu := range []string{"https://admin.example.com" + path, "https://ADMIN.example.com:443" + path, "https://admin.example.com:8443" + path, base + path} {
		if resp, b := get("", htu); resp.StatusCode != http.StatusOK {
			t.Errorf("proof for %s = %d %s", htu, resp.StatusCode, b)
		}
	}
	for _, tt := range []struct{ host, htu string }{
		{"", "http://admin.example.com" + path},
		{"", "https://admin.example.com:9443" + path},
		{"", "https://dns.example.net" + path},
		{"", "https://evil.example" + path},
		{"", "https://admin.example.com.evil.example" + path},
		{"", "https://admin.example.com/api/v1/policy"},
		// The request's Host isn't trusted once there are origins.
		{"evil.example", "http://evil.example" + path},
		{"admin.example.com", "http://admin.example.com" + path},
	} {
		resp, b := get(tt.host, tt.htu)
		wantRefused(t, "proof for "+tt.htu+" with Host "+tt.host, resp, b, errInvalidProof)
	}
}

func TestDPoP_TokenExchange(t *testing.T) {
	w := newWorkloads(t)
	a := createBareAccount(t, w.operator, `{"name":"Deploys","role":"admin"}`)
	w.trust(t, w.operator, a.ID)
	p := newProver(t, jwa.ES256)
	tokenURI := w.operator.base + "/api/v1/token"

	exchange := func(proofs ...string) (*http.Response, []byte) {
		t.Helper()
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, tokenURI, strings.NewReader(exchangeForm(a.ID, w.token(t, nil)).Encode()))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		for _, proof := range proofs {
			req.Header.Add("DPoP", proof)
		}
		return send(t, req)
	}

	// With a proof, the access token is bound to its key.
	resp, b := exchange(p.proof(t, http.MethodPost, tokenURI, ""))
	var tr api.TokenResponse
	if err := json.Unmarshal(b, &tr); resp.StatusCode != http.StatusOK || err != nil || tr.TokenType != "DPoP" {
		t.Fatalf("exchange with a proof = %d %s, want a DPoP token", resp.StatusCode, b)
	}
	bound := apiClient{t, w.operator.base, tr.AccessToken}
	uri := bound.base + "/api/v1/status"
	if resp, b := dpopRequest(t, bound, http.MethodGet, "/api/v1/status", "DPoP", p.proof(t, http.MethodGet, uri, bound.token)); resp.StatusCode != http.StatusOK {
		t.Errorf("bound access token with a proof = %d %s", resp.StatusCode, b)
	}
	resp, b = bound.do(http.MethodGet, "/api/v1/status", "")
	wantRefused(t, "a bound access token as a bearer token", resp, b, errInvalidToken)
	resp, b = dpopRequest(t, bound, http.MethodGet, "/api/v1/status", "DPoP")
	wantRefused(t, "a bound access token without a proof", resp, b, errInvalidProof)
	resp, b = dpopRequest(t, bound, http.MethodGet, "/api/v1/status", "DPoP", newProver(t, jwa.ES256).proof(t, http.MethodGet, uri, bound.token))
	wantRefused(t, "a bound access token with another key's proof", resp, b, errInvalidProof)

	// A bad proof refuses the exchange, saying only that.
	other := newProver(t, jwa.ES256)
	replayed := other.proof(t, http.MethodPost, tokenURI, "")
	if resp, b := exchange(replayed); resp.StatusCode != http.StatusOK {
		t.Fatalf("exchange = %d %s", resp.StatusCode, b)
	}
	for desc, proofs := range map[string][]string{
		"a proof for another URL": {other.proof(t, http.MethodPost, w.operator.base+"/api/v1/status", "")},
		"a proof for GET":         {other.proof(t, http.MethodGet, tokenURI, "")},
		"a malformed proof":       {"not.a.proof"},
		"two proofs":              {other.proof(t, http.MethodPost, tokenURI, ""), other.proof(t, http.MethodPost, tokenURI, "")},
		"an empty proof":          {""},
		"alg none":                {rawJWS(t, map[string]any{"typ": dpop.Type, "alg": "none", "jwk": other.public(t)}, proofClaims(http.MethodPost, tokenURI, ""), func(string) []byte { return nil })},
		"a replayed proof":        {replayed},
	} {
		resp, b := exchange(proofs...)
		var e api.OAuthError
		if err := json.Unmarshal(b, &e); resp.StatusCode != http.StatusBadRequest || err != nil || e.Error != dpop.ErrorInvalidProof {
			t.Errorf("exchange with %s = %d %s, want 400 invalid_dpop_proof", desc, resp.StatusCode, b)
		}
	}

	// Without a proof, it's a bearer token, as before.
	resp, b = exchange()
	if err := json.Unmarshal(b, &tr); resp.StatusCode != http.StatusOK || err != nil || tr.TokenType != "Bearer" {
		t.Fatalf("exchange without a proof = %d %s", resp.StatusCode, b)
	}
	if resp, b := (apiClient{t, w.operator.base, tr.AccessToken}).do(http.MethodGet, "/api/v1/status", ""); resp.StatusCode != http.StatusOK {
		t.Errorf("unbound access token = %d %s", resp.StatusCode, b)
	}

	// Proofs don't rescue identity tokens: those are checked first.
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, tokenURI, strings.NewReader(exchangeForm(a.ID, "forged").Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("DPoP", p.proof(t, http.MethodPost, tokenURI, ""))
	if resp, b := send(t, req); resp.StatusCode != http.StatusBadRequest || !strings.Contains(string(b), errInvalidGrant) {
		t.Errorf("forged identity token with a proof = %d %s", resp.StatusCode, b)
	}
}

func TestDPoP_RuleRequiresDPoP(t *testing.T) {
	w := newWorkloads(t)
	a := createBareAccount(t, w.operator, `{"name":"Deploys","role":"admin"}`)
	rule := strings.TrimSuffix(w.rule(), "}") + `,"require_dpop":true}`
	resp, b := w.operator.do(http.MethodPost, "/api/v1/service-accounts/"+a.ID+"/federation", rule)
	var r serviceaccount.TrustRule
	if err := json.Unmarshal(b, &r); resp.StatusCode != http.StatusCreated || err != nil || !r.RequireDPoP {
		t.Fatalf("add rule = %d %s", resp.StatusCode, b)
	}

	resp, b = w.exchange(t, exchangeForm(a.ID, w.token(t, nil)))
	var e api.OAuthError
	if err := json.Unmarshal(b, &e); resp.StatusCode != http.StatusBadRequest || err != nil || e.Error != dpop.ErrorInvalidProof {
		t.Errorf("proofless exchange = %d %s, want 400 invalid_dpop_proof", resp.StatusCode, b)
	}
	if !strings.Contains(w.log.String(), "no DPoP proof") {
		t.Errorf("the refusal's reason isn't logged:\n%s", w.log)
	}

	p := newProver(t, jwa.EdDSA)
	tokenURI := w.operator.base + "/api/v1/token"
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, tokenURI, strings.NewReader(exchangeForm(a.ID, w.token(t, nil)).Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("DPoP", p.proof(t, http.MethodPost, tokenURI, ""))
	resp, b = send(t, req)
	var tr api.TokenResponse
	if err := json.Unmarshal(b, &tr); resp.StatusCode != http.StatusOK || err != nil || tr.TokenType != "DPoP" {
		t.Fatalf("exchange with a proof = %d %s", resp.StatusCode, b)
	}
	bound := apiClient{t, w.operator.base, tr.AccessToken}
	if resp, b := dpopRequest(t, bound, http.MethodGet, "/api/v1/status", "DPoP", p.proof(t, http.MethodGet, bound.base+"/api/v1/status", bound.token)); resp.StatusCode != http.StatusOK {
		t.Errorf("bound access token = %d %s", resp.StatusCode, b)
	}

	// The store won't issue an unbound token under the rule either.
	if _, _, err := w.s.accounts.IssueToken(a.ID, r.ID, githubSubject); err == nil {
		t.Error("the store issued an unbound token under a rule requiring DPoP")
	}
}

// TestDPoP_Client checks the server and the CLI's client agree: a key
// bound with the client's signer, and an exchange through it, work end
// to end.
func TestDPoP_Client(t *testing.T) {
	w := newWorkloads(t)
	a := createBareAccount(t, w.operator, `{"name":"Deploys","role":"admin"}`)
	w.trust(t, w.operator, a.ID)
	key, err := client.GenerateDPoPKey()
	if err != nil {
		t.Fatal(err)
	}
	signer, err := client.NewDPoPSigner(key)
	if err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()

	c := &client.Client{Addr: w.operator.base, DPoP: signer}
	tr, err := c.ExchangeToken(ctx, api.TokenExchangeRequest{SubjectToken: w.token(t, nil), Audience: a.ID})
	if err != nil || tr.TokenType != "DPoP" {
		t.Fatalf("ExchangeToken = %+v, %v", tr, err)
	}
	c.Token = tr.AccessToken
	if _, err := c.Status(ctx); err != nil {
		t.Errorf("Status with a bound access token: %v", err)
	}
	if _, err := c.Profiles(ctx); err != nil {
		t.Errorf("Profiles with a bound access token: %v", err)
	}
	if _, err := (&client.Client{Addr: w.operator.base, Token: tr.AccessToken}).Status(ctx); err == nil {
		t.Error("the bound access token worked without its key")
	}

	operator := &client.Client{Addr: w.operator.base, Token: w.operator.token}
	k, err := operator.AddServiceAccountKey(ctx, a.ID, api.KeyRequest{Expires: time.Now().Add(time.Hour), JKT: signer.Thumbprint()})
	if err != nil {
		t.Fatal(err)
	}
	c.Token = k.Secret
	if _, err := c.Status(ctx); err != nil {
		t.Errorf("Status with a bound key: %v", err)
	}
}
