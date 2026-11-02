package client

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"testing"

	"github.com/picatz/doh/internal/api"
	"github.com/picatz/jose/pkg/dpop"
	"github.com/picatz/jose/pkg/dpop/dpophttp"
	"github.com/picatz/jose/pkg/jwa"
)

func TestDPoPKeys(t *testing.T) {
	key, err := GenerateDPoPKey()
	if err != nil {
		t.Fatal(err)
	}
	want, err := NewDPoPSigner(key)
	if err != nil || want.Algorithm() != jwa.ES256 {
		t.Fatalf("NewDPoPSigner = %v, %v", want, err)
	}

	// A key round-trips through PEM.
	b, err := MarshalDPoPKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := ParseDPoPKey(b); err != nil || got.Thumbprint() != want.Thumbprint() {
		t.Fatalf("ParseDPoPKey(MarshalDPoPKey) = %v, %v", got, err)
	}

	// So does the SEC 1 form openssl ecparam writes, after its parameters.
	sec1, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	openssl := append(pem.EncodeToMemory(&pem.Block{Type: "EC PARAMETERS", Bytes: []byte{6, 8, 42, 134, 72, 206, 61, 3, 1, 7}}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: sec1})...)
	if got, err := ParseDPoPKey(openssl); err != nil || got.Thumbprint() != want.Thumbprint() {
		t.Errorf("ParseDPoPKey(SEC 1) = %v, %v", got, err)
	}

	// Ed25519 signs with EdDSA, and RSA with RS256, which servers accept.
	_, ed, _ := ed25519.GenerateKey(rand.Reader)
	if s, err := NewDPoPSigner(ed); err != nil || s.Algorithm() != jwa.EdDSA {
		t.Errorf("Ed25519 signer = %v, %v", s, err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	if s, err := NewDPoPSigner(rsaKey); err != nil || s.Algorithm() != jwa.RS256 {
		t.Errorf("RSA signer = %v, %v", s, err)
	}

	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	smallRSA, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8 := func(k any) []byte {
		der, err := x509.MarshalPKCS8PrivateKey(k)
		if err != nil {
			t.Fatal(err)
		}
		return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	}
	pub, _ := x509.MarshalPKIXPublicKey(key.Public())
	for name, b := range map[string][]byte{
		"empty":         nil,
		"not PEM":       []byte("-----BEGIN NOTHING"),
		"two keys":      append(pkcs8(key), pkcs8(key)...),
		"trailing junk": append(pkcs8(key), "junk"...),
		"a public key":  pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pub}),
		"P-384":         pkcs8(p384),
		"1024-bit RSA":  pkcs8(smallRSA),
		"bad DER":       pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1, 2, 3}}),
	} {
		if _, err := ParseDPoPKey(b); err == nil {
			t.Errorf("ParseDPoPKey accepted %s", name)
		}
	}
}

func TestClient_SignsDPoPProofs(t *testing.T) {
	key, _ := GenerateDPoPKey()
	signer, err := NewDPoPSigner(key)
	if err != nil {
		t.Fatal(err)
	}
	verifier := &dpop.Verifier{Replay: dpop.NewMemoryReplayCache(10, nil)}
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		proof, err := dpophttp.FromRequest(r)
		if err != nil {
			t.Errorf("%s: %v", r.URL.Path, err)
		}
		req := dpop.Request{Method: r.Method, URI: "http://" + r.Host + r.URL.Path, Thumbprint: signer.Thumbprint()}
		if r.URL.Path == "/api/v1/token" {
			// An exchange sends no credential of its own, and gets a token
			// bound to the key.
			if r.Header.Get("Authorization") != "" {
				t.Errorf("exchange sent Authorization %q", r.Header.Get("Authorization"))
			}
			if _, err := verifier.Verify(r.Context(), proof, req); err != nil {
				t.Errorf("exchange proof: %v", err)
			}
			writeJSON(w, http.StatusOK, api.TokenResponse{AccessToken: "doh_at_x", TokenType: "DPoP"})
			return
		}
		token, err := dpophttp.AccessTokenFromRequest(r)
		if err != nil || token != "secret" {
			t.Errorf("Authorization = %q, want the DPoP scheme", r.Header.Get("Authorization"))
		}
		req.AccessToken = token
		if _, err := verifier.Verify(r.Context(), proof, req); err != nil {
			t.Errorf("%s %s proof: %v", r.Method, r.URL.Path, err)
		}
		writeJSON(w, http.StatusOK, api.Status{})
	})
	c.DPoP = signer

	ctx := context.Background()
	for range 2 { // a fresh proof each time, or the replay cache refuses it
		if _, err := c.Status(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := c.Profiles(ctx); err != nil {
		t.Fatal(err)
	}
	tr, err := c.ExchangeToken(ctx, api.TokenExchangeRequest{SubjectToken: "id", Audience: "a"})
	if err != nil || tr.TokenType != "DPoP" {
		t.Fatalf("ExchangeToken = %+v, %v", tr, err)
	}
}
