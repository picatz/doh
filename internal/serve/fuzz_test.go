package serve

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/picatz/jose/pkg/dpop"
	"github.com/picatz/jose/pkg/josetest"
	"github.com/picatz/jose/pkg/jwa"
)

// FuzzVerifyProof sends arbitrary DPoP headers with a credential bound to
// a key: it must never panic, and may accept only a proof that key
// signed, for this request, once.
func FuzzVerifyProof(f *testing.F) {
	key := josetest.Key(f, jwa.ES256)
	signer, err := dpop.NewSigner(key)
	if err != nil {
		f.Fatal(err)
	}
	other, _ := dpop.NewSigner(josetest.Key(f, jwa.ES256))
	const uri, token = "http://127.0.0.1:9090/api/v1/policy", "access-token"

	signed := map[string]bool{} // the proofs signer made, by their signing input
	for _, s := range []*dpop.Signer{signer, other} {
		for _, method := range []string{http.MethodGet, http.MethodPost} {
			for _, tok := range []string{token, ""} {
				proof, err := s.Proof(method, uri, dpop.ProofOptions{AccessToken: tok})
				if err != nil {
					f.Fatal(err)
				}
				if s == signer {
					signed[proof[:strings.LastIndexByte(proof, '.')]] = true
				}
				f.Add(method == http.MethodPost, proof)
			}
		}
	}
	f.Add(false, "")
	f.Add(false, "a.b.c")
	f.Add(false, "eyJhbGciOiJub25lIn0.e30.")

	s := &Server{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	v := newProofVerifier()
	accepted := map[string]bool{}
	f.Fuzz(func(t *testing.T, post bool, proof string) {
		method := http.MethodGet
		if post {
			method = http.MethodPost
		}
		r := httptest.NewRequest(method, uri, nil)
		r.Header.Set("DPoP", proof)
		p, err := s.verifyProof(v, r, token, signer.Thumbprint())
		if err != nil {
			return
		}
		input := proof[:strings.LastIndexByte(proof, '.')]
		switch {
		case p.Thumbprint != signer.Thumbprint():
			t.Fatalf("accepted a proof by another key: %s", proof)
		case !signed[input]:
			t.Fatalf("accepted a proof the key didn't sign: %s", proof)
		case accepted[input]:
			t.Fatalf("accepted a proof twice: %s", proof)
		}
		accepted[input] = true
	})
}

// FuzzCredential parses Authorization headers: it must never panic, and
// only the Bearer and DPoP schemes give a credential.
func FuzzCredential(f *testing.F) {
	for _, s := range []string{"Bearer abc", "DPoP abc", "bearer  x ", "Basic dXNlcjpwYXNz", "Bearer", "", " Bearer x"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, header string) {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("Authorization", header)
		token, isDPoP, ok := credential(r)
		if !ok {
			if token != "" || isDPoP {
				t.Fatalf("no credential, but token %q, DPoP %v", token, isDPoP)
			}
			return
		}
		scheme, _, _ := strings.Cut(r.Header.Get("Authorization"), " ")
		if want := strings.EqualFold(scheme, "DPoP"); isDPoP != want || (!want && !strings.EqualFold(scheme, "Bearer")) {
			t.Fatalf("scheme %q gave DPoP %v", scheme, isDPoP)
		}
		if token != strings.TrimSpace(token) {
			t.Fatalf("token %q isn't trimmed", token)
		}
	})
}
