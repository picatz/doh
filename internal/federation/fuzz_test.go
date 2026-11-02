package federation

import (
	"strings"
	"testing"
	"time"

	"github.com/picatz/doh/internal/serviceaccount"
	"github.com/picatz/jose/pkg/josetest"
	"github.com/picatz/jose/pkg/jwa"
	"github.com/picatz/jose/pkg/jwt"
)

// FuzzVerify sends arbitrary identity tokens for token exchange, as
// anyone can: it must never panic, and may accept only a token the
// provider signed, whose claims satisfy the rule.
func FuzzVerify(f *testing.F) {
	p := newProvider(f)
	rule := p.rule()
	v := &Verifier{}

	good := p.claims()
	wrongSubject := p.claims()
	wrongSubject[jwt.Subject] = "repo:evil/app:ref:refs/heads/main"
	expired := p.claims()
	expired[jwt.ExpirationTime] = time.Now().Add(-time.Hour)

	signed := map[string]bool{} // the provider's tokens, by signing input
	for _, c := range []jwt.ClaimsSet{good, wrongSubject, expired} {
		token := josetest.Token(f, p.key, c)
		signed[token[:strings.LastIndexByte(token, '.')]] = true
		f.Add(token)
	}
	other := josetest.Token(f, josetest.Key(f, jwa.ES256), good)
	f.Add(other)
	f.Add("eyJhbGciOiJub25lIn0." + strings.Split(other, ".")[1] + ".")
	f.Add("")
	f.Add("a.b.c")

	f.Fuzz(func(t *testing.T, token string) {
		r, claims, err := v.Verify(t.Context(), []serviceaccount.TrustRule{rule}, token)
		if err != nil {
			return
		}
		if i := strings.LastIndexByte(token, '.'); i < 0 || !signed[token[:i]] {
			t.Fatalf("accepted a token the provider didn't sign: %s", token)
		}
		if r.ID != rule.ID || claims[jwt.Subject] != rule.Subject || claims[jwt.Issuer] != rule.Issuer {
			t.Fatalf("accepted claims %v for rule %+v", claims, r)
		}
	})
}
