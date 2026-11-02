package serviceaccount

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// testJKT is a well-formed thumbprint.
var testJKT = func() string {
	sum := sha256.Sum256([]byte("a public key"))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}()

func TestValidThumbprint(t *testing.T) {
	if !ValidThumbprint(testJKT) {
		t.Fatalf("ValidThumbprint(%q) = false", testJKT)
	}
	// RFC 7638, Section 3.1's example.
	if !ValidThumbprint("NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs") {
		t.Error("the RFC 7638 example isn't a valid thumbprint")
	}
	for _, jkt := range []string{
		"",
		testJKT[:42],
		testJKT + "A",
		testJKT + "=",
		strings.ReplaceAll(testJKT, testJKT[:1], "+"),
		strings.Repeat("A", 42) + "B", // non-zero trailing bits: not canonical
		strings.Repeat("!", 43),
	} {
		if ValidThumbprint(jkt) {
			t.Errorf("ValidThumbprint(%q) = true", jkt)
		}
	}
}

func TestStore_BoundKeys(t *testing.T) {
	s, c, path := newStore(t)
	a, _ := s.Create(NewAccount{Name: "CI", Role: RoleAdmin})

	if _, _, err := s.AddKey(a.ID, c.Now().Add(day), BoundTo("not a thumbprint")); !errors.Is(err, ErrInvalid) {
		t.Errorf("AddKey with a malformed jkt = %v, want ErrInvalid", err)
	}
	k, secret, err := s.AddKey(a.ID, c.Now().Add(day), BoundTo(testJKT))
	if err != nil || k.JKT != testJKT || !k.Bound() {
		t.Fatalf("AddKey bound = %+v, %v", k, err)
	}
	plain, plainSecret, _ := s.AddKey(a.ID, c.Now().Add(day))
	if plain.Bound() {
		t.Fatal("an unbound key is bound")
	}

	// Lookup finds the key, binding and all, without marking it used;
	// MarkUsed does.
	_, got, ok := s.Lookup(secret)
	if !ok || got.JKT != testJKT {
		t.Fatalf("Lookup = %+v, %v", got, ok)
	}
	if !mustAccount(t, s, a.ID).Keys[0].LastUsed.IsZero() {
		t.Error("Lookup marked the key used")
	}
	s.MarkUsed(k.ID)
	if mustAccount(t, s, a.ID).Keys[0].LastUsed.IsZero() {
		t.Error("MarkUsed didn't mark the key used")
	}
	s.MarkUsed("0000000000000000") // a key that's gone is ignored
	if _, _, ok := s.Lookup(secret + "x"); ok {
		t.Error("Lookup accepted a forged secret")
	}

	// The binding survives a restart, and the unbound key stays unbound.
	reopened, err := Open(path, WithClock(c.Now))
	if err != nil {
		t.Fatal(err)
	}
	if _, got, ok := reopened.Lookup(secret); !ok || got.JKT != testJKT {
		t.Errorf("after reopening, the bound key = %+v, %v", got, ok)
	}
	if _, got, ok := reopened.Lookup(plainSecret); !ok || got.Bound() {
		t.Errorf("after reopening, the unbound key = %+v, %v", got, ok)
	}

	// Unbound keys leave the field out, so older binaries still load the
	// file; bound ones have it.
	b, _ := os.ReadFile(path)
	if n := strings.Count(string(b), `"jkt"`); n != 1 {
		t.Errorf("the file has %d jkt fields, want 1 for the one bound key:\n%s", n, b)
	}

	// Rotating binds the new key only as asked.
	next, _, err := s.RotateKey(a.ID, k.ID, c.Now().Add(day), 0)
	if err != nil || next.Bound() {
		t.Errorf("rotated without BoundTo = %+v, %v; want an unbound key", next, err)
	}
	rebound, _, err := s.RotateKey(a.ID, plain.ID, c.Now().Add(day), 0, BoundTo(testJKT))
	if err != nil || rebound.JKT != testJKT {
		t.Errorf("rotated with BoundTo = %+v, %v", rebound, err)
	}
	if _, _, err := s.RotateKey(a.ID, next.ID, c.Now().Add(day), 0, BoundTo("x")); !errors.Is(err, ErrInvalid) {
		t.Errorf("rotated with a malformed jkt = %v", err)
	}
}

func TestStore_LoadRejectsMalformedThumbprints(t *testing.T) {
	key := func(jkt string) string {
		return `{"version":1,"accounts":[{"id":"a","name":"x","role":"admin","created":"2026-01-01T00:00:00Z","keys":[{"id":"0123456789abcdef","digest":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","created":"2026-01-01T00:00:00Z","expires":"2027-01-01T00:00:00Z"` + jkt + `}]}]}`
	}
	for name, tt := range map[string]struct {
		content string
		ok      bool
	}{
		"no jkt, as before": {key(""), true},
		"a jkt":             {key(`,"jkt":"` + testJKT + `"`), true},
		"a malformed jkt":   {key(`,"jkt":"abc"`), false},
		"a padded jkt":      {key(`,"jkt":"` + testJKT + `="`), false},
	} {
		path := filepath.Join(t.TempDir(), "sa.json")
		if err := os.WriteFile(path, []byte(tt.content), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Open(path); (err == nil) != tt.ok {
			t.Errorf("%s: Open = %v, want ok %v", name, err, tt.ok)
		}
	}
}

func TestAccessTokens_Bound(t *testing.T) {
	s, _, path := newStore(t)
	a, _ := s.Create(NewAccount{Name: "CI", Role: RoleAdmin})
	optional, err := s.AddTrustRule(a.ID, githubRule())
	if err != nil {
		t.Fatal(err)
	}
	strict := githubRule()
	strict.RequireDPoP = true
	required, err := s.AddTrustRule(a.ID, strict)
	if err != nil || !required.RequireDPoP {
		t.Fatalf("AddTrustRule = %+v, %v", required, err)
	}

	// A rule requiring DPoP issues only bound tokens.
	if _, _, err := s.IssueToken(a.ID, required.ID, "sub"); !errors.Is(err, ErrInvalid) {
		t.Errorf("unbound token under a rule requiring DPoP: %v", err)
	}
	if _, _, err := s.IssueToken(a.ID, optional.ID, "sub", BoundTo("nope")); !errors.Is(err, ErrInvalid) {
		t.Errorf("token bound to a malformed jkt: %v", err)
	}
	for _, rule := range []string{optional.ID, required.ID} {
		at, secret, err := s.IssueToken(a.ID, rule, "sub", BoundTo(testJKT))
		if err != nil || at.JKT != testJKT || !at.Bound() {
			t.Fatalf("bound token = %+v, %v", at, err)
		}
		if _, got, ok := s.AuthenticateToken(secret); !ok || got.JKT != testJKT {
			t.Errorf("AuthenticateToken = %+v, %v; want its binding", got, ok)
		}
	}
	at, _, err := s.IssueToken(a.ID, optional.ID, "sub")
	if err != nil || at.Bound() {
		t.Errorf("unbound token = %+v, %v", at, err)
	}

	// The requirement survives a restart.
	reopened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	got := mustAccount(t, reopened, a.ID).Federation
	if len(got) != 2 || got[0].RequireDPoP || !got[1].RequireDPoP {
		t.Errorf("after reopening, rules = %+v", got)
	}
	b, _ := os.ReadFile(path)
	if n := strings.Count(string(b), "require_dpop"); n != 1 {
		t.Errorf("the file has %d require_dpop fields, want 1:\n%s", n, b)
	}
}
