package serviceaccount

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// FuzzLookup sends arbitrary bearer tokens, as clients send them: lookup
// must never panic, and only a key's exact secret finds its key.
func FuzzLookup(f *testing.F) {
	now := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	s, err := Open(filepath.Join(f.TempDir(), "service-accounts.json"), WithClock(func() time.Time { return now }))
	if err != nil {
		f.Fatal(err)
	}
	a, err := s.Create(NewAccount{Name: "ci", Role: RoleAdmin})
	if err != nil {
		f.Fatal(err)
	}
	key, secret, err := s.AddKey(a.ID, now.Add(24*time.Hour))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(secret)
	f.Add(strings.ToUpper(secret))
	f.Add(secret[:len(secret)-1] + "A")
	f.Add(secret + "=")
	f.Add(SecretPrefix + strings.Repeat("0", keyIDLen) + "_" + strings.Repeat("A", 43))
	f.Add("")
	f.Fuzz(func(t *testing.T, token string) {
		got, k, ok := s.Lookup(token)
		if !ok {
			return
		}
		if token != secret || got.ID != a.ID || k.ID != key.ID {
			t.Fatalf("token %q found key %s of %s", token, k.ID, got.ID)
		}
	})
}
