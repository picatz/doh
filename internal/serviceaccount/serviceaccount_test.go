package serviceaccount

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// clock is a settable time source.
type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.now }
func (c *clock) Add(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

func newStore(t *testing.T) (*Store, *clock, string) {
	t.Helper()
	c := &clock{now: time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)}
	path := filepath.Join(t.TempDir(), "service-accounts.json")
	s, err := Open(path, WithClock(c.Now))
	if err != nil {
		t.Fatal(err)
	}
	return s, c, path
}

const day = 24 * time.Hour

func TestStore_KeysAuthenticate(t *testing.T) {
	s, c, _ := newStore(t)
	a, err := s.Create(NewAccount{Name: "Home Assistant", Tenant: "smiths", Role: RoleReader, CreatedBy: "kent"})
	if err != nil {
		t.Fatal(err)
	}
	if len(a.ID) != 16 || a.Tenant != "smiths" || a.Role != RoleReader || len(a.Keys) != 0 {
		t.Fatalf("Create = %+v", a)
	}

	k, secret, err := s.AddKey(a.ID, c.Now().Add(90*day))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(secret, SecretPrefix+k.ID+"_") || !IsSecret(secret) {
		t.Fatalf("secret %q doesn't name its key %s", secret, k.ID)
	}

	got, gk, ok := s.Authenticate(secret)
	if !ok || got.ID != a.ID || gk.ID != k.ID || got.Tenant != "smiths" {
		t.Fatalf("Authenticate = %+v, %+v, %v", got, gk, ok)
	}
	if gk.LastUsed.IsZero() {
		t.Error("Authenticate didn't record the key's use")
	}
}

func TestStore_RejectsForgedAndMalformed(t *testing.T) {
	s, c, _ := newStore(t)
	a, _ := s.Create(NewAccount{Name: "ci", Role: RoleAdmin})
	k, secret, _ := s.AddKey(a.ID, c.Now().Add(day))

	// The right key ID with another secret: forged.
	forged := secret[:len(secret)-4] + "AAAA"
	if forged == secret {
		forged = secret[:len(secret)-4] + "BBBB"
	}
	for name, token := range map[string]string{
		"forged":           forged,
		"another key":      SecretPrefix + "0123456789abcdef_" + strings.Repeat("A", 43),
		"empty":            "",
		"prefix only":      SecretPrefix,
		"truncated":        secret[:len(secret)-1],
		"extended":         secret + "A",
		"upper-case ID":    SecretPrefix + strings.ToUpper(k.ID) + secret[len(SecretPrefix)+keyIDLen:],
		"not hex":          SecretPrefix + "zzzzzzzzzzzzzzzz_" + strings.Repeat("A", 43),
		"no separator":     SecretPrefix + k.ID + "-" + secret[len(SecretPrefix)+keyIDLen+1:],
		"operator token":   "doh_admin_" + strings.Repeat("A", 43),
		"whitespace":       " " + secret,
		"other prefix":     "doh_sb_" + secret[len(SecretPrefix):],
		"secret alone":     secret[len(SecretPrefix)+keyIDLen+1:],
		"account ID":       a.ID,
		"key ID":           k.ID,
		"key ID as secret": SecretPrefix + k.ID + "_" + k.ID,
	} {
		if _, _, ok := s.Authenticate(token); ok {
			t.Errorf("%s token authenticated", name)
		}
	}
}

func TestStore_Expiry(t *testing.T) {
	s, c, _ := newStore(t)
	a, _ := s.Create(NewAccount{Name: "ci", Role: RoleAdmin})

	for name, expires := range map[string]time.Time{
		"in the past":  c.Now().Add(-time.Second),
		"now":          c.Now(),
		"over a year":  c.Now().Add(MaxKeyLifetime + time.Second),
		"zero":         {},
		"far too long": c.Now().Add(100 * 365 * day),
	} {
		if _, _, err := s.AddKey(a.ID, expires); !errors.Is(err, ErrInvalid) {
			t.Errorf("AddKey expiring %s: %v", name, err)
		}
	}

	_, secret, err := s.AddKey(a.ID, c.Now().Add(MaxKeyLifetime))
	if err != nil {
		t.Fatal(err)
	}
	c.Add(MaxKeyLifetime - time.Second)
	if _, _, ok := s.Authenticate(secret); !ok {
		t.Fatal("key refused a second before it expires")
	}
	c.Add(time.Second)
	if _, _, ok := s.Authenticate(secret); ok {
		t.Fatal("expired key authenticated")
	}
}

func TestStore_RotateWithGrace(t *testing.T) {
	s, c, _ := newStore(t)
	a, _ := s.Create(NewAccount{Name: "ci", Role: RoleAdmin})
	old, oldSecret, _ := s.AddKey(a.ID, c.Now().Add(90*day))

	k, secret, err := s.RotateKey(a.ID, old.ID, c.Now().Add(90*day), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if k.ID == old.ID || secret == oldSecret {
		t.Fatal("rotation reused the old key")
	}

	// During the grace period, both work; after it, only the new one.
	for _, sec := range []string{oldSecret, secret} {
		if _, _, ok := s.Authenticate(sec); !ok {
			t.Error("a key was refused during the grace period")
		}
	}
	c.Add(time.Hour)
	if _, _, ok := s.Authenticate(oldSecret); ok {
		t.Error("the old key still works after the grace period")
	}
	if _, _, ok := s.Authenticate(secret); !ok {
		t.Error("the new key was refused")
	}

	// Rotating an expired key is refused: there's nothing to hand over.
	if _, _, err := s.RotateKey(a.ID, old.ID, c.Now().Add(day), 0); !errors.Is(err, ErrInvalid) {
		t.Errorf("rotating an expired key: %v", err)
	}

	// A grace of zero revokes at once.
	_, third, err := s.RotateKey(a.ID, k.ID, c.Now().Add(day), 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, ok := s.Authenticate(secret); ok {
		t.Error("a key rotated without grace still works")
	}
	if _, _, ok := s.Authenticate(third); !ok {
		t.Error("the newest key was refused")
	}

	// Rotation never lengthens the old key's life.
	acct, _ := s.Account(a.ID)
	short, _, _ := s.AddKey(a.ID, c.Now().Add(time.Minute))
	if _, _, err := s.RotateKey(a.ID, short.ID, c.Now().Add(day), 2*time.Hour); err != nil {
		t.Fatal(err)
	}
	acct, _ = s.Account(a.ID)
	for _, kk := range acct.Keys {
		if kk.ID == short.ID && !kk.Expires.Equal(c.Now().Add(time.Minute)) {
			t.Errorf("rotation moved a key's expiry from %v to %v", c.Now().Add(time.Minute), kk.Expires)
		}
	}

	for name, grace := range map[string]time.Duration{"negative": -time.Second, "too long": MaxGrace + time.Second} {
		if _, _, err := s.RotateKey(a.ID, k.ID, c.Now().Add(day), grace); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s grace: %v", name, err)
		}
	}
	if _, _, err := s.RotateKey(a.ID, "0123456789abcdef", c.Now().Add(day), 0); !errors.Is(err, ErrNotFound) {
		t.Errorf("rotating an unknown key: %v", err)
	}
}

func TestStore_Revocation(t *testing.T) {
	s, c, _ := newStore(t)
	a, _ := s.Create(NewAccount{Name: "ci", Tenant: "smiths", Role: RoleAdmin})
	b, _ := s.Create(NewAccount{Name: "ha", Tenant: "smiths", Role: RoleReader})
	other, _ := s.Create(NewAccount{Name: "ha", Tenant: "joneses", Role: RoleReader})
	k1, s1, _ := s.AddKey(a.ID, c.Now().Add(day))
	_, s2, _ := s.AddKey(a.ID, c.Now().Add(day))
	_, s3, _ := s.AddKey(b.ID, c.Now().Add(day))
	_, s4, _ := s.AddKey(other.ID, c.Now().Add(day))

	if err := s.DeleteKey(a.ID, k1.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := s.Authenticate(s1); ok {
		t.Error("a deleted key still works")
	}
	if _, _, ok := s.Authenticate(s2); !ok {
		t.Error("deleting one key revoked another")
	}
	if err := s.DeleteKey(a.ID, k1.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("deleting a key twice: %v", err)
	}
	// A key can only be deleted through its own account.
	k3 := mustAccount(t, s, b.ID).Keys[0]
	if err := s.DeleteKey(a.ID, k3.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("deleting another account's key: %v", err)
	}

	if err := s.Delete(a.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := s.Authenticate(s2); ok {
		t.Error("a deleted account's key still works")
	}
	if err := s.Delete(a.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("deleting an account twice: %v", err)
	}

	if n, err := s.DeleteTenant("smiths"); err != nil || n != 1 {
		t.Fatalf("DeleteTenant = %d, %v", n, err)
	}
	if _, _, ok := s.Authenticate(s3); ok {
		t.Error("a deleted tenant's key still works")
	}
	if _, _, ok := s.Authenticate(s4); !ok {
		t.Error("deleting one tenant revoked another's keys")
	}
	if _, err := s.DeleteTenant(""); !errors.Is(err, ErrInvalid) {
		t.Error("DeleteTenant accepted the operator")
	}
}

func mustAccount(t *testing.T, s *Store, id string) Account {
	t.Helper()
	a, ok := s.Account(id)
	if !ok {
		t.Fatalf("no account %s", id)
	}
	return a
}

func TestStore_Limits(t *testing.T) {
	s, c, _ := newStore(t)
	for name, n := range map[string]NewAccount{
		"no name":      {Role: RoleAdmin},
		"blank name":   {Name: "  ", Role: RoleAdmin},
		"long name":    {Name: strings.Repeat("a", 65), Role: RoleAdmin},
		"control char": {Name: "a\nb", Role: RoleAdmin},
		"no role":      {Name: "x"},
		"bad role":     {Name: "x", Role: "owner"},
	} {
		if _, err := s.Create(n); !errors.Is(err, ErrInvalid) {
			t.Errorf("Create with %s: %v", name, err)
		}
	}

	for range MaxTenantAccounts {
		if _, err := s.Create(NewAccount{Name: "x", Tenant: "big", Role: RoleReader}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.Create(NewAccount{Name: "x", Tenant: "big", Role: RoleReader}); !errors.Is(err, ErrLimit) {
		t.Errorf("a tenant exceeded its account limit: %v", err)
	}
	if _, err := s.Create(NewAccount{Name: "x", Tenant: "small", Role: RoleReader}); err != nil {
		t.Errorf("one tenant's limit blocked another: %v", err)
	}

	a, _ := s.Create(NewAccount{Name: "keys", Role: RoleAdmin})
	for range MaxKeys {
		if _, _, err := s.AddKey(a.ID, c.Now().Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := s.AddKey(a.ID, c.Now().Add(time.Hour)); !errors.Is(err, ErrLimit) {
		t.Errorf("added more than %d keys: %v", MaxKeys, err)
	}
	// Expired keys make room.
	c.Add(time.Hour)
	if _, _, err := s.AddKey(a.ID, c.Now().Add(time.Hour)); err != nil {
		t.Errorf("expired keys didn't make room: %v", err)
	}
	if n := len(mustAccount(t, s, a.ID).Keys); n != 1 {
		t.Errorf("%d keys after expired ones were cleared, want 1", n)
	}

	if _, _, err := s.AddKey("nope", c.Now().Add(time.Hour)); !errors.Is(err, ErrNotFound) {
		t.Errorf("AddKey to an unknown account: %v", err)
	}
}

func TestStore_Persistence(t *testing.T) {
	s, c, path := newStore(t)
	a, _ := s.Create(NewAccount{Name: "Home Assistant", Tenant: "smiths", Role: RoleReader, CreatedBy: "kent"})
	_, secret, _ := s.AddKey(a.ID, c.Now().Add(day))

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), secret) || strings.Contains(string(b), secret[len(SecretPrefix)+keyIDLen+1:]) {
		t.Fatal("the store holds a key's secret, not only its digest")
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Errorf("store mode = %v, want 0600", fi.Mode().Perm())
	}

	reopened, err := Open(path, WithClock(c.Now))
	if err != nil {
		t.Fatal(err)
	}
	got, _, ok := reopened.Authenticate(secret)
	if !ok || got.Name != "Home Assistant" || got.Tenant != "smiths" || got.CreatedBy != "kent" {
		t.Fatalf("after reopening: %+v, %v", got, ok)
	}

	for name, content := range map[string]string{
		"unknown field": `{"version":1,"accounts":[],"extra":true}`,
		"version":       `{"version":2,"accounts":[]}`,
		"bad role":      `{"version":1,"accounts":[{"id":"a","name":"x","role":"owner","created":"2026-01-01T00:00:00Z","keys":[]}]}`,
		"short digest":  `{"version":1,"accounts":[{"id":"a","name":"x","role":"admin","created":"2026-01-01T00:00:00Z","keys":[{"id":"0123456789abcdef","digest":"AAAA","created":"2026-01-01T00:00:00Z","expires":"2027-01-01T00:00:00Z"}]}]}`,
		"not JSON":      `{`,
	} {
		bad := filepath.Join(t.TempDir(), "sa.json")
		if err := os.WriteFile(bad, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Open(bad); err == nil {
			t.Errorf("opened a store with %s", name)
		}
	}
}

func TestStore_LastUsedWritesSparingly(t *testing.T) {
	s, c, path := newStore(t)
	a, _ := s.Create(NewAccount{Name: "ci", Role: RoleAdmin})
	_, secret, _ := s.AddKey(a.ID, c.Now().Add(day))

	s.Authenticate(secret)
	before, _ := os.Stat(path)
	c.Add(time.Minute)
	_, k, _ := s.Authenticate(secret)
	if !k.LastUsed.Equal(c.Now()) {
		t.Errorf("LastUsed = %v, want the latest use %v", k.LastUsed, c.Now())
	}
	after, _ := os.Stat(path)
	if !after.ModTime().Equal(before.ModTime()) || after.Size() != before.Size() {
		t.Error("authenticating within the hour rewrote the store")
	}
}

func TestStore_ViewsHideDigests(t *testing.T) {
	s, c, _ := newStore(t)
	a, _ := s.Create(NewAccount{Name: "ci", Role: RoleAdmin})
	k, secret, _ := s.AddKey(a.ID, c.Now().Add(day))
	_, ak, _ := s.Authenticate(secret)
	for _, key := range append(mustAccount(t, s, a.ID).Keys, k, ak) {
		if key.digest != [32]byte{} {
			t.Errorf("key %s is returned with its digest", key.ID)
		}
	}
}

func TestStore_InMemory(t *testing.T) {
	s, err := Open("")
	if err != nil {
		t.Fatal(err)
	}
	a, err := s.Create(NewAccount{Name: "ci", Role: RoleAdmin})
	if err != nil {
		t.Fatal(err)
	}
	if _, secret, err := s.AddKey(a.ID, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	} else if _, _, ok := s.Authenticate(secret); !ok {
		t.Error("in-memory key refused")
	}
}

func TestStore_SaveFailureChangesNothing(t *testing.T) {
	s, c, path := newStore(t)
	a, _ := s.Create(NewAccount{Name: "ci", Role: RoleAdmin})
	_, secret, _ := s.AddKey(a.ID, c.Now().Add(day))

	// Make saving fail: the store's path becomes a non-empty directory.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(path, "x"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.AddKey(a.ID, c.Now().Add(day)); err == nil {
		t.Fatal("AddKey succeeded without saving")
	}
	if err := s.Delete(a.ID); err == nil {
		t.Fatal("Delete succeeded without saving")
	}
	if n := len(mustAccount(t, s, a.ID).Keys); n != 1 {
		t.Errorf("%d keys after failed saves, want 1", n)
	}
	if _, _, ok := s.Authenticate(secret); !ok {
		t.Error("a failed Delete revoked the account's key anyway")
	}
}
