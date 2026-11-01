// Package serviceaccount keeps the identities automation uses with the
// admin API: scripts, home automation, CI jobs, and other servers.
//
// A service account belongs to one tenant, or to the server's operator,
// and has a role, as a person does. It authenticates with keys: random
// secrets that always expire, are stored only as SHA-256 digests, and are
// shown once, when they're made.
//
// Keys rotate without downtime: [Store.RotateKey] adds a new key and lets
// the old one keep working for a grace period, so automation can switch
// over before it stops. Removing a key, or its account, revokes it at
// once.
package serviceaccount

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/picatz/doh/internal/atomicfile"
)

// Role is what a service account may do.
type Role string

// Roles.
const (
	RoleAdmin  Role = "admin"  // read and change
	RoleReader Role = "reader" // read only
)

// Valid reports whether r is a known role.
func (r Role) Valid() bool { return r == RoleAdmin || r == RoleReader }

// Limits.
const (
	// MaxAccounts bounds the service accounts on a server, and
	// MaxTenantAccounts those of one tenant.
	MaxAccounts       = 1000
	MaxTenantAccounts = 50

	// MaxKeys bounds an account's keys, so rotating with a grace period
	// always has room.
	MaxKeys = 5

	// MaxKeyLifetime bounds how long a key may live. Keys that must last
	// longer are rotated.
	MaxKeyLifetime = 366 * 24 * time.Hour

	// MaxGrace bounds how long a rotated key keeps working.
	MaxGrace = 7 * 24 * time.Hour

	// lastUsedPrecision is how stale a persisted last-used time may get,
	// so authenticating doesn't write to disk on every request.
	lastUsedPrecision = time.Hour
)

// SecretPrefix begins every key's secret, so a leaked one is easy to
// recognize and to scan for.
const SecretPrefix = "doh_sa_"

// Errors.
var (
	ErrNotFound = errors.New("not found")
	ErrInvalid  = errors.New("invalid")
	ErrLimit    = errors.New("limit reached")
)

// Account is a service account.
type Account struct {
	// ID identifies the account. It's generated, and safe to show.
	ID string `json:"id"`

	// Name says what the account is for, such as "Home Assistant".
	Name string `json:"name"`

	// Tenant is the tenant it acts for, or empty for the server's
	// operator.
	Tenant string `json:"tenant,omitempty"`

	// Role is what it may do.
	Role Role `json:"role"`

	// Created is when it was made, and CreatedBy who made it.
	Created   time.Time `json:"created"`
	CreatedBy string    `json:"created_by,omitempty"`

	// Keys are its keys, without their secrets.
	Keys []Key `json:"keys"`
}

// Key is a service account's credential.
type Key struct {
	// ID identifies the key. It's part of the secret, and safe to show.
	ID string `json:"id"`

	// Created, Expires, and LastUsed are when the key was made, when it
	// stops working, and roughly when it last authenticated.
	Created  time.Time `json:"created"`
	Expires  time.Time `json:"expires"`
	LastUsed time.Time `json:"last_used,omitzero"`

	digest [sha256.Size]byte
}

// Expired reports whether k no longer works at now.
func (k Key) Expired(now time.Time) bool { return !now.Before(k.Expires) }

// NewAccount describes a service account to create.
type NewAccount struct {
	Name      string
	Tenant    string
	Role      Role
	CreatedBy string
}

// Store keeps service accounts, persisted to a file. It's safe for
// concurrent use.
type Store struct {
	path string
	now  func() time.Time

	mu       sync.Mutex
	accounts []*Account
	keys     map[string]*Account // by key ID
	used     map[string]time.Time
}

// Option configures a [Store].
type Option func(*Store)

// WithClock sets the store's clock, for tests.
func WithClock(now func() time.Time) Option {
	return func(s *Store) { s.now = now }
}

// Open opens the store persisted at path, which needn't exist yet. With an
// empty path, the store is kept only in memory.
func Open(path string, opts ...Option) (*Store, error) {
	s := &Store{path: path, now: time.Now, keys: make(map[string]*Account), used: make(map[string]time.Time)}
	for _, opt := range opts {
		opt(s)
	}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

// Accounts returns every account, oldest first.
func (s *Store) Accounts() []Account {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Account, len(s.accounts))
	for i, a := range s.accounts {
		out[i] = s.view(a)
	}
	return out
}

// Account returns the account with id.
func (s *Store) Account(id string) (Account, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a := s.find(id)
	if a == nil {
		return Account{}, false
	}
	return s.view(a), true
}

// Create adds a service account, without keys.
func (s *Store) Create(n NewAccount) (Account, error) {
	name, ok := validName(n.Name)
	if !ok {
		return Account{}, fmt.Errorf("%w: name it with 1 to 64 printable characters", ErrInvalid)
	}
	if !n.Role.Valid() {
		return Account{}, fmt.Errorf("%w: role must be %s or %s", ErrInvalid, RoleAdmin, RoleReader)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.accounts) >= MaxAccounts {
		return Account{}, fmt.Errorf("%w: at most %d service accounts", ErrLimit, MaxAccounts)
	}
	if n.Tenant != "" {
		count := 0
		for _, a := range s.accounts {
			if a.Tenant == n.Tenant {
				count++
			}
		}
		if count >= MaxTenantAccounts {
			return Account{}, fmt.Errorf("%w: at most %d service accounts per tenant", ErrLimit, MaxTenantAccounts)
		}
	}

	id, err := newAccountID()
	if err != nil {
		return Account{}, err
	}
	a := &Account{ID: id, Name: name, Tenant: n.Tenant, Role: n.Role, Created: s.now().UTC(), CreatedBy: n.CreatedBy, Keys: []Key{}}
	if err := s.commit(func() { s.accounts = append(s.accounts, a) }, func() { s.accounts = s.accounts[:len(s.accounts)-1] }); err != nil {
		return Account{}, err
	}
	return s.view(a), nil
}

// Delete removes the account with id, revoking its keys.
func (s *Store) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	i := slices.IndexFunc(s.accounts, func(a *Account) bool { return a.ID == id })
	if i < 0 {
		return fmt.Errorf("service account %q: %w", id, ErrNotFound)
	}
	return s.remove(func(a *Account) bool { return a.ID == id })
}

// DeleteTenant removes every account of tenant, revoking their keys, and
// returns how many there were.
func (s *Store) DeleteTenant(tenant string) (int, error) {
	if tenant == "" {
		return 0, fmt.Errorf("%w: no tenant", ErrInvalid)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, a := range s.accounts {
		if a.Tenant == tenant {
			n++
		}
	}
	if n == 0 {
		return 0, nil
	}
	return n, s.remove(func(a *Account) bool { return a.Tenant == tenant })
}

// remove deletes the accounts drop reports true for, persisting the
// change. s.mu must be held.
func (s *Store) remove(drop func(*Account) bool) error {
	before := slices.Clone(s.accounts)
	return s.commit(func() {
		s.accounts = slices.DeleteFunc(s.accounts, drop)
		s.reindex()
	}, func() {
		s.accounts = before
		s.reindex()
	})
}

// AddKey adds a key to an account, expiring at expires, and returns it
// with its secret, which isn't kept.
func (s *Store) AddKey(account string, expires time.Time) (Key, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a := s.find(account)
	if a == nil {
		return Key{}, "", fmt.Errorf("service account %q: %w", account, ErrNotFound)
	}
	return s.addKey(a, expires, nil)
}

// RotateKey replaces a key: it adds a new key expiring at expires, and
// shortens the old key's life to grace from now, so whoever uses it can
// switch to the new one. A grace of zero revokes the old key at once.
func (s *Store) RotateKey(account, key string, expires time.Time, grace time.Duration) (Key, string, error) {
	if grace < 0 || grace > MaxGrace {
		return Key{}, "", fmt.Errorf("%w: the grace period is 0 to %v", ErrInvalid, MaxGrace)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	a := s.find(account)
	if a == nil {
		return Key{}, "", fmt.Errorf("service account %q: %w", account, ErrNotFound)
	}
	i := slices.IndexFunc(a.Keys, func(k Key) bool { return k.ID == key })
	if i < 0 {
		return Key{}, "", fmt.Errorf("key %q: %w", key, ErrNotFound)
	}
	now := s.now()
	if a.Keys[i].Expired(now) {
		return Key{}, "", fmt.Errorf("%w: key %q has expired; add a new key instead", ErrInvalid, key)
	}

	retire := func(keys []Key) {
		j := slices.IndexFunc(keys, func(k Key) bool { return k.ID == key })
		if until := now.Add(grace).UTC(); until.Before(keys[j].Expires) {
			keys[j].Expires = until
		}
	}
	return s.addKey(a, expires, retire)
}

// addKey adds a key to a, after applying also to its keys, persisting
// both or neither. s.mu must be held.
func (s *Store) addKey(a *Account, expires time.Time, also func([]Key)) (Key, string, error) {
	now := s.now()
	switch {
	case !expires.After(now):
		return Key{}, "", fmt.Errorf("%w: a key must expire in the future", ErrInvalid)
	case expires.Sub(now) > MaxKeyLifetime:
		return Key{}, "", fmt.Errorf("%w: a key may last at most %d days; rotate it to keep going", ErrInvalid, int(MaxKeyLifetime.Hours()/24))
	}

	// Expired keys make room for new ones.
	keys := slices.DeleteFunc(slices.Clone(a.Keys), func(k Key) bool { return k.Expired(now) })
	if len(keys) >= MaxKeys {
		return Key{}, "", fmt.Errorf("%w: at most %d keys per service account; remove one first", ErrLimit, MaxKeys)
	}

	id, secret, err := newSecret()
	if err != nil {
		return Key{}, "", err
	}
	k := Key{ID: id, Created: now.UTC(), Expires: expires.UTC(), digest: sha256.Sum256([]byte(secret))}
	keys = append(keys, k)
	if also != nil {
		also(keys)
	}

	before := a.Keys
	if err := s.commit(func() { a.Keys = keys; s.reindex() }, func() { a.Keys = before; s.reindex() }); err != nil {
		return Key{}, "", err
	}
	k.digest = [sha256.Size]byte{}
	return k, secret, nil
}

// DeleteKey revokes a key at once.
func (s *Store) DeleteKey(account, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	a := s.find(account)
	if a == nil {
		return fmt.Errorf("service account %q: %w", account, ErrNotFound)
	}
	i := slices.IndexFunc(a.Keys, func(k Key) bool { return k.ID == key })
	if i < 0 {
		return fmt.Errorf("key %q: %w", key, ErrNotFound)
	}
	before := a.Keys
	keys := slices.Delete(slices.Clone(a.Keys), i, i+1)
	return s.commit(func() { a.Keys = keys; s.reindex() }, func() { a.Keys = before; s.reindex() })
}

// Authenticate returns the account and key a secret belongs to, if the
// key exists and hasn't expired.
//
// The key's ID, in the secret, finds the key, and the secret's digest is
// compared in constant time. Key IDs aren't secret, so how long a failure
// takes may reveal whether a key exists, never anything about its secret.
func (s *Store) Authenticate(secret string) (Account, Key, bool) {
	id, ok := keyID(secret)
	if !ok {
		return Account{}, Key{}, false
	}
	sum := sha256.Sum256([]byte(secret))
	now := s.now()

	s.mu.Lock()
	defer s.mu.Unlock()
	a := s.keys[id]
	if a == nil {
		return Account{}, Key{}, false
	}
	i := slices.IndexFunc(a.Keys, func(k Key) bool { return k.ID == id })
	k := &a.Keys[i]
	if subtle.ConstantTimeCompare(sum[:], k.digest[:]) != 1 || k.Expired(now) {
		return Account{}, Key{}, false
	}

	// Remember when the key was used: exactly in memory, and on disk when
	// what's there is more than lastUsedPrecision old. A failure to save
	// it doesn't refuse a valid key.
	s.used[id] = now.UTC()
	if now.Sub(k.LastUsed) >= lastUsedPrecision {
		previous := k.LastUsed
		_ = s.commit(func() { k.LastUsed = now.UTC() }, func() { k.LastUsed = previous })
	}
	view := s.view(a)
	return view, view.Keys[i], true
}

// find returns the account with id. s.mu must be held.
func (s *Store) find(id string) *Account {
	i := slices.IndexFunc(s.accounts, func(a *Account) bool { return a.ID == id })
	if i < 0 {
		return nil
	}
	return s.accounts[i]
}

// view copies a for callers, with keys' most recent use. s.mu must be
// held.
func (s *Store) view(a *Account) Account {
	v := *a
	v.Keys = slices.Clone(a.Keys)
	for i, k := range v.Keys {
		if t, ok := s.used[k.ID]; ok && t.After(k.LastUsed) {
			v.Keys[i].LastUsed = t
		}
		v.Keys[i].digest = [sha256.Size]byte{}
	}
	return v
}

// reindex rebuilds the index of keys. s.mu must be held.
func (s *Store) reindex() {
	clear(s.keys)
	for _, a := range s.accounts {
		for _, k := range a.Keys {
			s.keys[k.ID] = a
		}
	}
}

// commit applies change and persists the result, undoing the change if
// it can't be saved. s.mu must be held.
func (s *Store) commit(change, undo func()) error {
	change()
	if err := s.save(); err != nil {
		undo()
		return err
	}
	return nil
}

// newAccountID returns a random account ID: 16 lower-case base32
// characters, 80 bits.
func newAccountID() (string, error) {
	var b [10]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return strings.ToLower(base32.StdEncoding.EncodeToString(b[:])), nil
}

// keyIDLen is the length of a key ID: 16 hex characters, 64 bits.
const keyIDLen = 16

// newSecret returns a new key's ID and secret: the prefix, the ID, an
// underscore, and 256 random bits, base64url encoded.
func newSecret() (id, secret string, err error) {
	var b [8 + 32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", "", err
	}
	id = hex.EncodeToString(b[:8])
	return id, SecretPrefix + id + "_" + base64.RawURLEncoding.EncodeToString(b[8:]), nil
}

// keyID returns the key ID in secret, if it looks like a key's secret.
func keyID(secret string) (string, bool) {
	rest, ok := strings.CutPrefix(secret, SecretPrefix)
	if !ok || len(rest) != keyIDLen+1+43 || rest[keyIDLen] != '_' {
		return "", false
	}
	id := rest[:keyIDLen]
	if _, err := hex.DecodeString(id); err != nil || strings.ToLower(id) != id {
		return "", false
	}
	return id, true
}

// IsSecret reports whether token looks like a service account key's
// secret, as opposed to another kind of credential.
func IsSecret(token string) bool { return strings.HasPrefix(token, SecretPrefix) }

// validName trims a name and reports whether it's 1 to 64 printable
// characters.
func validName(name string) (string, bool) {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 64 {
		return "", false
	}
	for _, r := range name {
		if r < ' ' || r == 0x7f {
			return "", false
		}
	}
	return name, true
}

// file is the persisted form of the store.
type file struct {
	Version  int           `json:"version"`
	Accounts []fileAccount `json:"accounts"`
}

type fileAccount struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Tenant    string    `json:"tenant,omitempty"`
	Role      Role      `json:"role"`
	Created   time.Time `json:"created"`
	CreatedBy string    `json:"created_by,omitempty"`
	Keys      []fileKey `json:"keys"`
}

type fileKey struct {
	ID       string    `json:"id"`
	Digest   []byte    `json:"digest"` // SHA-256 of the secret
	Created  time.Time `json:"created"`
	Expires  time.Time `json:"expires"`
	LastUsed time.Time `json:"last_used,omitzero"`
}

// load reads the persisted store, if there is one.
func (s *Store) load() error {
	if s.path == "" {
		return nil
	}
	b, err := os.ReadFile(s.path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("serviceaccount: %w", err)
	}

	var f file
	if err := json.Unmarshal(b, &f, json.RejectUnknownMembers(true)); err != nil {
		return fmt.Errorf("serviceaccount: reading %s: %w", s.path, err)
	}
	if f.Version != 1 {
		return fmt.Errorf("serviceaccount: %s has unsupported version %d", s.path, f.Version)
	}
	seen := make(map[string]bool)
	for _, fa := range f.Accounts {
		a := Account{ID: fa.ID, Name: fa.Name, Tenant: fa.Tenant, Role: fa.Role, Created: fa.Created, CreatedBy: fa.CreatedBy}
		if !a.Role.Valid() || a.ID == "" || s.find(a.ID) != nil {
			return fmt.Errorf("serviceaccount: %s: invalid account %q", s.path, a.ID)
		}
		a.Keys = make([]Key, 0, len(fa.Keys))
		for _, fk := range fa.Keys {
			k := Key{ID: fk.ID, Created: fk.Created, Expires: fk.Expires, LastUsed: fk.LastUsed}
			if len(fk.Digest) != sha256.Size || len(k.ID) != keyIDLen || seen[k.ID] {
				return fmt.Errorf("serviceaccount: %s: invalid key %q", s.path, k.ID)
			}
			k.digest = [sha256.Size]byte(fk.Digest)
			a.Keys = append(a.Keys, k)
			seen[k.ID] = true
		}
		s.accounts = append(s.accounts, &a)
	}
	s.reindex()
	return nil
}

// save persists the store atomically, readable only by its owner. s.mu
// must be held.
func (s *Store) save() error {
	if s.path == "" {
		return nil
	}
	f := file{Version: 1, Accounts: make([]fileAccount, len(s.accounts))}
	for i, a := range s.accounts {
		fa := fileAccount{ID: a.ID, Name: a.Name, Tenant: a.Tenant, Role: a.Role, Created: a.Created, CreatedBy: a.CreatedBy, Keys: make([]fileKey, len(a.Keys))}
		for j, k := range a.Keys {
			fa.Keys[j] = fileKey{ID: k.ID, Digest: k.digest[:], Created: k.Created, Expires: k.Expires, LastUsed: k.LastUsed}
		}
		f.Accounts[i] = fa
	}
	b, err := json.Marshal(f, json.Deterministic(true))
	if err != nil {
		return err
	}
	if err := atomicfile.WriteFile(s.path, b, 0o600); err != nil {
		return fmt.Errorf("serviceaccount: saving %s: %w", s.path, err)
	}
	return nil
}
