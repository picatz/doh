// Package signin signs people in to the doh web UI, with single-use
// sign-in links and passkeys, and keeps their browser sessions.
//
// Browsers never hold an API token. An operator who has one (such as the
// admin token "doh serve" generates) creates a sign-in link with
// [Service.NewLink], which "doh ui" prints; opening it exchanges the
// link's single-use code for a session cookie. Signed in, they can add
// passkeys ([WebAuthn]), which then sign them in directly.
//
// Once anyone has a passkey, links become a first factor only: a link
// leads to a pending session that a passkey must complete, so stealing a
// link, or the token that makes them, isn't enough to sign in. Passkeys are
// a sign-in on their own, since they require user verification (a
// biometric or PIN) as well as the device.
//
// Sessions are kept in memory, as hashes of their cookies, and end after
// [Config.IdleTimeout] without use or [Config.Lifetime] at most. People and
// their passkeys are persisted to [Config.Path].
//
// [WebAuthn]: https://www.w3.org/TR/webauthn-3/
package signin

import (
	"cmp"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/picatz/doh/internal/webauthn"
)

// Role is what a signed-in person may do.
type Role string

// Roles.
const (
	RoleAdmin  Role = "admin"  // everything
	RoleReader Role = "reader" // read-only
)

// Allows reports whether r includes the permissions of other.
func (r Role) Allows(other Role) bool {
	return r == RoleAdmin || r == other
}

func (r Role) valid() bool { return r == RoleAdmin || r == RoleReader }

// Defaults for [Config].
const (
	DefaultIdleTimeout = 2 * time.Hour
	DefaultLifetime    = 12 * time.Hour
	DefaultLinkTTL     = 5 * time.Minute

	maxSessions        = 1_000 // complete sessions
	maxPendingSessions = 200   // sessions still signing in
	maxLinks           = 100
	maxPeople          = 100
	maxPasskeys        = 20 // per person
)

// Config configures a [Service].
type Config struct {
	// Origins are the web origins the UI is served at, such as
	// "http://localhost:9090" or "https://admin.dns.example.com". The
	// first's host is the WebAuthn relying party ID, so all must share it.
	// Passkeys need a host name, not an IP address, and HTTPS or
	// localhost.
	Origins []string

	// Name is shown by browsers when creating passkeys. It defaults to
	// "doh".
	Name string

	// Path persists people and passkeys as JSON. Empty keeps them in
	// memory.
	Path string

	// IdleTimeout ends sessions unused for this long, and Lifetime ends
	// them this long after sign-in, whatever their use. They default to
	// DefaultIdleTimeout and DefaultLifetime.
	IdleTimeout, Lifetime time.Duration

	// Logger records sign-ins and changes. Nil discards them.
	Logger *slog.Logger

	// Now returns the current time. Nil means time.Now.
	Now func() time.Time
}

// Person is someone who can sign in with passkeys.
type Person struct {
	// ID identifies the person: their WebAuthn user handle, base64url
	// encoded.
	ID string `json:"id"`

	// Name is how they're shown, such as "Kent".
	Name string `json:"name"`

	// Role is what they may do.
	Role Role `json:"role"`

	// Created is when they were added.
	Created time.Time `json:"created"`

	// Passkeys are their credentials.
	Passkeys []Passkey `json:"passkeys"`
}

// Passkey is a credential a person signs in with.
type Passkey struct {
	// ID is the credential ID, base64url encoded.
	ID string `json:"id"`

	// Name describes it, such as "MacBook".
	Name string `json:"name"`

	// Created and LastUsed are when it was added and last signed in with.
	Created  time.Time `json:"created"`
	LastUsed time.Time `json:"last_used,omitzero"`

	// Synced reports whether it's a multi-device passkey that was last
	// reported backed up, such as to iCloud Keychain or Google Password
	// Manager.
	Synced bool `json:"synced"`

	// Credential is the WebAuthn credential record. [Service.People]
	// leaves it out.
	Credential webauthn.Credential `json:"credential,omitzero"`
}

// Session is a browser's signed-in session.
type Session struct {
	// Person is the signed-in person's ID, empty for a link sign-in
	// without a passkey.
	Person string `json:"person,omitempty"`

	// Name is the person's name, or "Sign-in link".
	Name string `json:"name"`

	// Role is what the session may do.
	Role Role `json:"role"`

	// Method is how the session signed in: "link", "passkey", or
	// "link+passkey".
	Method string `json:"method"`

	// Pending reports a link sign-in that still needs a passkey.
	Pending bool `json:"pending,omitempty"`

	// Created and Expires bound the session's life.
	Created time.Time `json:"created"`
	Expires time.Time `json:"expires"`

	lastSeen time.Time
	binding  string // WebAuthn ceremony binding: the session's own secret
}

// Service signs people in and keeps their sessions. It's safe for
// concurrent use.
type Service struct {
	config  Config
	rp      *webauthn.RelyingParty
	rpID    string
	secure  bool // whether every origin is HTTPS, for __Host- cookies
	logger  *slog.Logger
	now     func() time.Time
	persist bool

	mu          sync.Mutex
	people      []Person
	sessions    map[[sha256.Size]byte]*Session
	links       map[[sha256.Size]byte]link
	enrollments map[string]enrollment // by ceremony ID
}

type link struct {
	role    Role
	expires time.Time
}

// New returns a service for config, loading any persisted people.
func New(config Config) (*Service, error) {
	if len(config.Origins) == 0 {
		return nil, errors.New("signin: no origins")
	}

	var rpID string
	secure := true
	for _, o := range config.Origins {
		u, err := url.Parse(o)
		if err != nil || u.Host == "" || u.Path != "" || (u.Scheme != "https" && u.Scheme != "http") {
			return nil, fmt.Errorf("signin: origin %q must be a scheme and host, such as https://admin.example.com", o)
		}
		host := u.Hostname()
		if rpID == "" {
			rpID = host
		} else if host != rpID {
			return nil, fmt.Errorf("signin: origin %q must have the host %q, like the first origin", o, rpID)
		}
		secure = secure && u.Scheme == "https"
	}

	config.Name = cmp.Or(config.Name, "doh")
	config.IdleTimeout = cmp.Or(config.IdleTimeout, DefaultIdleTimeout)
	config.Lifetime = cmp.Or(config.Lifetime, DefaultLifetime)

	s := &Service{
		config:   config,
		rpID:     rpID,
		secure:   secure,
		logger:   cmp.Or(config.Logger, slog.New(slog.DiscardHandler)),
		now:      config.Now,
		persist:  config.Path != "",
		sessions: make(map[[sha256.Size]byte]*Session),
		links:    make(map[[sha256.Size]byte]link),

		enrollments: make(map[string]enrollment),
	}
	if s.now == nil {
		s.now = time.Now
	}

	store, err := webauthn.NewMemoryChallengeStore(1_000)
	if err != nil {
		return nil, err
	}
	store.Now = s.now
	s.rp, err = webauthn.New(webauthn.Config{
		ID:      rpID,
		Name:    config.Name,
		Origins: config.Origins,
		Store:   store,
		Clock:   s.now,
	})
	if err != nil {
		return nil, fmt.Errorf("signin: %w (passkeys need a host name, such as localhost, not an IP address)", err)
	}

	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

// RPID returns the WebAuthn relying party ID passkeys are created for.
func (s *Service) RPID() string { return s.rpID }

// HasPasskeys reports whether anyone has a passkey, which makes passkeys
// required to complete link sign-ins.
func (s *Service) HasPasskeys() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.hasPasskeys()
}

func (s *Service) hasPasskeys() bool {
	return slices.ContainsFunc(s.people, func(p Person) bool { return len(p.Passkeys) > 0 })
}

// People returns everyone who can sign in with passkeys, without their
// credential records.
func (s *Service) People() []Person {
	s.mu.Lock()
	defer s.mu.Unlock()

	people := make([]Person, len(s.people))
	for i, p := range s.people {
		p.Passkeys = slices.Clone(p.Passkeys)
		for j := range p.Passkeys {
			p.Passkeys[j].Credential = webauthn.Credential{}
		}
		people[i] = p
	}
	return people
}

// ErrNotFound reports a person or passkey that doesn't exist.
var ErrNotFound = errors.New("signin: not found")

// DeletePerson removes a person and their passkeys, and ends their
// sessions.
func (s *Service) DeletePerson(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	i := slices.IndexFunc(s.people, func(p Person) bool { return p.ID == id })
	if i < 0 {
		return ErrNotFound
	}
	people := slices.Delete(slices.Clone(s.people), i, i+1)
	if err := s.save(people); err != nil {
		return err
	}
	s.people = people
	s.endSessions(id)
	s.logger.Info("signin: removed person", slog.String("person", id))
	return nil
}

// DeletePasskey removes one of a person's passkeys.
func (s *Service) DeletePasskey(person, passkey string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	i := slices.IndexFunc(s.people, func(p Person) bool { return p.ID == person })
	if i < 0 {
		return ErrNotFound
	}
	people := slices.Clone(s.people)
	p := &people[i]
	j := slices.IndexFunc(p.Passkeys, func(k Passkey) bool { return k.ID == passkey })
	if j < 0 {
		return ErrNotFound
	}
	p.Passkeys = slices.Delete(slices.Clone(p.Passkeys), j, j+1)
	if err := s.save(people); err != nil {
		return err
	}
	s.people = people
	s.logger.Info("signin: removed passkey", slog.String("person", person), slog.String("passkey", passkey))
	return nil
}

// NewLink creates a single-use sign-in code granting role, valid for
// [DefaultLinkTTL]. The caller must already be authorized for role, such
// as by an API token.
func (s *Service) NewLink(role Role) (code string, expires time.Time, err error) {
	if !role.valid() {
		return "", time.Time{}, fmt.Errorf("signin: invalid role %q", role)
	}

	code, err = randomToken()
	if err != nil {
		return "", time.Time{}, err
	}
	now := s.now()
	expires = now.Add(DefaultLinkTTL)

	s.mu.Lock()
	defer s.mu.Unlock()

	for k, l := range s.links {
		if !now.Before(l.expires) {
			delete(s.links, k)
		}
	}
	if len(s.links) >= maxLinks {
		return "", time.Time{}, errors.New("signin: too many outstanding sign-in links; wait a few minutes")
	}
	s.links[sha256.Sum256([]byte(code))] = link{role: role, expires: expires}
	return code, expires, nil
}

// randomToken returns 32 random bytes, base64url encoded.
func randomToken() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

// peopleFile is the persisted form of people.
type peopleFile struct {
	Version int      `json:"version"`
	People  []Person `json:"people"`
}

// load reads persisted people, if any.
func (s *Service) load() error {
	if !s.persist {
		return nil
	}
	b, err := os.ReadFile(s.config.Path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("signin: %w", err)
	}

	var f peopleFile
	if err := json.Unmarshal(b, &f, json.RejectUnknownMembers(true)); err != nil {
		return fmt.Errorf("signin: reading %s: %w", s.config.Path, err)
	}
	if f.Version != 1 {
		return fmt.Errorf("signin: %s has unsupported version %d", s.config.Path, f.Version)
	}
	for _, p := range f.People {
		if !p.Role.valid() {
			return fmt.Errorf("signin: %s: person %q has invalid role %q", s.config.Path, p.ID, p.Role)
		}
	}
	s.people = f.People
	return nil
}

// save persists people atomically, readable only by its owner. s.mu must
// be held. On error, nothing changes on disk.
func (s *Service) save(people []Person) error {
	if !s.persist {
		return nil
	}
	b, err := json.Marshal(peopleFile{Version: 1, People: people}, json.Deterministic(true))
	if err != nil {
		return err
	}

	dir := filepath.Dir(s.config.Path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("signin: %w", err)
	}
	f, err := os.CreateTemp(dir, "."+filepath.Base(s.config.Path)+".*.tmp")
	if err != nil {
		return fmt.Errorf("signin: %w", err)
	}
	tmp := f.Name()
	_, err = f.Write(b)
	if err == nil {
		err = f.Chmod(0o600)
	}
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, s.config.Path)
	}
	if err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("signin: saving %s: %w", s.config.Path, err)
	}
	return nil
}

// validName trims a display name and reports whether it's acceptable: 1
// to 64 printable characters.
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
