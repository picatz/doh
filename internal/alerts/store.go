package alerts

import (
	"context"
	"crypto/subtle"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/picatz/doh/internal/atomicfile"
	"github.com/picatz/doh/internal/webpush"
)

// fileVersion is the version of the persisted store.
const fileVersion = 1

// store keeps each scope's settings and destinations, persisted to a
// file, and its recent deliveries, in memory. It's safe for concurrent
// use. The devices each scope has seen are a [Memory]'s; files from
// before kept them too, and [openStore] returns them to import.
type store struct {
	path string

	mu     sync.Mutex
	scopes map[string]*scopeData
	dirty  bool // changed since saved, by deliveries

	// legacyDevices are the devices an older file kept, by scope, until
	// they're imported into a Memory and the file is saved without them.
	legacyDevices map[string]*fileDevices
}

// scopeData is one scope's state.
type scopeData struct {
	settings     *Settings // nil for the defaults
	destinations []*destination

	deliveries []Delivery // newest last
}

// destination is a destination with what's never shown: its full URL, its
// webhook secret, a push subscription's keys, and an email address's
// confirmation and unsubscribe tokens.
type destination struct {
	Destination
	url    string
	secret string // a webhook's signing secret

	p256dh, auth string // a push subscription's keys, base64url

	unsubscribe string        // an email address's one-click unsubscribe token
	confirm     *confirmation // an email address's pending confirmation
}

// confirmation is an email address's pending confirmation: the SHA-256 of
// the code sent to it, never the code, and when it expires.
type confirmation struct {
	hash    string // hex
	expires time.Time
}

// view returns d as it's shown.
func (d *destination) view() Destination {
	v := d.Destination
	v.URL = redactURL(d.url)
	if d.Type == Push {
		v.URL = pushURLView(d.url)
		v.Subscription = SubscriptionID(d.url)
	}
	if d.confirm != nil {
		v.ConfirmBy = d.confirm.expires
	}
	if v.State == "" {
		v.State = Active
	}
	return v
}

// active reports whether alerts are sent to d.
func (d *destination) active() bool { return d.State == "" || d.State == Active }

// openStore opens the store persisted at path, which needn't exist yet.
// With an empty path, the store is kept only in memory.
func openStore(path string) (*store, error) {
	s := &store{path: path, scopes: make(map[string]*scopeData)}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

// scope returns the state of scope, creating it if needed. s.mu must be
// held.
func (s *store) scope(scope string) *scopeData {
	d := s.scopes[scope]
	if d == nil {
		d = new(scopeData)
		s.scopes[scope] = d
	}
	return d
}

// settings returns scope's settings, and whether it has destinations.
func (s *store) settings(scope string) (Settings, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d := s.scopes[scope]
	if d == nil {
		return DefaultSettings(scope), false
	}
	return d.currentSettings(scope), len(d.destinations) > 0
}

// currentSettings returns d's settings, or the defaults.
func (d *scopeData) currentSettings(scope string) Settings {
	if d.settings == nil {
		return DefaultSettings(scope)
	}
	return d.settings.clone()
}

// view returns scope's settings, destinations, and recent deliveries,
// newest first.
func (s *store) view(scope string) (Settings, []Destination, []Delivery) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d := s.scopes[scope]
	if d == nil {
		return DefaultSettings(scope), []Destination{}, []Delivery{}
	}
	dests := make([]Destination, len(d.destinations))
	for i, dest := range d.destinations {
		dests[i] = dest.view()
	}
	deliveries := slices.Clone(d.deliveries)
	slices.Reverse(deliveries)
	if deliveries == nil {
		deliveries = []Delivery{}
	}
	return d.currentSettings(scope), dests, deliveries
}

// destinations returns copies of scope's active destinations, with their
// URLs and secrets, for delivery: not email addresses waiting to be
// confirmed, nor browsers whose subscriptions have ended.
func (s *store) destinations(scope string) []destination {
	s.mu.Lock()
	defer s.mu.Unlock()
	d := s.scopes[scope]
	if d == nil {
		return nil
	}
	var out []destination
	for _, dest := range d.destinations {
		if dest.active() {
			out = append(out, *dest)
		}
	}
	return out
}

// find returns scope's destination of type t at url, if there is one.
// s.mu must be held.
func (s *store) find(scope string, t DestinationType, url string) *destination {
	d := s.scopes[scope]
	if d == nil {
		return nil
	}
	i := slices.IndexFunc(d.destinations, func(dest *destination) bool { return dest.Type == t && dest.url == url })
	if i < 0 {
		return nil
	}
	return d.destinations[i]
}

// prepareEmail checks that scope may add the email address at url,
// returning the destination already waiting for it to be confirmed, if
// there is one, to send a new code to.
func (s *store) prepareEmail(scope, url string) (*Destination, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if dest := s.find(scope, Email, url); dest != nil {
		if dest.confirm == nil {
			return nil, fmt.Errorf("%w: %s already gets alerts", ErrInvalid, strings.TrimPrefix(url, "mailto:"))
		}
		v := dest.view()
		return &v, nil
	}
	return nil, s.checkLimits(scope, Email)
}

// checkLimits reports whether scope may add a destination of type t.
// s.mu must be held.
func (s *store) checkLimits(scope string, t DestinationType) error {
	d := s.scopes[scope]
	if d == nil {
		return nil
	}
	if len(d.destinations) >= MaxDestinations {
		return fmt.Errorf("%w: at most %d destinations; remove one first", ErrLimit, MaxDestinations)
	}
	if t == Email {
		n := 0
		for _, dest := range d.destinations {
			if dest.Type == Email {
				n++
			}
		}
		if n >= MaxEmailDestinations {
			return fmt.Errorf("%w: at most %d email addresses, confirmed or not; remove one first", ErrLimit, MaxEmailDestinations)
		}
	}
	return nil
}

// setConfirmation replaces the pending confirmation of scope's email
// destination id.
func (s *store) setConfirmation(scope, id string, c *confirmation) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	d := s.scopes[scope]
	if d == nil {
		return fmt.Errorf("destination %q: %w", id, ErrNotFound)
	}
	i := slices.IndexFunc(d.destinations, func(dest *destination) bool { return dest.ID == id })
	if i < 0 || d.destinations[i].confirm == nil {
		return fmt.Errorf("destination %q: %w", id, ErrNotFound)
	}
	dest := d.destinations[i]
	before := dest.confirm
	dest.confirm = c
	if err := s.save(); err != nil {
		dest.confirm = before
		return err
	}
	return nil
}

// confirm confirms the pending email destination, in a scope allows
// accepts, whose code hashes to hash, at now, giving it unsubscribe as its
// unsubscribe token. Each code works once: a code that was used, or never
// sent, is not found; one past its time has expired.
func (s *store) confirm(allows func(scope string) bool, hash string, now time.Time, unsubscribe string) (string, Destination, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var (
		found      *destination
		foundScope string
	)
	// Compare with every pending code, in constant time, so how long it
	// takes says nothing about how close a guess was.
	for _, scope := range slices.Sorted(maps.Keys(s.scopes)) {
		if !allows(scope) {
			continue
		}
		for _, dest := range s.scopes[scope].destinations {
			if dest.confirm != nil && subtle.ConstantTimeCompare([]byte(dest.confirm.hash), []byte(hash)) == 1 {
				found, foundScope = dest, scope
			}
		}
	}
	switch {
	case found == nil:
		return "", Destination{}, fmt.Errorf("%w: no email address is waiting for that code; it may have been used already", ErrNotFound)
	case !now.Before(found.confirm.expires):
		return "", Destination{}, fmt.Errorf("%w: that code has expired; add the address again for a new one", ErrExpired)
	}
	before := found.Destination
	pending := found.confirm
	found.confirm, found.State, found.unsubscribe = nil, Active, unsubscribe
	if err := s.save(); err != nil {
		found.Destination, found.confirm, found.unsubscribe = before, pending, ""
		return "", Destination{}, err
	}
	return foundScope, found.view(), nil
}

// unsubscribe removes the email destination whose unsubscribe token is
// token, returning its scope and what it was.
func (s *store) unsubscribe(token string) (string, Destination, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, scope := range slices.Sorted(maps.Keys(s.scopes)) {
		d := s.scopes[scope]
		for i, dest := range d.destinations {
			if dest.unsubscribe == "" || subtle.ConstantTimeCompare([]byte(dest.unsubscribe), []byte(token)) != 1 {
				continue
			}
			before := d.destinations
			d.destinations = slices.Delete(slices.Clone(d.destinations), i, i+1)
			if err := s.save(); err != nil {
				d.destinations = before
				return "", Destination{}, err
			}
			return scope, dest.view(), nil
		}
	}
	return "", Destination{}, fmt.Errorf("%w: that unsubscribe link isn't for any address; it may have been used already", ErrNotFound)
}

// upsertPush adds a push destination to scope, or, if the browser is
// already subscribed, renews its keys, returning the destination.
func (s *store) upsertPush(scope string, dest *destination) (Destination, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if old := s.find(scope, Push, dest.url); old != nil {
		before := *old
		old.p256dh, old.auth, old.State, old.LastError = dest.p256dh, dest.auth, Active, ""
		if dest.Name != "" {
			old.Name = dest.Name
		}
		if err := s.save(); err != nil {
			*old = before
			return Destination{}, err
		}
		return old.view(), nil
	}
	if err := s.checkLimits(scope, Push); err != nil {
		return Destination{}, err
	}
	d := s.scope(scope)
	d.destinations = append(d.destinations, dest)
	if err := s.save(); err != nil {
		d.destinations = d.destinations[:len(d.destinations)-1]
		return Destination{}, err
	}
	return dest.view(), nil
}

// markGone records that scope's push destination id's subscription has
// ended, so nothing more is sent to it.
func (s *store) markGone(scope, id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d := s.scopes[scope]
	if d == nil {
		return
	}
	if i := slices.IndexFunc(d.destinations, func(dest *destination) bool { return dest.ID == id }); i >= 0 {
		d.destinations[i].State = Gone
		s.dirty = true
	}
}

// setSettings replaces scope's settings.
func (s *store) setSettings(scope string, settings Settings) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	d := s.scope(scope)
	before := d.settings
	d.settings = &settings
	if err := s.save(); err != nil {
		d.settings = before
		return err
	}
	return nil
}

// addDestination adds a destination to scope.
func (s *store) addDestination(scope string, dest *destination) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkLimits(scope, dest.Type); err != nil {
		return err
	}
	d := s.scope(scope)
	d.destinations = append(d.destinations, dest)
	if err := s.save(); err != nil {
		d.destinations = d.destinations[:len(d.destinations)-1]
		return err
	}
	return nil
}

// removeDestination removes scope's destination with id.
func (s *store) removeDestination(scope, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	d := s.scopes[scope]
	if d == nil {
		return fmt.Errorf("destination %q: %w", id, ErrNotFound)
	}
	i := slices.IndexFunc(d.destinations, func(dest *destination) bool { return dest.ID == id })
	if i < 0 {
		return fmt.Errorf("destination %q: %w", id, ErrNotFound)
	}
	before := d.destinations
	d.destinations = slices.Delete(slices.Clone(d.destinations), i, i+1)
	if err := s.save(); err != nil {
		d.destinations = before
		return err
	}
	return nil
}

// forget removes everything about scope.
func (s *store) forget(scope string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.scopes[scope]
	if !ok {
		return nil
	}
	legacy, hadLegacy := s.legacyDevices[scope]
	delete(s.scopes, scope)
	delete(s.legacyDevices, scope)
	if err := s.save(); err != nil {
		s.scopes[scope] = d
		if hadLegacy {
			s.legacyDevices[scope] = legacy
		}
		return err
	}
	return nil
}

// record remembers a delivery, and its outcome on its destination, if
// it's still there.
func (s *store) record(scope string, del Delivery) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d := s.scopes[scope]
	if d == nil {
		return
	}
	d.deliveries = append(d.deliveries, del)
	if n := len(d.deliveries) - RecentDeliveries; n > 0 {
		d.deliveries = slices.Delete(d.deliveries, 0, n)
	}
	if i := slices.IndexFunc(d.destinations, func(dest *destination) bool { return dest.ID == del.Destination }); i >= 0 {
		dest := d.destinations[i]
		if del.OK {
			dest.LastSuccess = del.Time
		} else {
			dest.LastFailure, dest.LastError = del.Time, del.Error
		}
		s.dirty = true
	}
}

// minByValue returns the key of m with the earliest time.
func minByValue(m map[string]time.Time) (string, time.Time) {
	var key string
	var at time.Time
	for k, t := range m {
		if key == "" || t.Before(at) || t.Equal(at) && k < key {
			key, at = k, t
		}
	}
	return key, at
}

// flush saves the store if deliveries changed it.
func (s *store) flush() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.dirty {
		return nil
	}
	return s.save()
}

// importDevices moves the devices an older file kept into m, then saves
// the file without them, keeping the file as it was beside it, with
// LegacyBackupSuffix appended, in case of a downgrade. Without such
// devices, it does nothing.
func (s *store) importDevices(ctx context.Context, m Memory) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.legacyDevices) == 0 {
		return nil
	}
	importer, ok := m.(DeviceImporter)
	if !ok {
		return nil // nowhere to put them; the file keeps them
	}
	for _, scope := range slices.Sorted(maps.Keys(s.legacyDevices)) {
		d := s.legacyDevices[scope]
		if err := importer.ImportDevices(ctx, scope, d.Since, d.Seen); err != nil {
			return fmt.Errorf("alerts: importing the devices %s kept: %w", s.path, err)
		}
	}
	if s.path != "" {
		backup := s.path + LegacyBackupSuffix
		if _, err := os.Stat(backup); errors.Is(err, fs.ErrNotExist) {
			b, err := os.ReadFile(s.path)
			if err != nil {
				return fmt.Errorf("alerts: %w", err)
			}
			if err := atomicfile.WriteFile(backup, b, 0o600); err != nil {
				return fmt.Errorf("alerts: keeping a copy of %s: %w", s.path, err)
			}
		}
	}
	s.legacyDevices = nil
	return s.save()
}

// LegacyBackupSuffix is appended to the alerts file's name for the copy
// kept when the devices it held move to a [Memory].
const LegacyBackupSuffix = ".before-statedb"

// file is the persisted form of the store.
type file struct {
	Version int         `json:"version"`
	Scopes  []fileScope `json:"scopes"`
}

type fileScope struct {
	// Scope is the tenant, or empty for the operator.
	Scope        string            `json:"scope"`
	Settings     *Settings         `json:"settings,omitempty"`
	Destinations []fileDestination `json:"destinations,omitempty"`

	// Devices are the devices the scope has seen, as files before the
	// state database kept them. They're read, to import, but no longer
	// written.
	Devices *fileDevices `json:"devices,omitempty"`
}

type fileDestination struct {
	ID          string          `json:"id"`
	Type        DestinationType `json:"type"`
	URL         string          `json:"url"`
	Secret      string          `json:"secret,omitempty"`
	Name        string          `json:"name,omitempty"`
	Created     time.Time       `json:"created"`
	CreatedBy   string          `json:"created_by,omitempty"`
	LastSuccess time.Time       `json:"last_success,omitzero"`
	LastFailure time.Time       `json:"last_failure,omitzero"`
	LastError   string          `json:"last_error,omitempty"`

	// State is "pending" or "gone", or empty for active.
	State DestinationState `json:"state,omitempty"`

	// P256DH and Auth are a push subscription's keys.
	P256DH string `json:"p256dh,omitempty"`
	Auth   string `json:"auth,omitempty"`

	// Unsubscribe is an email address's unsubscribe token, and
	// ConfirmHash and ConfirmExpires its pending confirmation.
	Unsubscribe    string    `json:"unsubscribe,omitempty"`
	ConfirmHash    string    `json:"confirm_hash,omitempty"`
	ConfirmExpires time.Time `json:"confirm_expires,omitzero"`
}

// valid reports whether fd has what its type needs, and nothing it
// doesn't: a webhook its secret, a push subscription its keys, and an
// email address either a pending confirmation or an active state.
func (fd fileDestination) valid() bool {
	pending := fd.State == Pending
	switch {
	case fd.State != "" && fd.State != Active && fd.State != Pending && fd.State != Gone:
		return false
	case (fd.Type == Webhook) != strings.HasPrefix(fd.Secret, SecretPrefix):
		return false
	case (fd.Type == Push) != (fd.P256DH != "" && fd.Auth != ""):
		return false
	case pending != (fd.ConfirmHash != ""), pending && fd.Type != Email, fd.State == Gone && fd.Type != Push:
		return false
	case fd.Unsubscribe != "" && (fd.Type != Email || pending):
		return false
	}
	if fd.Type == Push {
		_, _, err := (webpush.Subscription{Endpoint: fd.URL, Keys: webpush.SubscriptionKeys{P256DH: fd.P256DH, Auth: fd.Auth}}).Decode()
		return err == nil
	}
	return true
}

type fileDevices struct {
	Since time.Time            `json:"since"`
	Seen  map[string]time.Time `json:"seen"`
}

// load reads the persisted store, if there is one.
func (s *store) load() error {
	if s.path == "" {
		return nil
	}
	b, err := os.ReadFile(s.path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("alerts: %w", err)
	}

	var f file
	if err := json.Unmarshal(b, &f, json.RejectUnknownMembers(true)); err != nil {
		return fmt.Errorf("alerts: reading %s: %w", s.path, err)
	}
	if f.Version != fileVersion {
		return fmt.Errorf("alerts: %s has unsupported version %d", s.path, f.Version)
	}
	for _, sc := range f.Scopes {
		if _, dup := s.scopes[sc.Scope]; dup {
			return fmt.Errorf("alerts: %s: scope %q appears twice", s.path, sc.Scope)
		}
		d := s.scope(sc.Scope)
		if sc.Settings != nil {
			settings, err := sc.Settings.normalize(sc.Scope)
			if err != nil {
				return fmt.Errorf("alerts: %s: scope %q: %w", s.path, sc.Scope, err)
			}
			d.settings = &settings
		}
		if len(sc.Destinations) > MaxDestinations {
			return fmt.Errorf("alerts: %s: scope %q has too many destinations", s.path, sc.Scope)
		}
		for _, fd := range sc.Destinations {
			if fd.ID == "" || !fd.Type.Valid() || !fd.valid() ||
				slices.ContainsFunc(d.destinations, func(dest *destination) bool { return dest.ID == fd.ID }) {
				return fmt.Errorf("alerts: %s: scope %q: invalid destination %q", s.path, sc.Scope, fd.ID)
			}
			if err := checkDestination(sc.Scope, fd.Type, fd.URL); err != nil {
				return fmt.Errorf("alerts: %s: scope %q: destination %q: %w", s.path, sc.Scope, fd.ID, err)
			}
			dest := &destination{
				Destination: Destination{ID: fd.ID, Type: fd.Type, Name: fd.Name, Created: fd.Created, CreatedBy: fd.CreatedBy,
					LastSuccess: fd.LastSuccess, LastFailure: fd.LastFailure, LastError: fd.LastError, State: fd.State},
				url:         fd.URL,
				secret:      fd.Secret,
				p256dh:      fd.P256DH,
				auth:        fd.Auth,
				unsubscribe: fd.Unsubscribe,
			}
			if fd.ConfirmHash != "" {
				dest.confirm = &confirmation{hash: fd.ConfirmHash, expires: fd.ConfirmExpires}
			}
			d.destinations = append(d.destinations, dest)
		}
		if sc.Devices != nil {
			if s.legacyDevices == nil {
				s.legacyDevices = make(map[string]*fileDevices)
			}
			s.legacyDevices[sc.Scope] = sc.Devices
		}
	}
	return nil
}

// save persists the store atomically, readable only by its owner. s.mu
// must be held.
func (s *store) save() error {
	if s.path == "" {
		s.dirty = false
		return nil
	}
	f := file{Version: fileVersion, Scopes: []fileScope{}}
	for _, scope := range slices.Sorted(maps.Keys(s.scopes)) {
		d := s.scopes[scope]
		sc := fileScope{Scope: scope, Settings: d.settings, Devices: s.legacyDevices[scope]}
		for _, dest := range d.destinations {
			fd := fileDestination{
				ID: dest.ID, Type: dest.Type, URL: dest.url, Secret: dest.secret, Name: dest.Name,
				Created: dest.Created, CreatedBy: dest.CreatedBy,
				LastSuccess: dest.LastSuccess, LastFailure: dest.LastFailure, LastError: dest.LastError,
				State: dest.State, P256DH: dest.p256dh, Auth: dest.auth, Unsubscribe: dest.unsubscribe,
			}
			if dest.confirm != nil {
				fd.ConfirmHash, fd.ConfirmExpires = dest.confirm.hash, dest.confirm.expires
			}
			sc.Destinations = append(sc.Destinations, fd)
		}
		f.Scopes = append(f.Scopes, sc)
	}
	b, err := json.Marshal(f, json.Deterministic(true))
	if err != nil {
		return err
	}
	if err := atomicfile.WriteFile(s.path, b, 0o600); err != nil {
		return fmt.Errorf("alerts: saving %s: %w", s.path, err)
	}
	s.dirty = false
	return nil
}
