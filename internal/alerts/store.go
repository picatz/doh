package alerts

import (
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
)

// fileVersion is the version of the persisted store.
const fileVersion = 1

// store keeps each scope's settings, destinations, and seen devices,
// persisted to a file, and its recent deliveries, in memory. It's safe
// for concurrent use.
type store struct {
	path string

	mu     sync.Mutex
	scopes map[string]*scopeData
	dirty  bool // changed since saved, by deliveries or devices
}

// scopeData is one scope's state.
type scopeData struct {
	settings     *Settings // nil for the defaults
	destinations []*destination

	// devicesSince is when the scope started seeing devices, and devices
	// when each it has seen was last seen.
	devicesSince time.Time
	devices      map[string]time.Time

	deliveries []Delivery // newest last
}

// destination is a destination with what's never shown: its full URL and
// its webhook secret.
type destination struct {
	Destination
	url    string
	secret string
}

// view returns d as it's shown.
func (d *destination) view() Destination {
	v := d.Destination
	v.URL = redactURL(d.url)
	return v
}

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
		d = &scopeData{devices: make(map[string]time.Time)}
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

// destinations returns copies of scope's destinations, with their URLs
// and secrets, for delivery.
func (s *store) destinations(scope string) []destination {
	s.mu.Lock()
	defer s.mu.Unlock()
	d := s.scopes[scope]
	if d == nil {
		return nil
	}
	out := make([]destination, len(d.destinations))
	for i, dest := range d.destinations {
		out[i] = *dest
	}
	return out
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
	d := s.scope(scope)
	if len(d.destinations) >= MaxDestinations {
		return fmt.Errorf("%w: at most %d destinations; remove one first", ErrLimit, MaxDestinations)
	}
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
	delete(s.scopes, scope)
	if err := s.save(); err != nil {
		s.scopes[scope] = d
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

// seeDevice records that scope saw device at now, reporting whether it's
// new to the scope, and whether the scope is still learning its devices.
func (s *store) seeDevice(scope, device string, now time.Time) (isNew, learning bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d := s.scope(scope)
	if d.devicesSince.IsZero() {
		d.devicesSince = now.UTC()
		s.dirty = true
	}
	learning = now.Sub(d.devicesSince) < LearningPeriod

	if _, ok := d.devices[device]; ok {
		d.devices[device] = now.UTC() // persisted with the next change
		return false, learning
	}
	if len(d.devices) >= MaxSeenDevices {
		oldest, _ := minByValue(d.devices)
		delete(d.devices, oldest)
	}
	d.devices[device] = now.UTC()
	s.dirty = true
	return true, learning
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

// flush saves the store if deliveries or devices changed it.
func (s *store) flush() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.dirty {
		return nil
	}
	return s.save()
}

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
	Devices      *fileDevices      `json:"devices,omitempty"`
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
			if fd.ID == "" || !fd.Type.Valid() || fd.Type == Webhook && !strings.HasPrefix(fd.Secret, SecretPrefix) ||
				slices.ContainsFunc(d.destinations, func(dest *destination) bool { return dest.ID == fd.ID }) {
				return fmt.Errorf("alerts: %s: scope %q: invalid destination %q", s.path, sc.Scope, fd.ID)
			}
			if _, err := checkURL(sc.Scope, fd.Type, fd.URL); err != nil {
				return fmt.Errorf("alerts: %s: scope %q: destination %q: %w", s.path, sc.Scope, fd.ID, err)
			}
			d.destinations = append(d.destinations, &destination{
				Destination: Destination{ID: fd.ID, Type: fd.Type, Name: fd.Name, Created: fd.Created, CreatedBy: fd.CreatedBy,
					LastSuccess: fd.LastSuccess, LastFailure: fd.LastFailure, LastError: fd.LastError},
				url:    fd.URL,
				secret: fd.Secret,
			})
		}
		if sc.Devices != nil {
			d.devicesSince = sc.Devices.Since
			d.devices = maps.Clone(sc.Devices.Seen)
			if d.devices == nil {
				d.devices = make(map[string]time.Time)
			}
			for len(d.devices) > MaxSeenDevices {
				oldest, _ := minByValue(d.devices)
				delete(d.devices, oldest)
			}
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
		sc := fileScope{Scope: scope, Settings: d.settings}
		for _, dest := range d.destinations {
			sc.Destinations = append(sc.Destinations, fileDestination{
				ID: dest.ID, Type: dest.Type, URL: dest.url, Secret: dest.secret, Name: dest.Name,
				Created: dest.Created, CreatedBy: dest.CreatedBy,
				LastSuccess: dest.LastSuccess, LastFailure: dest.LastFailure, LastError: dest.LastError,
			})
		}
		if !d.devicesSince.IsZero() {
			sc.Devices = &fileDevices{Since: d.devicesSince, Seen: d.devices}
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
