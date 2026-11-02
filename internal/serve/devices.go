package serve

import (
	"cmp"
	"context"
	"log/slog"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/picatz/doh/internal/api"
	"github.com/picatz/doh/internal/policy"
	"github.com/picatz/doh/internal/statedb"
)

// maxSeenDevices bounds how many devices the server remembers having
// answered. Past it, the least recently seen are forgotten.
const maxSeenDevices = 4096

// maxListedDevices bounds how many devices one response lists.
const maxListedDevices = 200

// seenKey is a device as the server tells devices apart: by the profile
// it used, the name it was given (in a DoH path or the profile's
// devices), and its address.
type seenKey struct {
	profile, device string
	client          netip.Addr
}

// seenDevice is what the server remembers of a device it answered.
type seenDevice struct {
	tenant      string
	transport   string
	first, last time.Time
}

// seenDevices remembers the devices the server has answered, whether or
// not their profiles log queries: what lets the web UI tell someone that
// the phone they just set up is connected. It's bounded, and costs a map
// lookup per query. With a state database, what changed is saved every
// seenSaveInterval and when the server closes, and loaded when it starts,
// so devices seen survive restarts.
type seenDevices struct {
	mu      sync.Mutex
	devices map[seenKey]*seenDevice
	dirty   map[seenKey]struct{} // changed since last saved
	since   time.Time            // when remembering began
}

// seenSaveInterval is how often the devices seen are saved.
const seenSaveInterval = 30 * time.Second

func newSeenDevices(now time.Time) *seenDevices {
	return &seenDevices{devices: make(map[seenKey]*seenDevice), dirty: make(map[seenKey]struct{}), since: now}
}

// load adds the devices store kept, as when the server last saved them.
func (d *seenDevices) load(ctx context.Context, store *statedb.SeenDevices) error {
	saved, err := store.Load(ctx, maxSeenDevices)
	if err != nil {
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, s := range saved {
		client, _ := netip.ParseAddr(s.Client)
		k := seenKey{s.Profile, s.Device, client}
		if _, ok := d.devices[k]; ok || len(d.devices) >= maxSeenDevices {
			continue
		}
		d.devices[k] = &seenDevice{tenant: s.Tenant, transport: s.Transport, first: s.First, last: s.Last}
		if s.First.Before(d.since) {
			d.since = s.First
		}
	}
	return nil
}

// save stores what changed since it last did.
func (d *seenDevices) save(ctx context.Context, store *statedb.SeenDevices) error {
	d.mu.Lock()
	batch := make([]statedb.SeenDevice, 0, len(d.dirty))
	for k := range d.dirty {
		e := d.devices[k]
		if e == nil {
			continue // forgotten since
		}
		s := statedb.SeenDevice{Profile: k.profile, Device: k.device, Tenant: e.tenant, Transport: e.transport, First: e.first, Last: e.last}
		if k.client.IsValid() {
			s.Client = k.client.String()
		}
		batch = append(batch, s)
	}
	clear(d.dirty)
	d.mu.Unlock()
	if len(batch) == 0 {
		return nil
	}
	return store.Save(ctx, batch, maxSeenDevices)
}

// saveSeen saves the devices seen every seenSaveInterval, until ctx is
// done. Close saves the rest.
func (s *Server) saveSeen(ctx context.Context) error {
	ticker := time.NewTicker(seenSaveInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
		if err := s.seen.save(ctx, s.stateDB.SeenDevices()); err != nil && ctx.Err() == nil {
			s.logger.Warn("saving the devices seen", slog.Any("error", err))
		}
	}
}

// observe records that the server answered a query from client, under
// profile and device, at now.
func (d *seenDevices) observe(profile, tenant, device string, client netip.Addr, transport string, now time.Time) {
	if d == nil || profile == "" {
		return
	}
	k := seenKey{profile, device, client.Unmap()}
	d.mu.Lock()
	defer d.mu.Unlock()
	if e := d.devices[k]; e != nil {
		e.last, e.transport, e.tenant = now, transport, tenant
		d.dirty[k] = struct{}{}
		return
	}
	if len(d.devices) >= maxSeenDevices {
		d.forgetOldest(maxSeenDevices / 8)
	}
	d.devices[k] = &seenDevice{tenant: tenant, transport: transport, first: now, last: now}
	d.dirty[k] = struct{}{}
}

// forgetOldest forgets the n least recently seen devices. d.mu must be
// held. It's linear, but runs once per n new devices.
func (d *seenDevices) forgetOldest(n int) {
	type aged struct {
		k    seenKey
		last time.Time
	}
	all := make([]aged, 0, len(d.devices))
	for k, e := range d.devices {
		all = append(all, aged{k, e.last})
	}
	slices.SortFunc(all, func(a, b aged) int { return a.last.Compare(b.last) })
	for _, a := range all[:min(n, len(all))] {
		delete(d.devices, a.k)
	}
}

// seenFilter selects remembered devices.
type seenFilter struct {
	// visible reports whether the caller may see a profile's devices,
	// given the profile and the tenant it had when the device was seen.
	visible func(profile, tenant string) bool

	profile, device string
	// device is matched exactly when hasDevice is set, so "" can ask for
	// devices with no name.
	hasDevice bool

	// since keeps devices last seen at or after it; with new, devices
	// first seen at or after it.
	since time.Time
	new   bool
}

// list returns the devices f selects, most recently seen first, at most
// maxListedDevices.
func (d *seenDevices) list(f seenFilter) []api.SeenDevice {
	d.mu.Lock()
	defer d.mu.Unlock()
	var out []api.SeenDevice
	for k, e := range d.devices {
		switch {
		case f.profile != "" && k.profile != f.profile,
			f.hasDevice && k.device != f.device,
			!f.visible(k.profile, e.tenant),
			!f.since.IsZero() && f.new && e.first.Before(f.since),
			!f.since.IsZero() && e.last.Before(f.since):
			continue
		}
		sd := api.SeenDevice{Profile: k.profile, Device: k.device, Transport: e.transport, First: e.first, Last: e.last}
		if k.client.IsValid() {
			sd.Client = k.client.String()
		}
		out = append(out, sd)
	}
	slices.SortFunc(out, func(a, b api.SeenDevice) int {
		return cmp.Or(b.Last.Compare(a.Last), cmp.Compare(a.Profile, b.Profile), cmp.Compare(a.Device, b.Device), cmp.Compare(a.Client, b.Client))
	})
	if len(out) > maxListedDevices {
		out = out[:maxListedDevices]
	}
	return out
}

// apiDevices lists the devices the server has answered, as the caller may
// see them: a tenant, only its own profiles' devices.
//
// Query parameters: profile, device (present to match exactly, even
// empty), since (RFC 3339), and new=true to list only devices first seen
// since then. The web UI polls it to see a device it just set up connect.
func (s *Server) apiDevices(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	who := principalOf(r)
	pol := s.engine.Load().Policy()
	f := seenFilter{
		profile: q.Get("profile"),
		visible: func(profile, tenant string) bool {
			// Both the tenant the device was seen under and the profile's
			// tenant now must be the caller's, so a profile deleted and
			// made again by someone else shows them nothing of before.
			if who.operator() {
				return true
			}
			pr := pol.Profile(profile)
			return tenant == who.tenant && pr != nil && who.sees(pr)
		},
	}
	if f.profile != "" && !who.sees(pol.Profile(f.profile)) {
		writeError(w, http.StatusNotFound, "no profile "+strconv.Quote(f.profile))
		return
	}
	if q.Has("device") {
		f.device, f.hasDevice = q.Get("device"), true
		if f.device != "" && !policy.ValidID(f.device) {
			writeError(w, http.StatusBadRequest, "device names are 1 to 63 lower-case letters, digits, and single hyphens")
			return
		}
	}
	if v := q.Get("since"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			writeError(w, http.StatusBadRequest, "since must be an RFC 3339 time")
			return
		}
		f.since = t
	}
	switch q.Get("new") {
	case "", "false":
	case "true":
		f.new = true
	default:
		writeError(w, http.StatusBadRequest, "new must be true or false")
		return
	}
	devices := s.seen.list(f)
	if devices == nil {
		devices = []api.SeenDevice{}
	}
	for i := range devices {
		if a, err := netip.ParseAddr(devices[i].Client); err == nil && devices[i].Device == "" {
			devices[i].Hostname = s.hostnames.Name(a)
		}
	}
	s.seen.mu.Lock()
	since := s.seen.since
	s.seen.mu.Unlock()
	writeJSON(w, http.StatusOK, api.SeenDevices{Since: since, Devices: devices})
}
