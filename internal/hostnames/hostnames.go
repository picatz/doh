// Package hostnames learns the names of devices on a network from their
// addresses, so query logs can say "living-room-tv" rather than
// "192.168.1.50" without anyone typing it in.
//
// Names come from [Source]s: reverse DNS lookups ([PTR]) to the router,
// which most home routers answer with the hostnames their DHCP clients
// send, and DHCP lease files ([Leases]). A [Directory] caches what they
// say and looks names up in the background, so asking it for a name never
// waits.
//
// Hostnames are whatever devices call themselves: any device can claim
// any name. They're labels for people reading logs, never a basis for
// decisions such as which policy applies.
package hostnames

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// Source looks up the name of the device at an address.
type Source interface {
	// Lookup returns the device's hostname, or "" with a nil error if the
	// source doesn't know it.
	Lookup(ctx context.Context, addr netip.Addr) (string, error)
}

// Directory defaults.
const (
	// DefaultTTL is how long a found name is kept before it's looked up
	// again, since addresses move between devices as DHCP leases expire.
	DefaultTTL = time.Hour

	// DefaultNegativeTTL is how long an address with no known name, or
	// whose lookup failed, waits before it's looked up again.
	DefaultNegativeTTL = 10 * time.Minute

	// DefaultMaxEntries bounds the addresses remembered.
	DefaultMaxEntries = 10_000

	// lookupTimeout bounds each lookup, across every source.
	lookupTimeout = 3 * time.Second

	// queueSize bounds the lookups waiting to run; beyond it, addresses
	// are skipped until a later query asks again.
	queueSize = 256

	// workers is how many lookups run at once.
	workers = 2
)

// Directory caches device names, looked up from its sources in the
// background. It's safe for concurrent use. Create one with [New].
type Directory struct {
	sources     []Source
	accept      func(netip.Addr) bool
	ttl         time.Duration
	negativeTTL time.Duration
	maxEntries  int

	queue  chan netip.Addr
	cancel context.CancelFunc
	wg     sync.WaitGroup

	mu       sync.Mutex
	entries  map[netip.Addr]entry
	inflight map[netip.Addr]bool
}

type entry struct {
	name    string
	expires time.Time
}

// Option configures a [Directory].
type Option func(*Directory)

// WithTTL sets how long found names, and unknown addresses, are kept
// before being looked up again.
func WithTTL(found, unknown time.Duration) Option {
	return func(d *Directory) { d.ttl, d.negativeTTL = found, unknown }
}

// WithMaxEntries bounds how many addresses are remembered.
func WithMaxEntries(n int) Option {
	return func(d *Directory) { d.maxEntries = n }
}

// WithAccept limits lookups to addresses accept reports true for. By
// default, only local addresses are looked up: private, unique local,
// and link-local ones, whose names a local router or DHCP server knows.
func WithAccept(accept func(netip.Addr) bool) Option {
	return func(d *Directory) { d.accept = accept }
}

// IsLocal reports whether addr is a local network address, whose name a
// local router or DHCP server might know: private (RFC 1918), unique
// local (RFC 4193), or link-local.
func IsLocal(addr netip.Addr) bool {
	addr = addr.Unmap()
	return addr.IsPrivate() || addr.IsLinkLocalUnicast()
}

// New returns a directory over sources, consulted in order until one
// knows a name, and starts its background lookups. Close stops them.
func New(sources []Source, opts ...Option) *Directory {
	ctx, cancel := context.WithCancel(context.Background())
	d := &Directory{
		sources:     sources,
		accept:      IsLocal,
		ttl:         DefaultTTL,
		negativeTTL: DefaultNegativeTTL,
		maxEntries:  DefaultMaxEntries,
		queue:       make(chan netip.Addr, queueSize),
		cancel:      cancel,
		entries:     make(map[netip.Addr]entry),
		inflight:    make(map[netip.Addr]bool),
	}
	for _, opt := range opts {
		opt(d)
	}

	for range workers {
		d.wg.Go(func() { d.work(ctx) })
	}
	return d
}

// Name returns the known name of the device at addr, or "". It never
// waits: an unknown or stale address is looked up in the background, so
// its name is known by a later call.
func (d *Directory) Name(addr netip.Addr) string {
	if d == nil || !addr.IsValid() {
		return ""
	}
	addr = addr.Unmap().WithZone("")
	if !d.accept(addr) {
		return ""
	}

	now := time.Now()
	d.mu.Lock()
	e, ok := d.entries[addr]
	stale := !ok || !now.Before(e.expires)
	if stale && !d.inflight[addr] {
		select {
		case d.queue <- addr:
			d.inflight[addr] = true
		default: // busy: a later call will ask again
		}
	}
	d.mu.Unlock()

	// A stale name is still the best guess until its lookup finishes.
	return e.name
}

// work runs lookups from the queue until ctx is done.
func (d *Directory) work(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case addr := <-d.queue:
			d.store(addr, d.lookup(ctx, addr))
		}
	}
}

// lookup asks each source in turn for addr's name.
func (d *Directory) lookup(ctx context.Context, addr netip.Addr) string {
	ctx, cancel := context.WithTimeout(ctx, lookupTimeout)
	defer cancel()

	for _, s := range d.sources {
		name, err := s.Lookup(ctx, addr)
		if err == nil && name != "" {
			if name = Normalize(name); name != "" {
				return name
			}
		}
		if errors.Is(ctx.Err(), context.Canceled) {
			return ""
		}
	}
	return ""
}

// store records addr's looked-up name.
func (d *Directory) store(addr netip.Addr, name string) {
	ttl := d.ttl
	if name == "" {
		ttl = d.negativeTTL
	}
	now := time.Now()

	d.mu.Lock()
	defer d.mu.Unlock()

	delete(d.inflight, addr)
	if _, ok := d.entries[addr]; !ok && len(d.entries) >= d.maxEntries {
		d.evict(now)
	}
	d.entries[addr] = entry{name: name, expires: now.Add(ttl)}
}

// evict makes room for one more entry: every expired entry goes, or if
// none has expired, the one expiring soonest. d.mu must be held.
func (d *Directory) evict(now time.Time) {
	var (
		soonest netip.Addr
		when    time.Time
	)
	for addr, e := range d.entries {
		if !now.Before(e.expires) {
			delete(d.entries, addr)
			continue
		}
		if when.IsZero() || e.expires.Before(when) {
			soonest, when = addr, e.expires
		}
	}
	if len(d.entries) >= d.maxEntries {
		delete(d.entries, soonest)
	}
}

// Len returns the number of addresses remembered.
func (d *Directory) Len() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.entries)
}

// Close stops background lookups and waits for them to finish.
func (d *Directory) Close() {
	if d == nil {
		return
	}
	d.cancel()
	d.wg.Wait()
}

// Normalize turns a hostname into a device name, in the form profiles
// name devices: the first label, lower-cased, with anything but letters,
// digits, and hyphens turned into hyphens, runs of hyphens collapsed, and
// leading and trailing ones trimmed, at most 63 bytes. "Living Room
// TV.lan" becomes "living-room-tv". It returns "" if nothing is left.
func Normalize(hostname string) string {
	label, _, _ := strings.Cut(strings.TrimSpace(hostname), ".")

	var b strings.Builder
	hyphen := false
	for _, r := range strings.ToLower(label) {
		if b.Len() == 63 {
			break
		}
		switch {
		case 'a' <= r && r <= 'z', '0' <= r && r <= '9':
			b.WriteRune(r)
			hyphen = false
		case !hyphen && b.Len() > 0:
			b.WriteByte('-')
			hyphen = true
		}
	}
	return strings.Trim(b.String(), "-")
}
