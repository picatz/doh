package rdap

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"slices"
	"sync"
	"time"

	"github.com/picatz/doh/internal/atomicfile"

	"golang.org/x/sync/singleflight"
)

// Cache lifetimes for [Ages].
const (
	// youngAge is the age below which a domain counts as young, and is
	// looked up again more often until it isn't.
	youngAge = 90 * 24 * time.Hour

	oldTTL         = 30 * 24 * time.Hour
	youngMinTTL    = time.Hour
	youngMaxTTL    = 24 * time.Hour
	unsupportedTTL = 7 * 24 * time.Hour
	failureTTL     = 15 * time.Minute

	// rateLimitBackoff is how long an RDAP server that answered 429 Too
	// Many Requests is left alone.
	rateLimitBackoff = time.Minute

	// saveInterval is the most often Age saves the cache by itself.
	saveInterval = time.Minute

	defaultLookupTimeout = 2 * time.Second
	defaultMaxEntries    = 100_000

	// cacheVersion identifies the persisted cache format.
	cacheVersion = 1
)

// Ages reports how long ago domains were registered, caching lookups made
// with a [Client] so each registrable domain is looked up at most once per
// cache lifetime. Concurrent lookups of the same domain share one request,
// and the cache can be persisted to a file so restarts don't query again.
//
// Ages is safe for concurrent use. Its fields must not change after first
// use.
type Ages struct {
	// Client performs lookups. If nil, a zero [Client] is used.
	Client *Client

	// Path, if set, persists the cache as JSON. It's loaded on first use and
	// written atomically, readable only by its owner.
	Path string

	// Timeout bounds each lookup. If zero, 2 seconds is used.
	Timeout time.Duration

	// Logger reports lookup and persistence failures at debug and warn
	// levels. If nil, nothing is logged.
	Logger *slog.Logger

	now        func() time.Time // for tests
	maxEntries int              // for tests; 0 means defaultMaxEntries

	group  singleflight.Group
	saveMu sync.Mutex // serializes writes to Path

	mu       sync.Mutex
	loaded   bool
	entries  map[string]ageEntry
	backoff  map[string]time.Time // RDAP server host → until
	lastSave time.Time
	client   *Client
}

// ageEntry is a cached lookup. A zero Registered means the age is unknown.
type ageEntry struct {
	Registered time.Time `json:"registered,omitzero"`
	Checked    time.Time `json:"checked"`
	Expires    time.Time `json:"expires"`
}

// ageFile is the persisted form of the cache.
type ageFile struct {
	Version int                 `json:"version"`
	Entries map[string]ageEntry `json:"entries"`
}

func (a *Ages) clock() time.Time {
	if a.now != nil {
		return a.now()
	}
	return time.Now()
}

func (a *Ages) logger() *slog.Logger {
	if a.Logger == nil {
		return slog.New(slog.DiscardHandler)
	}
	return a.Logger
}

// init prepares the cache, loading Path on first use. a.mu must be held.
func (a *Ages) init() {
	if a.loaded {
		return
	}
	a.loaded = true
	a.entries = make(map[string]ageEntry)
	a.backoff = make(map[string]time.Time)
	a.client = a.Client
	if a.client == nil {
		a.client = &Client{}
	}
	if a.now != nil && a.client.now == nil && a.Client == nil {
		a.client.now = a.now
	}

	if a.Path == "" {
		return
	}

	data, err := os.ReadFile(a.Path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			a.logger().Warn("rdap: reading cache", slog.String("path", a.Path), slog.Any("error", err))
		}
		return
	}

	var file ageFile
	if err := json.Unmarshal(data, &file); err != nil || file.Version != cacheVersion {
		a.logger().Warn("rdap: ignoring unreadable cache", slog.String("path", a.Path), slog.Any("error", err))
		return
	}

	now := a.clock()
	for domain, e := range file.Entries {
		if _, err := normalize(domain); err == nil && now.Before(e.Expires) {
			a.entries[domain] = e
		}
	}
	a.evict()
}

// Age reports how long ago domain, a registrable domain such as
// "example.com", was registered. ok is false when the age is unknown: the
// top-level domain has no RDAP service, the domain isn't found, the
// lookup times out or fails, or the server is rate limiting, so callers
// can fail open.
//
// Results are cached: registrations older than 90 days for 30 days;
// younger ones until they turn 90 days old, but at least an hour and at
// most a day; unsupported TLDs for 7 days; and other failures for 15
// minutes. After an RDAP server answers 429 Too Many Requests
// ([RFC 7480, Section 5.5]), domains it serves aren't looked up for a
// minute.
//
// [RFC 7480, Section 5.5]: https://www.rfc-editor.org/rfc/rfc7480.html#section-5.5
func (a *Ages) Age(ctx context.Context, domain string) (age time.Duration, ok bool) {
	domain, err := normalize(domain)
	if err != nil {
		return 0, false
	}

	a.mu.Lock()
	a.init()
	e, found := a.entries[domain]
	a.mu.Unlock()

	if !found || !a.clock().Before(e.Expires) {
		ch := a.group.DoChan(domain, func() (any, error) {
			return a.lookup(ctx, domain), nil
		})

		select {
		case <-ctx.Done():
			return 0, false
		case res := <-ch:
			e = res.Val.(ageEntry)
		}
	}

	if e.Registered.IsZero() {
		return 0, false
	}

	return max(a.clock().Sub(e.Registered), 0), true
}

// lookup queries domain's RDAP server and caches the result, returning the
// entry (which may be uncached, for rate limited servers).
func (a *Ages) lookup(ctx context.Context, domain string) ageEntry {
	// Share the lookup with other callers even if this one gives up.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), cmp.Or(a.Timeout, defaultLookupTimeout))
	defer cancel()

	now := a.clock()

	base, err := a.client.serviceURL(ctx, domain)
	if err != nil {
		return a.store(domain, now, time.Time{}, err)
	}

	a.mu.Lock()
	until, backingOff := a.backoff[base.Host]
	a.mu.Unlock()
	if backingOff && now.Before(until) {
		return ageEntry{}
	}

	registered, err := a.client.registered(ctx, base, domain)
	if rl, ok := errors.AsType[*rateLimitedError](err); ok {
		a.logger().Debug("rdap: rate limited, backing off", slog.String("host", rl.host))
		a.mu.Lock()
		a.backoff[base.Host] = now.Add(rateLimitBackoff)
		a.mu.Unlock()
		return ageEntry{}
	}

	return a.store(domain, now, registered, err)
}

// store caches the result of looking up domain at now, and saves the cache
// if it hasn't been saved for a while.
func (a *Ages) store(domain string, now, registered time.Time, err error) ageEntry {
	e := ageEntry{Registered: registered, Checked: now, Expires: now.Add(ttl(now, registered, err))}
	if err != nil {
		e.Registered = time.Time{}
		a.logger().Debug("rdap: lookup failed", slog.String("domain", domain), slog.Any("error", err))
	}

	a.mu.Lock()
	a.entries[domain] = e
	a.evict()
	save := a.Path != "" && now.Sub(a.lastSave) >= saveInterval
	if save {
		a.lastSave = now
	}
	a.mu.Unlock()

	if save {
		if err := a.Save(); err != nil {
			a.logger().Warn("rdap: saving cache", slog.String("path", a.Path), slog.Any("error", err))
		}
	}

	return e
}

// ttl returns how long to cache a lookup made at now.
func ttl(now, registered time.Time, err error) time.Duration {
	switch {
	case errors.Is(err, ErrUnsupported):
		return unsupportedTTL
	case err != nil:
		return failureTTL
	case now.Sub(registered) >= youngAge:
		return oldTTL
	default:
		return min(max(registered.Add(youngAge).Sub(now), youngMinTTL), youngMaxTTL)
	}
}

// evict drops the least recently checked tenth of the entries once there
// are too many. a.mu must be held.
func (a *Ages) evict() {
	limit := cmp.Or(a.maxEntries, defaultMaxEntries)
	if len(a.entries) <= limit {
		return
	}

	type checked struct {
		domain string
		at     time.Time
	}
	all := make([]checked, 0, len(a.entries))
	for d, e := range a.entries {
		all = append(all, checked{d, e.Checked})
	}
	slices.SortFunc(all, func(x, y checked) int { return x.at.Compare(y.at) })

	drop := len(a.entries) - limit + limit/10
	for _, c := range all[:min(drop, len(all))] {
		delete(a.entries, c.domain)
	}
}

// Save writes the cache to Path, omitting expired entries. It does nothing
// if Path is empty.
func (a *Ages) Save() error {
	if a.Path == "" {
		return nil
	}

	a.saveMu.Lock()
	defer a.saveMu.Unlock()

	a.mu.Lock()
	a.init()
	now := a.clock()
	file := ageFile{Version: cacheVersion, Entries: make(map[string]ageEntry, len(a.entries))}
	for d, e := range a.entries {
		if now.Before(e.Expires) {
			file.Entries[d] = e
		}
	}
	a.mu.Unlock()

	data, err := json.Marshal(file)
	if err != nil {
		return err
	}

	return atomicfile.WriteFile(a.Path, data, 0o600)
}
