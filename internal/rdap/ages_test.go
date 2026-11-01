package rdap

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeClock is a settable clock for tests.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func newAges(s *rdapServer, clock *fakeClock, path string) *Ages {
	c := s.client()
	c.now = clock.Now
	return &Ages{Client: c, Path: path, now: clock.Now}
}

func TestAges_CachesByAge(t *testing.T) {
	clock := &fakeClock{now: fakeNow}
	registrations := map[string]time.Time{
		"old.test":   fakeNow.Add(-5 * 365 * 24 * time.Hour),
		"young.test": fakeNow.Add(-3 * 24 * time.Hour),
		"edge.test":  fakeNow.Add(-youngAge + 10*time.Minute), // turns old in 10 minutes
	}
	s := newRDAPServer(t, []string{"test"}, func(w http.ResponseWriter, domain string) {
		registeredAt(registrations[domain])(w, domain)
	})
	tests := []struct {
		domain   string
		cachedAt time.Duration // still cached just before this
	}{
		{"old.test", oldTTL},
		{"young.test", youngMaxTTL},
		{"edge.test", youngMinTTL},
	}
	for _, tt := range tests {
		t.Run(tt.domain, func(t *testing.T) {
			clock.mu.Lock()
			clock.now = fakeNow
			clock.mu.Unlock()
			a := newAges(s, clock, "")
			start := clock.Now()
			age, ok := a.Age(t.Context(), tt.domain)
			if want := start.Sub(registrations[tt.domain]); !ok || age != want {
				t.Fatalf("Age = %v, %v; want %v, true", age, ok, want)
			}
			hits := s.domainHits.Load()

			// Age advances with the clock, from the cache.
			clock.Advance(tt.cachedAt - time.Second)
			if age, ok := a.Age(t.Context(), tt.domain); !ok || age != clock.Now().Sub(registrations[tt.domain]) {
				t.Errorf("cached Age = %v, %v", age, ok)
			}
			if n := s.domainHits.Load(); n != hits {
				t.Errorf("looked up again before expiry: %d requests, want %d", n, hits)
			}

			clock.Advance(2 * time.Second)
			if _, ok := a.Age(t.Context(), tt.domain); !ok {
				t.Error("Age after expiry not ok")
			}
			if n := s.domainHits.Load(); n != hits+1 {
				t.Errorf("not looked up again after expiry: %d requests, want %d", n, hits+1)
			}
		})
	}
}

func TestTTL(t *testing.T) {
	day := 24 * time.Hour
	tests := []struct {
		name       string
		registered time.Time
		err        error
		want       time.Duration
	}{
		{"old", fakeNow.Add(-youngAge), nil, oldTTL},
		{"young, far from 90 days", fakeNow.Add(-day), nil, youngMaxTTL},
		{"young, hours from 90 days", fakeNow.Add(-youngAge + 5*time.Hour), nil, 5 * time.Hour},
		{"young, minutes from 90 days", fakeNow.Add(-youngAge + time.Minute), nil, youngMinTTL},
		{"unsupported", time.Time{}, ErrUnsupported, unsupportedTTL},
		{"not found", time.Time{}, ErrNotFound, failureTTL},
	}
	for _, tt := range tests {
		if got := ttl(fakeNow, tt.registered, tt.err); got != tt.want {
			t.Errorf("%s: ttl = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestAges_NegativeCaching(t *testing.T) {
	clock := &fakeClock{now: fakeNow}
	s := newRDAPServer(t, []string{"test"}, func(w http.ResponseWriter, domain string) {
		http.NotFound(w, nil)
	})
	a := newAges(s, clock, "")

	for range 3 {
		if _, ok := a.Age(t.Context(), "gone.test"); ok {
			t.Fatal("Age of missing domain ok")
		}
	}
	if n := s.domainHits.Load(); n != 1 {
		t.Errorf("missing domain looked up %d times, want 1", n)
	}

	clock.Advance(failureTTL)
	a.Age(t.Context(), "gone.test")
	if n := s.domainHits.Load(); n != 2 {
		t.Errorf("missing domain looked up %d times after negative TTL, want 2", n)
	}

	// Unsupported TLDs are cached too, without any request.
	for range 2 {
		if _, ok := a.Age(t.Context(), "example.sh"); ok {
			t.Error("Age of unsupported TLD ok")
		}
	}
	if n := s.domainHits.Load(); n != 2 {
		t.Errorf("unsupported TLD caused requests: %d", n)
	}
	a.mu.Lock()
	e := a.entries["example.sh"]
	a.mu.Unlock()
	if got := e.Expires.Sub(e.Checked); got != unsupportedTTL {
		t.Errorf("unsupported TLD cached for %v, want %v", got, unsupportedTTL)
	}
}

func TestAges_Singleflight(t *testing.T) {
	clock := &fakeClock{now: fakeNow}
	release := make(chan struct{})
	s := newRDAPServer(t, []string{"test"}, func(w http.ResponseWriter, domain string) {
		<-release
		registeredAt(fakeNow.Add(-time.Hour))(w, domain)
	})
	a := newAges(s, clock, "")
	a.Timeout = 10 * time.Second

	var wg sync.WaitGroup
	var okCount atomic.Int64
	for range 20 {
		wg.Go(func() {
			if _, ok := a.Age(context.Background(), "popular.test"); ok {
				okCount.Add(1)
			}
		})
	}

	// Let the callers pile up on the in-flight lookup, then answer once.
	for s.domainHits.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	time.Sleep(20 * time.Millisecond)
	close(release)
	wg.Wait()

	if n := s.domainHits.Load(); n != 1 {
		t.Errorf("concurrent lookups made %d requests, want 1", n)
	}
	if n := okCount.Load(); n != 20 {
		t.Errorf("%d of 20 callers got an age", n)
	}
}

func TestAges_CallerCancellationDoesNotFailLookup(t *testing.T) {
	clock := &fakeClock{now: fakeNow}
	release := make(chan struct{})
	s := newRDAPServer(t, []string{"test"}, func(w http.ResponseWriter, domain string) {
		<-release
		registeredAt(fakeNow.Add(-time.Hour))(w, domain)
	})
	a := newAges(s, clock, "")
	a.Timeout = 10 * time.Second

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan bool)
	go func() {
		_, ok := a.Age(ctx, "slow.test")
		done <- ok
	}()
	for s.domainHits.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	cancel()
	if <-done {
		t.Error("canceled Age reported ok")
	}

	close(release)
	// The lookup completes in the background and is cached.
	deadline := time.Now().Add(5 * time.Second)
	for {
		a.mu.Lock()
		_, cached := a.entries["slow.test"]
		a.mu.Unlock()
		if cached {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("lookup not cached after caller canceled")
		}
		time.Sleep(time.Millisecond)
	}
	if _, ok := a.Age(t.Context(), "slow.test"); !ok {
		t.Error("Age after background lookup not ok")
	}
}

func TestAges_Timeout(t *testing.T) {
	clock := &fakeClock{now: fakeNow}
	release := make(chan struct{})
	defer close(release)
	s := newRDAPServer(t, []string{"test"}, func(w http.ResponseWriter, domain string) {
		select {
		case <-release:
		case <-time.After(5 * time.Second):
		}
	})
	a := newAges(s, clock, "")
	a.Timeout = 50 * time.Millisecond

	start := time.Now()
	if _, ok := a.Age(t.Context(), "hang.test"); ok {
		t.Error("Age of hanging lookup ok")
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("Age took %v, want about the timeout", d)
	}
}

func TestAges_RateLimitBackoff(t *testing.T) {
	clock := &fakeClock{now: fakeNow}
	var limited atomic.Bool
	limited.Store(true)
	s := newRDAPServer(t, []string{"test"}, func(w http.ResponseWriter, domain string) {
		if limited.Load() {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		registeredAt(fakeNow.Add(-time.Hour))(w, domain)
	})
	a := newAges(s, clock, "")

	if _, ok := a.Age(t.Context(), "a.test"); ok {
		t.Fatal("rate limited Age ok")
	}
	// Other domains on the same server aren't looked up while backing off.
	for _, d := range []string{"a.test", "b.test", "c.test"} {
		if _, ok := a.Age(t.Context(), d); ok {
			t.Errorf("Age(%s) ok while backing off", d)
		}
	}
	if n := s.domainHits.Load(); n != 1 {
		t.Errorf("%d requests while backing off, want 1", n)
	}

	limited.Store(false)
	clock.Advance(rateLimitBackoff)
	if _, ok := a.Age(t.Context(), "b.test"); !ok {
		t.Error("Age after backoff not ok")
	}
}

func TestAges_Persistence(t *testing.T) {
	clock := &fakeClock{now: fakeNow}
	when := fakeNow.Add(-10 * 24 * time.Hour)
	s := newRDAPServer(t, []string{"test"}, registeredAt(when))
	path := filepath.Join(t.TempDir(), "sub", "rdap.json")

	a := newAges(s, clock, path)
	if _, ok := a.Age(t.Context(), "kept.test"); !ok {
		t.Fatal("Age not ok")
	}
	// The first lookup saves immediately.
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("cache mode = %v, want 0600", perm)
	}

	// Later lookups within a minute aren't saved until Save.
	a.Age(t.Context(), "later.test")
	if err := a.Save(); err != nil {
		t.Fatal(err)
	}

	hits := s.domainHits.Load()
	b := newAges(s, clock, path)
	for _, d := range []string{"kept.test", "later.test"} {
		if age, ok := b.Age(t.Context(), d); !ok || age != clock.Now().Sub(when) {
			t.Errorf("reloaded Age(%s) = %v, %v", d, age, ok)
		}
	}
	if n := s.domainHits.Load(); n != hits {
		t.Errorf("reloaded cache made %d requests, want 0", n-hits)
	}

	// Expired entries aren't loaded.
	clock.Advance(youngMaxTTL)
	c := newAges(s, clock, path)
	c.Age(t.Context(), "kept.test")
	if n := s.domainHits.Load(); n != hits+1 {
		t.Errorf("expired persisted entry was used: %d requests, want 1", n-hits)
	}

	matches, _ := filepath.Glob(filepath.Join(filepath.Dir(path), "*.tmp"))
	if len(matches) > 0 {
		t.Errorf("temporary files left behind: %v", matches)
	}
}

func TestAges_CorruptCacheIgnored(t *testing.T) {
	clock := &fakeClock{now: fakeNow}
	s := newRDAPServer(t, []string{"test"}, registeredAt(fakeNow.Add(-time.Hour)))

	for name, content := range map[string]string{
		"garbage":       "{not json",
		"wrong version": `{"version":99,"entries":{"x.test":{"registered":"2020-01-01T00:00:00Z","expires":"2999-01-01T00:00:00Z"}}}`,
		"bad domain":    `{"version":1,"entries":{"../x":{"registered":"2020-01-01T00:00:00Z","checked":"2026-11-01T00:00:00Z","expires":"2999-01-01T00:00:00Z"}}}`,
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "rdap.json")
			if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			a := newAges(s, clock, path)
			if _, ok := a.Age(t.Context(), "x.test"); !ok {
				t.Error("Age with corrupt cache not ok")
			}
			a.mu.Lock()
			_, bad := a.entries["../x"]
			a.mu.Unlock()
			if bad {
				t.Error("invalid domain loaded from cache")
			}
		})
	}
}

func TestAges_Eviction(t *testing.T) {
	clock := &fakeClock{now: fakeNow}
	s := newRDAPServer(t, []string{"test"}, registeredAt(fakeNow.Add(-time.Hour)))
	a := newAges(s, clock, "")
	a.maxEntries = 10

	for i := range 25 {
		clock.Advance(time.Second)
		a.Age(t.Context(), string(rune('a'+i))+".test")
	}

	a.mu.Lock()
	n := len(a.entries)
	_, newest := a.entries["y.test"]
	_, oldest := a.entries["a.test"]
	a.mu.Unlock()

	if n > 10 {
		t.Errorf("%d entries, want at most 10", n)
	}
	if !newest || oldest {
		t.Errorf("eviction kept oldest (%v) or dropped newest (%v)", oldest, !newest)
	}
}

func TestAges_InvalidDomain(t *testing.T) {
	a := &Ages{Client: &Client{BootstrapURL: "http://127.0.0.1:1/never"}}
	if _, ok := a.Age(t.Context(), "bad/domain"); ok {
		t.Error("Age of invalid domain ok")
	}
	if err := a.Save(); err != nil {
		t.Errorf("Save without path = %v", err)
	}
}
