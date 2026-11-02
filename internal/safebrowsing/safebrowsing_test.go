package safebrowsing

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"
	"testing/synctest"
	"time"
)

const testKey = "test-key-AIzaSyNOTREAL"

func newChecker(t *testing.T, api *fakeAPI) *Checker {
	t.Helper()
	c, err := New(Options{Key: testKey, Client: &http.Client{Transport: api}})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestRice(t *testing.T) {
	// Worked by hand: 10, then differences 5 (quotient 1, remainder 1:
	// bits 1 0 1 0) and 3 (quotient 0, remainder 3: bits 0 1 1), read from
	// the least significant bit: 0b1100101.
	got, err := riceDeltas{first: 10, k: 2, entries: 2, data: []byte{0b1100101}}.decode()
	if err != nil || !slices.Equal(got, []uint32{10, 15, 18}) {
		t.Errorf("decode = %v, %v; want [10 15 18]", got, err)
	}

	// A single value is just the first.
	if got, err := (riceDeltas{first: 7}).decode(); err != nil || !slices.Equal(got, []uint32{7}) {
		t.Errorf("decode(single) = %v, %v", got, err)
	}

	// Round trips through the test encoder.
	values := []uint32{0, 1, 2, 1000, 1 << 20, 1<<31 + 5, 1<<32 - 1}
	r, err := parseRice(encodeRice(values, 0))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := r.decode(); err != nil || !slices.Equal(got, values) {
		t.Errorf("round trip = %v, %v", got, err)
	}

	// Malformed encodings fail rather than misread.
	for name, bad := range map[string]riceDeltas{
		"truncated":       {first: 1, k: 2, entries: 3, data: []byte{0b1100101}},
		"no parameter":    {first: 1, k: 0, entries: 1, data: []byte{1}},
		"huge parameter":  {first: 1, k: 40, entries: 1, data: []byte{1, 2, 3, 4, 5, 6}},
		"negative count":  {first: 1, k: 2, entries: -1, data: []byte{1}},
		"overflow":        {first: 1<<32 - 1, k: 2, entries: 1, data: []byte{0b100}},
		"too many values": {first: 1, k: 2, entries: maxEntries, data: []byte{1}},
	} {
		if got, err := bad.decode(); err == nil {
			t.Errorf("%s: decode = %v, want an error", name, got)
		}
	}
}

func TestPrefixList_Apply(t *testing.T) {
	sum := func(p ...uint32) []byte { return (&prefixList{prefixes: p}).checksum() }

	full, err := (*prefixList)(nil).apply(HashList{Version: []byte("v1"), Additions: []uint32{1, 5, 9}})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(full.prefixes, []uint32{1, 5, 9}) || string(full.version) != "v1" {
		t.Errorf("full = %+v", full)
	}

	// Removals by index, then additions, checked against the checksum.
	next, err := full.apply(HashList{Version: []byte("v2"), Partial: true, Removals: []uint32{1}, Additions: []uint32{3, 20}, Checksum: sum(1, 3, 9, 20)})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(next.prefixes, []uint32{1, 3, 9, 20}) {
		t.Errorf("partial = %v", next.prefixes)
	}
	if !slices.Equal(full.prefixes, []uint32{1, 5, 9}) {
		t.Error("apply changed the list it was applied to")
	}

	// Unchanged lists keep their prefixes.
	same, err := next.apply(HashList{Version: []byte("v3"), Partial: true})
	if err != nil || !slices.Equal(same.prefixes, next.prefixes) || string(same.version) != "v3" {
		t.Errorf("unchanged = %+v, %v", same, err)
	}

	for name, u := range map[string]HashList{
		"wrong checksum":         {Partial: true, Additions: []uint32{2}, Checksum: sum(1, 3, 9, 20)},
		"removal out of range":   {Partial: true, Removals: []uint32{4}},
		"removals in whole list": {Removals: []uint32{0}},
		"unsorted additions":     {Partial: true, Additions: []uint32{30, 25}},
	} {
		if got, err := next.apply(u); err == nil {
			t.Errorf("%s: apply = %v, want an error", name, got.prefixes)
		}
	}
	if _, err := (*prefixList)(nil).apply(HashList{Partial: true, Additions: []uint32{1}}); err == nil {
		t.Error("a partial update with no list applied")
	}
}

func TestExpressions(t *testing.T) {
	hosts := func(name string) []string {
		var hs []string
		for _, e := range expressions(name) {
			hs = append(hs, e.host)
			if e.hash != sha256.Sum256([]byte(e.host+"/")) {
				t.Errorf("%s: wrong hash", e.host)
			}
		}
		return hs
	}
	for name, want := range map[string][]string{
		"www.evil.example.com.":   {"www.evil.example.com", "evil.example.com", "example.com"},
		"A.B.C.D.E.F.G":           {"a.b.c.d.e.f.g", "c.d.e.f.g", "d.e.f.g", "e.f.g", "f.g"},
		"evil.example":            {"evil.example"},
		"com":                     nil,
		"":                        nil,
		"b.c.d.e.f.example.co.uk": {"b.c.d.e.f.example.co.uk", "e.f.example.co.uk", "f.example.co.uk", "example.co.uk", "co.uk"},
	} {
		if got := hosts(name); !slices.Equal(got, want) {
			t.Errorf("expressions(%q) = %q, want %q", name, got, want)
		}
	}
}

func TestChecker(t *testing.T) {
	ctx := t.Context()
	api := newFakeAPI(testKey)
	api.listHost("se-4b", "phish.example", SocialEngineering)
	api.listHost("mw-4b", "malware.example", Malware)
	api.listHost("se-4b", "canary.example", SocialEngineering, 1) // CANARY: not enforced
	api.publish("uws-4b")
	c := newChecker(t, api)

	// Nothing matches before the lists are fetched, and nothing is sent.
	if _, ok, err := c.Lookup(ctx, "phish.example"); ok || err != nil {
		t.Errorf("Lookup before an update = %v, %v", ok, err)
	}
	if n := api.count("/v5/hashes:search"); n != 0 {
		t.Errorf("%d searches before the lists were fetched", n)
	}

	wait, err := c.Update(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if wait != 30*time.Minute {
		t.Errorf("Update wait = %v, want the server's 30m", wait)
	}
	if st := c.Status(); st.Prefixes["se-4b"] != 2 || st.Prefixes["mw-4b"] != 1 || st.Prefixes["uws-4b"] != 0 {
		t.Errorf("Status = %+v", st)
	}

	// The key travels in a header, never in the URL.
	req := api.last("/v5/hashLists:batchGet")
	if strings.Contains(req.URL.String(), testKey) || req.Header.Get("X-Goog-Api-Key") != testKey {
		t.Errorf("the key was sent as %q in %s", req.Header.Get("X-Goog-Api-Key"), req.URL)
	}
	if got := req.URL.Query()["names"]; !slices.Equal(got, DefaultLists) || req.URL.Query().Has("version") {
		t.Errorf("first update asked for %q with versions %q", got, req.URL.Query()["version"])
	}

	// A name not on the local lists is answered locally.
	if _, ok, err := c.Lookup(ctx, "www.example.org"); ok || err != nil {
		t.Errorf("Lookup(clean) = %v, %v", ok, err)
	}
	if n := api.count("/v5/hashes:search"); n != 0 {
		t.Errorf("a clean name was sent to the API (%d searches)", n)
	}

	// A listed name, and subdomains of it, match, sending only 4-byte
	// prefixes.
	threat, ok, err := c.Lookup(ctx, "login.phish.example")
	if err != nil || !ok || threat.Host != "phish.example" || !slices.Equal(threat.Types, []ThreatType{SocialEngineering}) {
		t.Fatalf("Lookup(listed) = %+v, %v, %v", threat, ok, err)
	}
	if want := "phish.example is listed by Google Safe Browsing for phishing or social engineering"; threat.String() != want {
		t.Errorf("String = %q, want %q", threat.String(), want)
	}
	search := api.last("/v5/hashes:search")
	for _, p := range search.URL.Query()["hashPrefixes"] {
		if b, err := base64.StdEncoding.DecodeString(p); err != nil || len(b) != 4 {
			t.Errorf("sent hash prefix %q, want 4 bytes", p)
		}
	}
	if strings.Contains(search.URL.String(), "phish") || strings.Contains(search.URL.String(), testKey) {
		t.Errorf("the search request revealed the name or key: %s", search.URL)
	}

	// The result is cached for the server's duration.
	if _, ok, _ := c.Lookup(ctx, "phish.example"); !ok {
		t.Error("cached match lost")
	}
	if n := api.count("/v5/hashes:search"); n != 1 {
		t.Errorf("%d searches, want the cached result used", n)
	}

	// Canary matches aren't enforced.
	if _, ok, err := c.Lookup(ctx, "canary.example"); ok || err != nil {
		t.Errorf("Lookup(canary) = %v, %v", ok, err)
	}

	if threat, ok, _ := c.Lookup(ctx, "malware.example"); !ok || threat.Types[0] != Malware {
		t.Errorf("Lookup(malware) = %+v, %v", threat, ok)
	}

	// The next update sends the versions and applies a partial update.
	api.listHost("se-4b", "newphish.example", SocialEngineering)
	if _, err := c.Update(ctx); err != nil {
		t.Fatal(err)
	}
	if v := api.last("/v5/hashLists:batchGet").URL.Query()["version"]; len(v) != 3 || v[0] == "" {
		t.Errorf("second update sent versions %q", v)
	}
	if _, ok, _ := c.Lookup(ctx, "newphish.example"); !ok {
		t.Error("a name added by a partial update didn't match")
	}

	// A list that fails its checksum is dropped, to be fetched whole.
	api.listHost("se-4b", "another.example", SocialEngineering)
	api.badSum = true
	if _, err := c.Update(ctx); !errors.Is(err, errChecksum) {
		t.Errorf("Update with a bad checksum = %v", err)
	}
	if st := c.Status(); st.Prefixes["se-4b"] != 0 || st.Prefixes["mw-4b"] != 1 {
		t.Errorf("after a bad checksum, Status = %+v", st)
	}
	api.badSum = false
	if _, err := c.Update(ctx); err != nil {
		t.Fatal(err)
	}
	if st := c.Status(); st.Prefixes["se-4b"] != 4 {
		t.Errorf("after a full refetch, Status = %+v", st)
	}
}

func TestChecker_FailsOpen(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx := context.Background()
		api := newFakeAPI(testKey)
		api.listHost("se-4b", "phish.example", SocialEngineering)
		c := newChecker(t, api)
		if _, err := c.Update(ctx); err != nil {
			t.Fatal(err)
		}

		api.mu.Lock()
		api.fail = true
		api.mu.Unlock()
		_, ok, err := c.Lookup(ctx, "phish.example")
		if ok || err == nil {
			t.Fatalf("Lookup with the API down = %v, %v; want no match and an error", ok, err)
		}
		if strings.Contains(err.Error(), testKey) {
			t.Errorf("error reveals the key: %v", err)
		}

		// While backing off, no requests are made.
		for range 5 {
			c.Lookup(ctx, "phish.example")
		}
		if n := api.count("/v5/hashes:search"); n != 1 {
			t.Errorf("%d searches while backing off, want 1", n)
		}

		// After the backoff, it tries again and recovers.
		api.mu.Lock()
		api.fail = false
		api.mu.Unlock()
		time.Sleep(backoffMin)
		if _, ok, err := c.Lookup(ctx, "phish.example"); !ok || err != nil {
			t.Errorf("Lookup after the backoff = %v, %v", ok, err)
		}
	})
}

func TestChecker_CacheExpires(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx := context.Background()
		api := newFakeAPI(testKey)
		api.cache = 10 * time.Minute
		api.listHost("se-4b", "phish.example", SocialEngineering)
		c := newChecker(t, api)
		if _, err := c.Update(ctx); err != nil {
			t.Fatal(err)
		}

		// Results are kept for the server's cache duration, then asked for
		// again.
		c.Lookup(ctx, "phish.example")
		time.Sleep(9 * time.Minute)
		c.Lookup(ctx, "phish.example")
		if n := api.count("/v5/hashes:search"); n != 1 {
			t.Errorf("%d searches within the cache duration, want 1", n)
		}
		time.Sleep(2 * time.Minute)
		c.Lookup(ctx, "phish.example")
		if n := api.count("/v5/hashes:search"); n != 2 {
			t.Errorf("%d searches after the cache expired, want 2", n)
		}
	})
}

func TestChecker_Run(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		api := newFakeAPI(testKey)
		api.minWait = 30 * time.Minute
		api.listHost("se-4b", "phish.example", SocialEngineering)
		c := newChecker(t, api)

		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() {
			defer close(done)
			c.Run(ctx)
		}()

		synctest.Wait()
		if n := api.count("/v5/hashLists:batchGet"); n != 1 {
			t.Errorf("%d updates at start, want 1", n)
		}
		// The server's minimum wait is honored.
		time.Sleep(29 * time.Minute)
		synctest.Wait()
		if n := api.count("/v5/hashLists:batchGet"); n != 1 {
			t.Errorf("%d updates before the minimum wait, want 1", n)
		}
		time.Sleep(2 * time.Minute)
		synctest.Wait()
		if n := api.count("/v5/hashLists:batchGet"); n != 2 {
			t.Errorf("%d updates after the minimum wait, want 2", n)
		}

		// Failures back off exponentially.
		api.mu.Lock()
		api.fail = true
		api.mu.Unlock()
		time.Sleep(30 * time.Minute)
		synctest.Wait()
		before := api.count("/v5/hashLists:batchGet")
		time.Sleep(4 * time.Hour)
		synctest.Wait()
		// Backoffs of at least 0.5, 1, 2, and 4 minutes, and so on,
		// doubling: about 8 attempts in 4 hours, not 240.
		if n := api.count("/v5/hashLists:batchGet") - before; n > 12 || n < 3 {
			t.Errorf("%d updates in 4 hours of failures, want a handful", n)
		}

		cancel()
		<-done
	})
}

// TestChecker_PrefixCollision checks that a name whose hash shares only
// its prefix with a listed hash isn't flagged: the full hash decides.
func TestChecker_PrefixCollision(t *testing.T) {
	ctx := t.Context()
	api := newFakeAPI(testKey)
	h := api.listHost("se-4b", "innocent.example", SocialEngineering)
	// Replace the listed hash with another sharing its prefix.
	api.mu.Lock()
	msg := api.full[h]
	delete(api.full, h)
	other := h
	other[31] ^= 0xff
	api.full[other] = []byte(strings.Replace(string(msg), string(h[:]), string(other[:]), 1))
	api.mu.Unlock()

	c := newChecker(t, api)
	if _, err := c.Update(ctx); err != nil {
		t.Fatal(err)
	}
	if threat, ok, err := c.Lookup(ctx, "innocent.example"); ok || err != nil {
		t.Errorf("Lookup on a prefix collision = %+v, %v, %v; want no match", threat, ok, err)
	}
	if n := api.count("/v5/hashes:search"); n != 1 {
		t.Errorf("%d searches, want the prefix confirmed once", n)
	}
}

func TestNew(t *testing.T) {
	if _, err := New(Options{}); err == nil {
		t.Error("New without a key succeeded")
	}
}

func FuzzParseBatch(f *testing.F) {
	api := newFakeAPI(testKey)
	api.listHost("se-4b", "phish.example", SocialEngineering)
	api.listHost("se-4b", "other.example", Malware)
	f.Add(appendBytesField(nil, 1, api.hashList("se-4b", api.versions["se-4b"], -1)))
	f.Add(appendBytesField(nil, 1, api.hashList("se-4b", api.versions["se-4b"], 0)))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, msg []byte) {
		lists, err := parseBatch(msg)
		if err != nil {
			return
		}
		for _, l := range lists {
			if !slices.IsSorted(l.Additions) || !slices.IsSorted(l.Removals) {
				t.Fatalf("unsorted values: %+v", l)
			}
			if _, err := (&prefixList{prefixes: []uint32{1, 2, 3}}).apply(l); err != nil {
				continue
			}
		}
	})
}

func FuzzParseSearch(f *testing.F) {
	api := newFakeAPI(testKey)
	h := api.listHost("se-4b", "phish.example", SocialEngineering)
	var msg []byte
	msg = appendBytesField(msg, 1, api.full[h])
	msg = appendBytesField(msg, 2, encodeDuration(time.Minute))
	f.Add(msg)
	f.Add([]byte{0x0a, 0x00})
	f.Fuzz(func(t *testing.T, msg []byte) {
		r, err := parseSearch(msg)
		if err != nil {
			return
		}
		for _, h := range r.hashes {
			for _, tt := range h.Threats {
				if tt < Malware || tt > PotentiallyHarmfulApplication {
					t.Fatalf("unknown threat type %d kept", tt)
				}
			}
		}
		if r.cache < 0 {
			t.Fatalf("negative cache duration %v", r.cache)
		}
	})
}

func BenchmarkLookup(b *testing.B) {
	api := newFakeAPI(testKey)
	api.listHost("se-4b", "phish.example", SocialEngineering)
	c, _ := New(Options{Key: testKey, Client: &http.Client{Transport: api}})
	if _, err := c.Update(context.Background()); err != nil {
		b.Fatal(err)
	}
	for _, name := range []string{"www.example.com", "phish.example"} {
		c.Lookup(context.Background(), name) // fill the cache
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				c.Lookup(context.Background(), name)
			}
		})
	}
}
