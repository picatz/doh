package blocklist

import (
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

// fakeLists serves lists from memory, by URL, honoring If-None-Match, and
// counts full and conditional responses. It's an http.RoundTripper, so
// tests in a synctest bubble never touch the network.
type fakeLists struct {
	mu          sync.Mutex
	bodies      map[string]string
	etags       map[string]string
	full        map[string]int
	notModified map[string]int
	down        bool
}

func newFakeLists() *fakeLists {
	return &fakeLists{bodies: map[string]string{}, etags: map[string]string{}, full: map[string]int{}, notModified: map[string]int{}}
}

func (f *fakeLists) set(url, body, etag string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.bodies[url], f.etags[url] = body, etag
}

func (f *fakeLists) counts(url string) (full, notModified int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.full[url], f.notModified[url]
}

func (f *fakeLists) RoundTrip(r *http.Request) (*http.Response, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	url := r.URL.String()
	resp := &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: http.NoBody, Request: r}
	switch etag := f.etags[url]; {
	case f.down:
		resp.StatusCode = http.StatusServiceUnavailable
	case etag != "" && r.Header.Get("If-None-Match") == etag:
		f.notModified[url]++
		resp.StatusCode = http.StatusNotModified
	default:
		f.full[url]++
		resp.Header.Set("ETag", etag)
		resp.Body = io.NopCloser(strings.NewReader(f.bodies[url]))
	}
	return resp, nil
}

func TestRefreshSchedule_Interval(t *testing.T) {
	threat := Source{Name: ThreatIntelPreset, Location: Presets[ThreatIntelPreset]}
	renamed := Source{Name: "mine", Location: Presets["scams"]} // a preset under another name
	privacy := Source{Name: DefaultPreset, Location: Presets[DefaultPreset]}
	parental := Source{Name: "gambling", Location: Presets["gambling"]}
	custom := Source{Name: "custom", Location: "https://lists.example/block.txt"}

	def := DefaultRefreshSchedule()
	for src, want := range map[Source]time.Duration{
		threat: 2 * time.Hour, renamed: 2 * time.Hour, privacy: 24 * time.Hour, parental: 24 * time.Hour, custom: 24 * time.Hour,
	} {
		if got := def.Interval(src); got != want {
			t.Errorf("default Interval(%s) = %v, want %v", src.Name, got, want)
		}
	}

	s := RefreshSchedule{Every: 6 * time.Hour, Categories: map[string]time.Duration{CategoryParental: time.Hour, CategorySecurity: 0}}
	for src, want := range map[Source]time.Duration{threat: 6 * time.Hour, parental: time.Hour, custom: 6 * time.Hour} {
		if got := s.Interval(src); got != want {
			t.Errorf("Interval(%s) = %v, want %v", src.Name, got, want)
		}
	}
	if got := (RefreshSchedule{}).Interval(custom); got != DefaultRefresh {
		t.Errorf("zero schedule Interval = %v, want %v", got, DefaultRefresh)
	}

	// Jitter stays within its fraction, either way, and is clamped to half.
	now := time.Now()
	for _, j := range []float64{0.1, 0.9, -1} {
		s := RefreshSchedule{Every: time.Hour, Jitter: j}
		lo, hi := time.Hour-time.Duration(min(max(j, 0), 0.5)*float64(time.Hour)), time.Hour+time.Duration(min(max(j, 0), 0.5)*float64(time.Hour))
		for range 1000 {
			if d := s.next(custom, now).Sub(now); d < lo || d > hi {
				t.Fatalf("jitter %v: next in %v, want within [%v, %v]", j, d, lo, hi)
			}
		}
	}
}

func TestRegistry_Refresh(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		lists := newFakeLists()
		threatURL, adsURL := Presets[ThreatIntelPreset], Presets[DefaultPreset]
		lists.set(threatURL, "||malware.example^\n", `"t1"`)
		lists.set(adsURL, "||ads.example^\n", `"a1"`)
		threat := Source{Name: ThreatIntelPreset, Location: threatURL}
		ads := Source{Name: DefaultPreset, Location: adsURL}

		// No cache directory: validators are kept in memory.
		r := NewRegistry(&Loader{Client: &http.Client{Transport: lists}}, nil)
		defer r.Close()
		r.Sync([]Source{threat, ads})
		if err := r.Wait(t.Context(), threat, ads); err != nil {
			t.Fatal(err)
		}
		first := r.List(threat)

		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		done := make(chan struct{})
		go func() {
			defer close(done)
			_ = r.Refresh(ctx, RefreshSchedule{Every: 24 * time.Hour, Categories: map[string]time.Duration{CategorySecurity: 2 * time.Hour}, Jitter: 0.1})
		}()
		synctest.Wait()

		// Checks are scheduled within the jitter of each category's interval.
		for _, st := range r.Status() {
			want := 24 * time.Hour
			if st.Category == CategorySecurity {
				want = 2 * time.Hour
			}
			if d := time.Until(st.Next); d < want*9/10 || d > want*11/10 {
				t.Errorf("%s: next check in %v, want %v ± 10%%", st.Name, d, want)
			}
		}

		// After one security interval, the threat list was checked with a
		// conditional request, and kept without being parsed again; the
		// ads list wasn't checked at all.
		time.Sleep(2*time.Hour*11/10 + time.Minute)
		synctest.Wait()
		if full, nm := lists.counts(threatURL); full != 1 || nm != 1 {
			t.Errorf("threat list: %d downloads and %d not modified, want 1 and 1", full, nm)
		}
		if full, nm := lists.counts(adsURL); full != 1 || nm != 0 {
			t.Errorf("ads list: %d downloads and %d not modified, want 1 and 0", full, nm)
		}
		if r.List(threat) != first {
			t.Error("an unchanged list was rebuilt")
		}

		// A change is picked up at the next check.
		lists.set(threatURL, "||malware.example^\n||phish.example^\n", `"t2"`)
		time.Sleep(2*time.Hour*11/10 + time.Minute)
		synctest.Wait()
		if _, ok := r.List(threat).Block("login.phish.example"); !ok {
			t.Error("the changed threat list wasn't reloaded")
		}

		// Failures keep the rules and stay on schedule.
		lists.mu.Lock()
		lists.down = true
		lists.mu.Unlock()
		time.Sleep(2*time.Hour*11/10 + time.Minute)
		synctest.Wait()
		if r.Err(threat) == nil {
			t.Error("a failed check wasn't recorded")
		}
		if _, ok := r.List(threat).Block("phish.example"); !ok {
			t.Error("a failed check dropped the rules")
		}
		lists.mu.Lock()
		lists.down = false
		lists.mu.Unlock()
		time.Sleep(2*time.Hour*11/10 + time.Minute)
		synctest.Wait()
		if r.Err(threat) != nil {
			t.Errorf("the list didn't recover on schedule: %v", r.Err(threat))
		}

		// By a day, the ads list has been checked once, conditionally.
		time.Sleep(24*time.Hour*11/10 - 4*(2*time.Hour*11/10+time.Minute))
		synctest.Wait()
		if full, nm := lists.counts(adsURL); full != 1 || nm != 1 {
			t.Errorf("ads list after a day: %d downloads and %d not modified, want 1 and 1", full, nm)
		}

		// A list added while refreshing gets its own schedule.
		added := Source{Name: "scams", Location: Presets["scams"]}
		lists.set(added.Location, "||fake.example^\n", `"s1"`)
		r.Sync([]Source{threat, ads, added})
		if err := r.Wait(t.Context(), added); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		time.Sleep(2*time.Hour*11/10 + time.Minute)
		synctest.Wait()
		if full, nm := lists.counts(added.Location); full != 1 || nm < 1 {
			t.Errorf("added list: %d downloads and %d not modified, want 1 and at least 1", full, nm)
		}

		cancel()
		<-done
	})
}

func TestLoader_ReloadUnchanged(t *testing.T) {
	server := newListServer(t, "||ads.example.com^\n")
	src := Source{Name: "remote", Location: server.URL}

	for _, cacheDir := range []string{"", filepath.Join(t.TempDir(), "cache")} {
		server.full.Store(0)
		server.notModified.Store(0)
		l := &Loader{Client: server.Client(), CacheDir: cacheDir}

		list, v, err := l.reloadSource(t.Context(), src, nil)
		if err != nil || list == nil || v == nil || v.ETag != `"v1"` {
			t.Fatalf("cache %q: first load = %v, %+v, %v", cacheDir, list, v, err)
		}
		again, v2, err := l.reloadSource(t.Context(), src, v)
		if err != nil || again != nil || v2 != v {
			t.Errorf("cache %q: reload of an unchanged list = %v, %+v, %v; want nil and the same version", cacheDir, again, v2, err)
		}
		if server.full.Load() != 1 || server.notModified.Load() != 1 {
			t.Errorf("cache %q: %d downloads and %d not modified, want 1 and 1", cacheDir, server.full.Load(), server.notModified.Load())
		}

		// Another version, such as one a different process cached, is
		// loaded rather than mistaken for the caller's.
		other := &Version{ETag: `"v0"`}
		if list, _, err := l.reloadSource(t.Context(), src, other); err != nil || list == nil {
			t.Errorf("cache %q: reload with a stale version = %v, %v; want the list", cacheDir, list, err)
		}
	}
}

func TestLoader_ReloadUnchangedFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "list.txt")
	write := func(s string) {
		if err := os.WriteFile(path, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("||a.example^\n")
	src := Source{Name: "file", Location: path}
	l := &Loader{}

	_, v, err := l.reloadSource(t.Context(), src, nil)
	if err != nil {
		t.Fatal(err)
	}
	if list, _, err := l.reloadSource(t.Context(), src, v); err != nil || list != nil {
		t.Errorf("unchanged file reloaded: %v, %v", list, err)
	}
	write("||a.example^\n||b.example^\n")
	if list, _, err := l.reloadSource(t.Context(), src, v); err != nil || list == nil || list.Len() != 2 {
		t.Errorf("changed file = %v, %v; want 2 rules", list, err)
	}
}
