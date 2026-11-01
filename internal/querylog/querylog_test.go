package querylog

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// clock is a settable fake time source.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock(t time.Time) *clock { return &clock{t: t} }

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) Set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = t
}

func open(t *testing.T, opts Options) *Log {
	t.Helper()
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.NewTextHandler(t.Output(), nil))
	}
	l, err := Open(opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l
}

func ids(entries []Entry) []uint64 {
	var out []uint64
	for _, e := range entries {
		out = append(out, e.ID)
	}
	return out
}

var t0 = time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)

func TestAppendQueryOrder(t *testing.T) {
	c := newClock(t0)
	l := open(t, Options{Memory: 10, Now: c.Now})

	for i := range 3 {
		e := l.Append(Entry{Name: fmt.Sprintf("n%d.example", i), Status: StatusAllowed})
		if e.ID != uint64(i+1) {
			t.Fatalf("ID = %d, want %d", e.ID, i+1)
		}
		if !e.Time.Equal(t0) {
			t.Fatalf("Time = %v, want %v", e.Time, t0)
		}
	}

	explicit := t0.Add(-time.Hour)
	if e := l.Append(Entry{Time: explicit}); !e.Time.Equal(explicit) {
		t.Fatalf("explicit time overwritten: %v", e.Time)
	}

	page := l.Query(Filter{})
	if got, want := ids(page.Entries), []uint64{4, 3, 2, 1}; !slices.Equal(got, want) {
		t.Fatalf("IDs = %v, want %v", got, want)
	}
	if page.NextPageToken != "" {
		t.Fatalf("unexpected next page token")
	}
	if l.Len() != 4 {
		t.Fatalf("Len = %d", l.Len())
	}
}

func TestQueryEmptyIsNonNil(t *testing.T) {
	l := open(t, Options{})
	if page := l.Query(Filter{}); page.Entries == nil {
		t.Fatal("Entries is nil")
	}
}

func TestQueryReturnsCopies(t *testing.T) {
	l := open(t, Options{})
	l.Append(Entry{Answers: []string{"A 192.0.2.1"}})
	l.Query(Filter{}).Entries[0].Answers[0] = "mutated"
	if got := l.Query(Filter{}).Entries[0].Answers[0]; got != "A 192.0.2.1" {
		t.Fatalf("ring modified through query result: %q", got)
	}
}

func TestFilter(t *testing.T) {
	l := open(t, Options{})
	entries := []Entry{
		{Time: t0, Profile: "kids", Device: "tablet", Client: "192.0.2.10", Name: "ads.example.com", Status: StatusBlocked, Reason: "list"},
		{Time: t0.Add(time.Minute), Profile: "kids", Client: "192.0.2.11", Name: "www.Example.org", Status: StatusAllowed},
		{Time: t0.Add(2 * time.Minute), Profile: "default", Device: "laptop", Client: "192.0.2.12", Name: "new.example.net", Status: StatusBlocked, Reason: "newly-registered"},
		{Time: t0.Add(3 * time.Minute), Profile: "default", Client: "192.0.2.12", Name: "nas.home.arpa", Status: StatusRewritten, Reason: "rewrite"},
		{Time: t0.Add(4 * time.Minute), Name: "broken.example", Status: StatusError},
	}
	for _, e := range entries {
		l.Append(e)
	}

	tests := []struct {
		name string
		f    Filter
		want []uint64
	}{
		{"all", Filter{}, []uint64{5, 4, 3, 2, 1}},
		{"profile", Filter{Profile: "kids"}, []uint64{2, 1}},
		{"device", Filter{Device: "laptop"}, []uint64{3}},
		{"client", Filter{Client: "192.0.2.12"}, []uint64{4, 3}},
		{"status", Filter{Status: StatusBlocked}, []uint64{3, 1}},
		{"status error", Filter{Status: StatusError}, []uint64{5}},
		{"reason", Filter{Reason: "rewrite"}, []uint64{4}},
		{"search case-insensitive", Filter{Search: "EXAMPLE.org"}, []uint64{2}},
		{"search substring", Filter{Search: "example"}, []uint64{5, 3, 2, 1}},
		{"since inclusive", Filter{Since: t0.Add(3 * time.Minute)}, []uint64{5, 4}},
		{"until inclusive", Filter{Until: t0.Add(time.Minute)}, []uint64{2, 1}},
		{"since and until", Filter{Since: t0.Add(time.Minute), Until: t0.Add(2 * time.Minute)}, []uint64{3, 2}},
		{"combined", Filter{Profile: "default", Status: StatusBlocked}, []uint64{3}},
		{"no match", Filter{Profile: "nobody"}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ids(l.Query(tt.f).Entries); !slices.Equal(got, tt.want) {
				t.Fatalf("IDs = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPagination(t *testing.T) {
	l := open(t, Options{Memory: 100})
	for i := range 25 {
		status := StatusAllowed
		if i%2 == 0 {
			status = StatusBlocked
		}
		l.Append(Entry{Status: status})
	}

	var all []uint64
	f := Filter{Limit: 4, Status: StatusBlocked}
	for pages := 0; ; pages++ {
		if pages > 10 {
			t.Fatal("pagination doesn't terminate")
		}
		page := l.Query(f)
		if len(page.Entries) > 4 {
			t.Fatalf("page has %d entries", len(page.Entries))
		}
		all = append(all, ids(page.Entries)...)
		if page.NextPageToken == "" {
			break
		}
		f.PageToken = page.NextPageToken
	}

	want := []uint64{25, 23, 21, 19, 17, 15, 13, 11, 9, 7, 5, 3, 1}
	if !slices.Equal(all, want) {
		t.Fatalf("IDs = %v, want %v", all, want)
	}
}

func TestPaginationExactLimitHasNoNextPage(t *testing.T) {
	l := open(t, Options{})
	for range 4 {
		l.Append(Entry{})
	}
	if page := l.Query(Filter{Limit: 4}); page.NextPageToken != "" || len(page.Entries) != 4 {
		t.Fatalf("got %d entries, token %q", len(page.Entries), page.NextPageToken)
	}
}

func TestPaginationAcrossRingWrap(t *testing.T) {
	l := open(t, Options{Memory: 5})
	for range 12 {
		l.Append(Entry{})
	}

	if got, want := ids(l.Query(Filter{}).Entries), []uint64{12, 11, 10, 9, 8}; !slices.Equal(got, want) {
		t.Fatalf("IDs = %v, want %v", got, want)
	}

	page := l.Query(Filter{Limit: 2})
	if got := ids(page.Entries); !slices.Equal(got, []uint64{12, 11}) {
		t.Fatalf("first page = %v", got)
	}

	// The token references entries that are evicted by more appends; the
	// next page continues with whatever older entries remain.
	for range 2 {
		l.Append(Entry{})
	}
	page = l.Query(Filter{Limit: 10, PageToken: page.NextPageToken})
	if got, want := ids(page.Entries), []uint64{10}; !slices.Equal(got, want) {
		t.Fatalf("after wrap = %v, want %v", got, want)
	}

	// A token for an entry that's entirely evicted returns nothing older.
	page = l.Query(Filter{PageToken: encodeToken(3)})
	if len(page.Entries) != 0 {
		t.Fatalf("evicted token returned %v", ids(page.Entries))
	}
}

func TestLimitBounds(t *testing.T) {
	l := open(t, Options{Memory: 2000})
	for range 1500 {
		l.Append(Entry{})
	}
	if n := len(l.Query(Filter{}).Entries); n != DefaultLimit {
		t.Fatalf("default page = %d", n)
	}
	if n := len(l.Query(Filter{Limit: 5000}).Entries); n != MaxLimit {
		t.Fatalf("capped page = %d", n)
	}
}

func TestInvalidPageToken(t *testing.T) {
	l := open(t, Options{})
	l.Append(Entry{})

	for _, token := range []string{"!!!", "e30", encodeToken(0), "eyJ2IjoyLCJiIjo1fQ"} {
		if page := l.Query(Filter{PageToken: token}); len(page.Entries) != 0 {
			t.Errorf("token %q matched entries", token)
		}
		if _, err := ParseFilter(url.Values{"page_token": {token}}); err == nil {
			t.Errorf("ParseFilter accepted token %q", token)
		}
	}
}

func TestParseFilter(t *testing.T) {
	since := "2026-11-01T00:00:00Z"
	until := "2026-11-02T00:00:00Z"
	token := encodeToken(42)

	f, err := ParseFilter(url.Values{
		"profile": {"kids"}, "device": {"tablet"}, "client": {"192.0.2.1"},
		"status": {"blocked"}, "reason": {"list"}, "q": {"ads"},
		"since": {since}, "until": {until}, "limit": {"50"}, "page_token": {token},
	})
	if err != nil {
		t.Fatal(err)
	}

	want := Filter{
		Profile: "kids", Device: "tablet", Client: "192.0.2.1",
		Status: StatusBlocked, Reason: "list", Search: "ads",
		Since: time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC), Until: time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC),
		Limit: 50, PageToken: token,
	}
	if f != want {
		t.Fatalf("got %+v, want %+v", f, want)
	}

	if f, err := ParseFilter(url.Values{}); err != nil || f != (Filter{}) {
		t.Fatalf("empty: %+v, %v", f, err)
	}

	for _, v := range []url.Values{
		{"status": {"maybe"}},
		{"since": {"yesterday"}},
		{"until": {"2026-11-01"}},
		{"limit": {"0"}},
		{"limit": {"-1"}},
		{"limit": {"1001"}},
		{"limit": {"ten"}},
		{"page_token": {"garbage"}},
	} {
		if _, err := ParseFilter(v); err == nil {
			t.Errorf("ParseFilter(%v) succeeded", v)
		}
	}
}

func TestStats(t *testing.T) {
	l := open(t, Options{})
	add := func(n int, e Entry) {
		for range n {
			l.Append(e)
		}
	}
	add(3, Entry{Time: t0, Name: "b.example", Status: StatusBlocked, Reason: "list", Client: "192.0.2.1", Profile: "p"})
	add(3, Entry{Time: t0, Name: "a.example", Status: StatusBlocked, Reason: "rebinding", Client: "192.0.2.1", Device: "tv", Profile: "p"})
	add(1, Entry{Time: t0, Name: "c.example", Status: StatusBlocked, Reason: "list", Client: "192.0.2.2", Profile: "p"})
	add(5, Entry{Time: t0, Name: "ok.example", Status: StatusAllowed, Client: "192.0.2.2", Profile: "p"})
	add(2, Entry{Time: t0, Name: "nas.home.arpa", Status: StatusRewritten, Reason: "rewrite", Client: "192.0.2.3", Profile: "p"})
	add(1, Entry{Time: t0, Name: "x.example", Status: StatusError, Client: "192.0.2.3", Profile: "other"})

	s := l.Stats(Filter{Profile: "p"}, 2)

	if s.Total != 14 {
		t.Fatalf("Total = %d", s.Total)
	}
	if !s.Since.Equal(t0) {
		t.Fatalf("Since = %v", s.Since)
	}
	wantStatus := map[Status]int{StatusBlocked: 7, StatusAllowed: 5, StatusRewritten: 2}
	if fmt.Sprint(s.ByStatus) != fmt.Sprint(wantStatus) {
		t.Fatalf("ByStatus = %v", s.ByStatus)
	}
	wantReason := map[string]int{"list": 4, "rebinding": 3, "rewrite": 2}
	if fmt.Sprint(s.ByReason) != fmt.Sprint(wantReason) {
		t.Fatalf("ByReason = %v", s.ByReason)
	}
	// Ties broken by name ascending.
	if want := []Count{{"a.example", 3}, {"b.example", 3}}; !slices.Equal(s.TopBlocked, want) {
		t.Fatalf("TopBlocked = %v", s.TopBlocked)
	}
	if want := []Count{{"ok.example", 5}}; !slices.Equal(s.TopAllowed, want) {
		t.Fatalf("TopAllowed = %v", s.TopAllowed)
	}
	// Devices are named over addresses.
	if want := []Count{{"192.0.2.2", 6}, {"192.0.2.1", 3}}; !slices.Equal(s.TopClients, want) {
		t.Fatalf("TopClients = %v", s.TopClients)
	}

	if s := l.Stats(Filter{Profile: "none"}, 10); s.Total != 0 || !s.Since.IsZero() || s.TopBlocked == nil {
		t.Fatalf("empty stats = %+v", s)
	}
}

func TestSubscribe(t *testing.T) {
	l := open(t, Options{})
	ctx, cancel := context.WithCancel(t.Context())

	ch := l.Subscribe(ctx, Filter{Status: StatusBlocked, Limit: 1, Until: t0.Add(-time.Hour)})
	l.Append(Entry{Name: "allowed", Status: StatusAllowed})
	l.Append(Entry{Name: "blocked", Status: StatusBlocked})

	select {
	case e := <-ch:
		if e.Name != "blocked" || e.ID != 2 {
			t.Fatalf("got %+v", e)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no entry received")
	}

	cancel()
	waitClosed(t, ch)
}

func TestSubscribeClosedOnClose(t *testing.T) {
	l := open(t, Options{})
	ch := l.Subscribe(t.Context(), Filter{})
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	waitClosed(t, ch)

	// Subscribing to a closed log returns a closed channel.
	waitClosed(t, l.Subscribe(t.Context(), Filter{}))

	if err := l.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

func waitClosed(t *testing.T, ch <-chan Entry) {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		select {
		case _, ok := <-ch:
			if !ok {
				return
			}
		case <-deadline:
			t.Fatal("channel not closed")
		}
	}
}

func TestSlowSubscriberDoesNotBlock(t *testing.T) {
	l := open(t, Options{})
	ch := l.Subscribe(t.Context(), Filter{})

	done := make(chan struct{})
	go func() {
		defer close(done)
		for range subscriberBuffer * 4 {
			l.Append(Entry{})
		}
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Append blocked on a slow subscriber")
	}

	if n := len(ch); n != subscriberBuffer {
		t.Fatalf("buffered %d entries, want %d", n, subscriberBuffer)
	}
}

func TestFilesAndReload(t *testing.T) {
	dir := t.TempDir()
	c := newClock(time.Date(2026, 11, 1, 23, 0, 0, 0, time.FixedZone("x", -5*3600))) // 2026-11-02 04:00 UTC

	l := open(t, Options{Dir: dir, Now: c.Now})
	for i := range 3 {
		l.Append(Entry{Name: fmt.Sprintf("n%d.example", i), Status: StatusAllowed})
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(filepath.Join(dir, "2026-11-02.jsonl")); err != nil {
		t.Fatalf("daily file not named by UTC date: %v", err)
	}
	if info, err := os.Stat(filepath.Join(dir, "2026-11-02.jsonl")); err == nil && info.Mode().Perm() != 0o640 {
		t.Fatalf("mode = %v", info.Mode().Perm())
	}

	l2 := open(t, Options{Dir: dir, Now: c.Now})
	if got := ids(l2.Query(Filter{}).Entries); !slices.Equal(got, []uint64{3, 2, 1}) {
		t.Fatalf("reloaded IDs = %v", got)
	}
	if e := l2.Append(Entry{}); e.ID != 4 {
		t.Fatalf("ID after reload = %d, want 4", e.ID)
	}
	if got := l2.Query(Filter{Search: "n1"}).Entries; len(got) != 1 || got[0].Status != StatusAllowed {
		t.Fatalf("reloaded entry = %+v", got)
	}
}

func TestReloadSkipsCorruptLinesAndKeepsNewest(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o640); err != nil {
			t.Fatal(err)
		}
	}
	write("2026-10-31.jsonl", `{"id":1,"name":"old1"}`+"\n"+`{"id":2,"name":"old2"}`+"\n")
	write("2026-11-01.jsonl", `{"id":3,"name":"a"}`+"\n"+"not json\n"+`{"id":0,"name":"no id"}`+"\n"+`{"id":5,"name":"c"}`+"\n"+`{"id":4,"name":"b"}`+"\n"+`{"id":6,"na`)
	write("notes.txt", "ignored")

	c := newClock(t0)
	l := open(t, Options{Dir: dir, Memory: 4, Now: c.Now})

	if got, want := ids(l.Query(Filter{}).Entries), []uint64{5, 4, 3, 2}; !slices.Equal(got, want) {
		t.Fatalf("IDs = %v, want %v", got, want)
	}
	if e := l.Append(Entry{}); e.ID != 6 {
		t.Fatalf("next ID = %d", e.ID)
	}
}

func TestRetention(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"2026-10-20.jsonl", "2026-10-29.jsonl", "2026-10-31.jsonl", "2026-01-01.txt", "keep.jsonl", "2026-13-01.jsonl"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(`{"id":1}`+"\n"), 0o640); err != nil {
			t.Fatal(err)
		}
	}

	c := newClock(t0) // 2026-11-01 12:00 UTC
	open(t, Options{Dir: dir, Retention: 72 * time.Hour, Now: c.Now})

	got := dirNames(t, dir)
	want := []string{"2026-01-01.txt", "2026-10-29.jsonl", "2026-10-31.jsonl", "2026-13-01.jsonl", "keep.jsonl"}
	if !slices.Equal(got, want) {
		t.Fatalf("files = %v, want %v", got, want)
	}
}

func TestDayRollover(t *testing.T) {
	dir := t.TempDir()
	c := newClock(time.Date(2026, 11, 1, 23, 59, 0, 0, time.UTC))
	l := open(t, Options{Dir: dir, Retention: 48 * time.Hour, Now: c.Now})

	l.Append(Entry{Name: "first"})
	c.Set(time.Date(2026, 11, 2, 0, 1, 0, 0, time.UTC))
	l.Append(Entry{Name: "second"})
	// Two days later, the first day's file has expired.
	c.Set(time.Date(2026, 11, 4, 0, 1, 0, 0, time.UTC))
	l.Append(Entry{Name: "third"})
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}

	if got, want := dirNames(t, dir), []string{"2026-11-02.jsonl", "2026-11-04.jsonl"}; !slices.Equal(got, want) {
		t.Fatalf("files = %v, want %v", got, want)
	}

	b, err := os.ReadFile(filepath.Join(dir, "2026-11-04.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if want := `"name":"third"`; !strings.Contains(string(b), want) {
		t.Fatalf("file = %s", b)
	}
}

func TestPeriodicFlush(t *testing.T) {
	dir := t.TempDir()
	l := open(t, Options{Dir: dir})
	e := l.Append(Entry{Name: "flushed"})

	name := filepath.Join(dir, e.Time.UTC().Format(dayLayout)+".jsonl")
	deadline := time.Now().Add(5 * time.Second)
	for {
		b, _ := os.ReadFile(name)
		if strings.Contains(string(b), "flushed") {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("entry not flushed within 5s")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestConcurrentAppend(t *testing.T) {
	l := open(t, Options{Dir: t.TempDir(), Memory: 10_000})
	ch := l.Subscribe(t.Context(), Filter{})

	var received atomic.Int64
	go func() {
		for range ch {
			received.Add(1)
		}
	}()

	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 500 {
				l.Append(Entry{Status: StatusAllowed})
				_ = l.Query(Filter{Limit: 5})
				_ = l.Stats(Filter{}, 3)
			}
		})
	}
	wg.Wait()

	if l.Len() != 4000 {
		t.Fatalf("Len = %d", l.Len())
	}
	seen := map[uint64]bool{}
	f := Filter{Limit: MaxLimit}
	for {
		page := l.Query(f)
		for _, e := range page.Entries {
			if seen[e.ID] {
				t.Fatalf("duplicate ID %d", e.ID)
			}
			seen[e.ID] = true
		}
		if page.NextPageToken == "" {
			break
		}
		f.PageToken = page.NextPageToken
	}
	if len(seen) != 4000 {
		t.Fatalf("paged %d entries", len(seen))
	}
}

func TestOpenRejectsInvalidOptions(t *testing.T) {
	for _, opts := range []Options{{Memory: -1}, {Retention: -time.Hour}} {
		if _, err := Open(opts); err == nil {
			t.Errorf("Open(%+v) succeeded", opts)
		}
	}
}

func dirNames(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	slices.Sort(names)
	return names
}
