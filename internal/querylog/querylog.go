// Package querylog records the queries a resolver answers: an in-memory
// ring that serves queries, filters, and statistics, backed by optional
// daily JSON-lines files that survive restarts and expire after a
// retention period.
//
// The ring is the queryable index; the files are the durable store. On
// [Open], the newest entries are reloaded from the files into the ring, so
// history and entry IDs continue across restarts.
package querylog

import (
	"bufio"
	"cmp"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Entry is one answered query.
type Entry struct {
	// ID identifies the entry. It's assigned by [Log.Append] and strictly
	// increases, including across restarts with the same directory.
	ID uint64 `json:"id"`

	// Time is when the query was answered.
	Time time.Time `json:"time"`

	// Profile is the policy profile that answered the query, if any.
	Profile string `json:"profile,omitempty"`

	// Device is the name of the client device, if known.
	Device string `json:"device,omitempty"`

	// Client is the client's IP address.
	Client string `json:"client,omitempty"`

	// Transport is how the query arrived: "doh", "udp", or "tcp".
	Transport string `json:"transport"`

	// Name is the queried name, lower-case and without a trailing dot.
	Name string `json:"name"`

	// Type is the query type, such as "A" or "AAAA".
	Type string `json:"type"`

	// Rcode is the response code, such as "NOERROR".
	Rcode string `json:"rcode"`

	// Status summarizes how the query was answered.
	Status Status `json:"status"`

	// Cached reports whether the answer came from the cache.
	Cached bool `json:"cached,omitempty"`

	// Reason names why a query was blocked or rewritten, such as "list",
	// "rebinding", or "newly-registered".
	Reason string `json:"reason,omitempty"`

	// Rule is the matched domain, or other detail about the decision.
	Rule string `json:"rule,omitempty"`

	// Source names the list a matching rule came from.
	Source string `json:"source,omitempty"`

	// Answers summarizes the answer records, such as "A 192.0.2.1" or
	// "CNAME cdn.example.".
	Answers []string `json:"answers,omitempty"`

	// Upstream is the upstream resolver that answered, if any.
	Upstream string `json:"upstream,omitempty"`

	// DurationMS is how long the query took to answer, in milliseconds.
	DurationMS float64 `json:"duration_ms"`
}

// Status summarizes how a query was answered.
type Status string

// Statuses of an [Entry].
const (
	// StatusAllowed means the query was answered normally.
	StatusAllowed Status = "allowed"

	// StatusBlocked means the query was blocked by policy.
	StatusBlocked Status = "blocked"

	// StatusRewritten means the query was answered locally, such as by a
	// rewrite, safe search, or a local zone.
	StatusRewritten Status = "rewritten"

	// StatusError means the query couldn't be answered.
	StatusError Status = "error"
)

// valid reports whether s is one of the defined statuses.
func (s Status) valid() bool {
	switch s {
	case StatusAllowed, StatusBlocked, StatusRewritten, StatusError:
		return true
	}
	return false
}

// Defaults for [Options].
const (
	// DefaultMemory is the default number of entries kept in memory.
	DefaultMemory = 50_000

	// DefaultRetention is how long daily files are kept by default.
	DefaultRetention = 7 * 24 * time.Hour
)

// Options configures a [Log].
type Options struct {
	// Memory is how many of the newest entries are kept in memory, and so
	// can be queried. It defaults to DefaultMemory, and must not be
	// negative.
	Memory int

	// Dir, if set, stores entries in daily files named YYYY-MM-DD.jsonl
	// (in UTC) in this directory, which is created if needed. Writes are
	// confined to it. If empty, entries are kept in memory only.
	Dir string

	// Retention is how long daily files are kept, checked when the log is
	// opened and when the day changes. It defaults to DefaultRetention.
	Retention time.Duration

	// Logger reports write failures. If nil, nothing is logged.
	Logger *slog.Logger

	// Now returns the current time. If nil, [time.Now] is used.
	Now func() time.Time
}

// flushInterval is the longest buffered entries wait to be written.
const flushInterval = time.Second

// errorLogInterval limits how often write failures are logged.
const errorLogInterval = time.Minute

// subscriberBuffer is the channel capacity of each subscription.
const subscriberBuffer = 256

// dayLayout names daily files.
const dayLayout = "2006-01-02"

// Log is a query log. It's safe for concurrent use.
type Log struct {
	opts   Options
	logger *slog.Logger
	now    func() time.Time

	mu     sync.RWMutex
	ring   []Entry // grows to opts.Memory, then wraps
	start  int     // index of the oldest entry
	n      int     // number of entries
	nextID uint64

	wmu        sync.Mutex
	root       *os.Root
	file       *os.File
	bw         *bufio.Writer
	day        string
	lastErrLog time.Time
	closed     bool

	smu  sync.Mutex
	subs map[*subscriber]struct{}

	done      chan struct{}
	closeOnce sync.Once
	flushDone chan struct{}
}

type subscriber struct {
	ch chan Entry
	f  Filter
}

// Open opens a log with opts, reloading the newest entries from its
// directory, if any, and deleting files older than the retention period.
func Open(opts Options) (*Log, error) {
	if opts.Memory < 0 {
		return nil, errors.New("querylog: memory must not be negative")
	}
	if opts.Retention < 0 {
		return nil, errors.New("querylog: retention must not be negative")
	}
	opts.Memory = cmp.Or(opts.Memory, DefaultMemory)
	opts.Retention = cmp.Or(opts.Retention, DefaultRetention)

	l := &Log{
		opts:      opts,
		logger:    cmp.Or(opts.Logger, slog.New(slog.DiscardHandler)),
		now:       opts.Now,
		ring:      make([]Entry, 0, min(opts.Memory, 1024)),
		nextID:    1,
		subs:      make(map[*subscriber]struct{}),
		done:      make(chan struct{}),
		flushDone: make(chan struct{}),
	}

	if l.now == nil {
		l.now = time.Now
	}

	if opts.Dir != "" {
		if err := os.MkdirAll(opts.Dir, 0o750); err != nil {
			return nil, fmt.Errorf("querylog: %w", err)
		}
		root, err := os.OpenRoot(opts.Dir)
		if err != nil {
			return nil, fmt.Errorf("querylog: %w", err)
		}
		l.root = root

		l.expire()
		if err := l.reload(); err != nil {
			root.Close()
			return nil, err
		}

		go l.flusher()
	} else {
		close(l.flushDone)
	}

	return l, nil
}

// dayFiles returns the days of the daily files in the directory, newest
// first, ignoring other files.
func (l *Log) dayFiles() ([]time.Time, error) {
	entries, err := fs.ReadDir(l.root.FS(), ".")
	if err != nil {
		return nil, fmt.Errorf("querylog: %w", err)
	}

	var days []time.Time
	for _, e := range entries {
		day, ok := parseDayFile(e.Name())
		if ok && e.Type().IsRegular() {
			days = append(days, day)
		}
	}

	slices.SortFunc(days, func(a, b time.Time) int { return b.Compare(a) })
	return days, nil
}

// parseDayFile parses a daily file name, such as "2026-11-01.jsonl".
func parseDayFile(name string) (time.Time, bool) {
	base, ok := strings.CutSuffix(name, ".jsonl")
	if !ok || len(base) != len(dayLayout) {
		return time.Time{}, false
	}
	day, err := time.Parse(dayLayout, base)
	if err != nil {
		return time.Time{}, false
	}
	return day, true
}

func dayFile(day string) string { return day + ".jsonl" }

// expire deletes daily files whose last possible entry is older than the
// retention period.
func (l *Log) expire() {
	days, err := l.dayFiles()
	if err != nil {
		l.logger.Warn("querylog: listing files", slog.Any("error", err))
		return
	}

	cutoff := l.now().Add(-l.opts.Retention)
	for _, day := range days {
		if day.Add(24 * time.Hour).Before(cutoff) {
			name := dayFile(day.Format(dayLayout))
			if err := l.root.Remove(name); err != nil {
				l.logger.Warn("querylog: removing expired file", slog.String("file", name), slog.Any("error", err))
			}
		}
	}
}

// reload loads the newest entries from the daily files into the ring.
func (l *Log) reload() error {
	days, err := l.dayFiles()
	if err != nil {
		return err
	}

	var loaded []Entry
	for _, day := range days {
		if len(loaded) >= l.opts.Memory {
			break
		}

		f, err := l.root.Open(dayFile(day.Format(dayLayout)))
		if err != nil {
			return fmt.Errorf("querylog: %w", err)
		}

		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
		for sc.Scan() {
			var e Entry
			if err := json.Unmarshal(sc.Bytes(), &e); err != nil || e.ID == 0 {
				continue // a corrupt or partially written line
			}
			loaded = append(loaded, e)
		}
		err = sc.Err()
		f.Close()
		if err != nil {
			l.logger.Warn("querylog: reading file", slog.String("day", day.Format(dayLayout)), slog.Any("error", err))
		}
	}

	slices.SortFunc(loaded, func(a, b Entry) int { return cmp.Compare(a.ID, b.ID) })
	loaded = slices.CompactFunc(loaded, func(a, b Entry) bool { return a.ID == b.ID })
	if len(loaded) > l.opts.Memory {
		loaded = loaded[len(loaded)-l.opts.Memory:]
	}

	for _, e := range loaded {
		l.push(e)
	}
	if len(loaded) > 0 {
		l.nextID = loaded[len(loaded)-1].ID + 1
	}

	return nil
}

// push stores e in the ring, evicting the oldest entry if it's full.
// l.mu must be held, or l not yet shared.
func (l *Log) push(e Entry) {
	// Grow until full, so a quiet resolver doesn't hold memory for
	// entries it never logs. While growing, start is 0 and n is len(ring).
	if len(l.ring) < l.opts.Memory {
		l.ring = append(l.ring, e)
		l.n++
		return
	}
	l.ring[l.start] = e
	l.start = (l.start + 1) % len(l.ring)
}

// at returns the i-th oldest entry. l.mu must be held.
func (l *Log) at(i int) *Entry {
	return &l.ring[(l.start+i)%len(l.ring)]
}

// flusher flushes buffered entries periodically until the log is closed.
func (l *Log) flusher() {
	defer close(l.flushDone)

	ticker := time.NewTicker(flushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-l.done:
			return
		case <-ticker.C:
			l.wmu.Lock()
			if l.bw != nil {
				l.writeErr(l.bw.Flush())
			}
			l.wmu.Unlock()
		}
	}
}

// Append stores e, assigning its ID and, if unset, its time, and returns
// the stored entry. It never fails: file write errors are logged.
func (l *Log) Append(e Entry) Entry {
	l.mu.Lock()
	e.ID = l.nextID
	l.nextID++
	if e.Time.IsZero() {
		e.Time = l.now()
	}
	l.push(e)
	l.mu.Unlock()

	if l.root != nil {
		l.write(e)
	}

	l.smu.Lock()
	for s := range l.subs {
		if s.f.matchLive(&e) {
			select {
			case s.ch <- e:
			default: // a slow subscriber misses entries rather than blocking
			}
		}
	}
	l.smu.Unlock()

	return e
}

// write appends e to the current day's file.
func (l *Log) write(e Entry) {
	line, err := json.Marshal(e)
	if err != nil {
		l.writeErr(err)
		return
	}
	line = append(line, '\n')

	l.wmu.Lock()
	defer l.wmu.Unlock()

	if l.closed {
		return
	}

	if day := l.now().UTC().Format(dayLayout); day != l.day || l.bw == nil {
		if err := l.rotate(day); err != nil {
			l.writeErr(err)
			return
		}
	}

	_, err = l.bw.Write(line)
	l.writeErr(err)
}

// rotate switches to day's file, expiring old files when the day changes.
// l.wmu must be held.
func (l *Log) rotate(day string) error {
	rolled := l.day != "" && l.day != day

	if l.file != nil {
		err := l.bw.Flush()
		err = errors.Join(err, l.file.Close())
		l.file, l.bw = nil, nil
		l.writeErr(err)
	}

	if rolled {
		l.expire()
	}

	f, err := l.root.OpenFile(dayFile(day), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o640)
	if err != nil {
		return err
	}

	l.file, l.bw, l.day = f, bufio.NewWriter(f), day
	return nil
}

// writeErr logs err, at most once per errorLogInterval. l.wmu must be
// held.
func (l *Log) writeErr(err error) {
	if err == nil {
		return
	}
	if now := l.now(); now.Sub(l.lastErrLog) >= errorLogInterval || l.lastErrLog.IsZero() {
		l.lastErrLog = now
		l.logger.Warn("querylog: writing entries", slog.Any("error", err))
	}
}

// Len returns the number of entries in memory.
func (l *Log) Len() int {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.n
}

// Query returns the entries in memory matching f, newest first.
func (l *Log) Query(f Filter) Page {
	limit := f.limit()

	var before uint64
	if f.PageToken != "" {
		// An invalid token matches nothing, since ParseFilter rejects it.
		b, err := decodeToken(f.PageToken)
		if err != nil {
			return Page{Entries: []Entry{}}
		}
		before = b
	}

	l.mu.RLock()
	defer l.mu.RUnlock()

	page := Page{Entries: []Entry{}}
	for i := l.n - 1; i >= 0; i-- {
		e := l.at(i)
		if before != 0 && e.ID >= before {
			continue
		}
		if !f.match(e) {
			continue
		}
		if len(page.Entries) == limit {
			page.NextPageToken = encodeToken(page.Entries[limit-1].ID)
			break
		}
		page.Entries = append(page.Entries, cloneEntry(e))
	}

	return page
}

// cloneEntry copies e, so callers can't modify the ring's answers.
func cloneEntry(e *Entry) Entry {
	c := *e
	c.Answers = slices.Clone(e.Answers)
	return c
}

// Subscribe returns a channel of new entries matching f, ignoring its
// Limit, PageToken, and Until. Entries are dropped if the channel's
// buffer is full. The channel is closed when ctx is done or the log is
// closed.
func (l *Log) Subscribe(ctx context.Context, f Filter) <-chan Entry {
	s := &subscriber{ch: make(chan Entry, subscriberBuffer), f: f}

	l.smu.Lock()
	select {
	case <-l.done:
		l.smu.Unlock()
		close(s.ch)
		return s.ch
	default:
	}
	l.subs[s] = struct{}{}
	l.smu.Unlock()

	go func() {
		select {
		case <-ctx.Done():
		case <-l.done:
		}

		l.smu.Lock()
		delete(l.subs, s)
		close(s.ch)
		l.smu.Unlock()
	}()

	return s.ch
}

// Close flushes and closes the log's file and ends subscriptions. It's
// safe to call more than once.
func (l *Log) Close() error {
	var err error
	l.closeOnce.Do(func() {
		l.smu.Lock()
		close(l.done)
		l.smu.Unlock()
		<-l.flushDone

		l.wmu.Lock()
		defer l.wmu.Unlock()

		l.closed = true
		if l.file != nil {
			err = errors.Join(l.bw.Flush(), l.file.Close())
			l.file, l.bw = nil, nil
		}
		if l.root != nil {
			err = errors.Join(err, l.root.Close())
		}
	})
	return err
}

// Filter selects log entries. Zero fields match everything.
type Filter struct {
	// Profile, Device, and Client match entries with exactly these values.
	Profile, Device, Client string

	// Status matches entries with exactly this status.
	Status Status

	// Reason matches entries with exactly this reason.
	Reason string

	// Search matches entries whose name contains it, ignoring case.
	Search string

	// Since and Until match entries answered within these inclusive
	// bounds.
	Since, Until time.Time

	// Limit is the most entries in a page: 100 by default, at most
	// MaxLimit.
	Limit int

	// PageToken continues from a previous [Page.NextPageToken].
	PageToken string
}

// Page limits.
const (
	// DefaultLimit is the number of entries in a page by default.
	DefaultLimit = 100

	// MaxLimit is the most entries in a page.
	MaxLimit = 1000
)

func (f Filter) limit() int {
	if f.Limit <= 0 {
		return DefaultLimit
	}
	return min(f.Limit, MaxLimit)
}

// matchLive reports whether e matches f, ignoring Until, which doesn't
// apply to live entries.
func (f Filter) matchLive(e *Entry) bool {
	f.Until = time.Time{}
	return f.match(e)
}

// match reports whether e matches f.
func (f Filter) match(e *Entry) bool {
	switch {
	case f.Profile != "" && e.Profile != f.Profile,
		f.Device != "" && e.Device != f.Device,
		f.Client != "" && e.Client != f.Client,
		f.Status != "" && e.Status != f.Status,
		f.Reason != "" && e.Reason != f.Reason,
		!f.Since.IsZero() && e.Time.Before(f.Since),
		!f.Until.IsZero() && e.Time.After(f.Until):
		return false
	case f.Search != "":
		return strings.Contains(strings.ToLower(e.Name), strings.ToLower(f.Search))
	}
	return true
}

// ParseFilter builds a filter from URL query parameters: profile, device,
// client, status, reason, q (Search), since and until (RFC 3339), limit,
// and page_token.
func ParseFilter(v url.Values) (Filter, error) {
	f := Filter{
		Profile:   v.Get("profile"),
		Device:    v.Get("device"),
		Client:    v.Get("client"),
		Status:    Status(v.Get("status")),
		Reason:    v.Get("reason"),
		Search:    v.Get("q"),
		PageToken: v.Get("page_token"),
	}

	var errs []error

	if f.Status != "" && !f.Status.valid() {
		errs = append(errs, fmt.Errorf("invalid status %q (want allowed, blocked, rewritten, or error)", f.Status))
	}

	for _, p := range []struct {
		name string
		t    *time.Time
	}{{"since", &f.Since}, {"until", &f.Until}} {
		if s := v.Get(p.name); s != "" {
			t, err := time.Parse(time.RFC3339, s)
			if err != nil {
				errs = append(errs, fmt.Errorf("invalid %s %q (want an RFC 3339 time)", p.name, s))
			}
			*p.t = t
		}
	}

	if s := v.Get("limit"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 1 || n > MaxLimit {
			errs = append(errs, fmt.Errorf("invalid limit %q (want 1 to %d)", s, MaxLimit))
		}
		f.Limit = n
	}

	if f.PageToken != "" {
		if _, err := decodeToken(f.PageToken); err != nil {
			errs = append(errs, err)
		}
	}

	return f, errors.Join(errs...)
}

// pageToken is the decoded form of a page token.
type pageToken struct {
	V      int    `json:"v"`
	Before uint64 `json:"b"`
}

const tokenVersion = 1

func encodeToken(before uint64) string {
	b, _ := json.Marshal(pageToken{V: tokenVersion, Before: before})
	return base64.RawURLEncoding.EncodeToString(b)
}

func decodeToken(s string) (uint64, error) {
	invalid := errors.New("invalid page_token")

	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return 0, invalid
	}
	var t pageToken
	if err := json.Unmarshal(b, &t); err != nil || t.V != tokenVersion || t.Before == 0 {
		return 0, invalid
	}
	return t.Before, nil
}

// Page is a page of entries, newest first.
type Page struct {
	// Entries are the matching entries. It's never nil.
	Entries []Entry `json:"entries"`

	// NextPageToken, if set, continues with older entries.
	NextPageToken string `json:"next_page_token,omitempty"`
}

// Stats aggregates log entries.
type Stats struct {
	// Since is the time of the oldest entry considered.
	Since time.Time `json:"since,omitzero"`

	// Total is the number of entries considered.
	Total int `json:"total"`

	// ByStatus counts entries by status.
	ByStatus map[Status]int `json:"by_status"`

	// ByReason counts blocked and rewritten entries by reason.
	ByReason map[string]int `json:"by_reason"`

	// TopBlocked are the most blocked names.
	TopBlocked []Count `json:"top_blocked"`

	// TopAllowed are the most allowed names.
	TopAllowed []Count `json:"top_allowed"`

	// TopClients are the most active clients, by device name if known,
	// otherwise by address.
	TopClients []Count `json:"top_clients"`
}

// Count is how often a name appears.
type Count struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

// Stats aggregates the entries in memory matching f, ignoring its Limit
// and PageToken, listing the top names in each category.
func (l *Log) Stats(f Filter, top int) Stats {
	stats := Stats{ByStatus: map[Status]int{}, ByReason: map[string]int{}}
	blocked, allowed, clients := map[string]int{}, map[string]int{}, map[string]int{}

	l.mu.RLock()
	for i := range l.n {
		e := l.at(i)
		if !f.match(e) {
			continue
		}

		if stats.Total == 0 {
			stats.Since = e.Time
		}
		stats.Total++
		stats.ByStatus[e.Status]++

		switch e.Status {
		case StatusBlocked:
			blocked[e.Name]++
		case StatusAllowed:
			allowed[e.Name]++
		}
		if (e.Status == StatusBlocked || e.Status == StatusRewritten) && e.Reason != "" {
			stats.ByReason[e.Reason]++
		}
		if client := cmp.Or(e.Device, e.Client); client != "" {
			clients[client]++
		}
	}
	l.mu.RUnlock()

	stats.TopBlocked = topCounts(blocked, top)
	stats.TopAllowed = topCounts(allowed, top)
	stats.TopClients = topCounts(clients, top)

	return stats
}

// topCounts returns the top n counts, by count descending, then name.
func topCounts(m map[string]int, n int) []Count {
	counts := make([]Count, 0, len(m))
	for name, c := range m {
		counts = append(counts, Count{Name: name, Count: c})
	}
	slices.SortFunc(counts, func(a, b Count) int {
		return cmp.Or(cmp.Compare(b.Count, a.Count), strings.Compare(a.Name, b.Name))
	})
	if n >= 0 && len(counts) > n {
		counts = counts[:n]
	}
	return counts
}
