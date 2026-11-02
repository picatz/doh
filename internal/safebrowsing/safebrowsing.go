// Package safebrowsing checks host names against Google Safe Browsing's
// threat lists, keeping the lists' hash prefixes locally so that what's
// looked up stays private: only when a name's hash matches a local prefix
// is that 4-byte prefix, never the name, sent to Google, to get the full
// hashes that confirm or rule out the match.
//
// It implements the Safe Browsing API v5's local list mode
// (https://developers.google.com/safe-browsing/reference/Local.List.Mode):
// [Checker.Run] keeps the lists current with hashLists:batchGet, waiting
// at least as long as the server asks between updates and backing off
// after failures, and [Checker.Lookup] answers from the local lists and a
// cache of hashes:search results, kept as long as the server allows.
// Requests carry the API key in the X-Goog-Api-Key header, so it's never
// part of a URL, and errors never include it.
//
// DNS sees host names, not URLs, so only host-wide entries (expressions
// such as "evil.example/") can match; lists' entries for particular paths
// on otherwise good sites don't.
package safebrowsing

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

// DefaultBaseURL is the Safe Browsing API's address.
const DefaultBaseURL = "https://safebrowsing.googleapis.com"

// DefaultLists are the hash lists checked by default: social engineering
// (phishing), malware, and unwanted software, for desktop platforms.
var DefaultLists = []string{"se-4b", "mw-4b", "uws-4b"}

// Defaults for [Options].
const (
	// DefaultTimeout bounds each request to the API.
	DefaultTimeout = 2 * time.Second

	// DefaultMaxCached bounds the cached hashes:search results.
	DefaultMaxCached = 50_000

	// maxResponse bounds a response's size: full lists are a few
	// megabytes.
	maxResponse = 64 << 20

	// minUpdateWait is the shortest wait between list updates, however
	// little the server asks for, except that a zero wait (more to send)
	// is followed promptly a few times in a row.
	minUpdateWait = time.Minute

	// maxImmediate is how many updates in a row may follow a zero wait.
	maxImmediate = 5

	// Backoff after failed requests: doubling from backoffMin, with
	// jitter, up to backoffMax.
	backoffMin = time.Minute
	backoffMax = 8 * time.Hour

	// maxCacheDuration caps how long a search result is kept, as the API
	// allows for empty results.
	maxCacheDuration = 24 * time.Hour
)

// Options configures a [Checker].
type Options struct {
	// Key is the API key. It's sent only in request headers.
	Key string

	// Lists are the hash lists to check. If empty, [DefaultLists].
	Lists []string

	// Client makes requests. If nil, [http.DefaultClient].
	Client *http.Client

	// BaseURL is the API's address. If empty, [DefaultBaseURL].
	BaseURL string

	// Timeout bounds each request. If zero, [DefaultTimeout].
	Timeout time.Duration

	// MaxCached bounds the cached search results. If zero,
	// [DefaultMaxCached].
	MaxCached int

	// Logger reports updates and failures. If nil, nothing is logged.
	Logger *slog.Logger

	// Now returns the current time. If nil, time.Now.
	Now func() time.Time
}

// Checker looks host names up in Safe Browsing's threat lists. It's safe
// for concurrent use.
type Checker struct {
	opts   Options
	logger *slog.Logger
	group  singleflight.Group

	mu        sync.RWMutex
	lists     map[string]*prefixList
	updated   time.Time
	cache     map[uint32]cached
	searchErr time.Time     // when search requests may be made again, after a failure
	backoff   time.Duration // the current search backoff
}

// cached is a hashes:search result for one prefix: the full hashes that
// matched it, until expires.
type cached struct {
	hashes  []FullHash
	expires time.Time
}

// New returns a checker. Its lists are empty, so it matches nothing,
// until [Checker.Run] has fetched them.
func New(opts Options) (*Checker, error) {
	if strings.TrimSpace(opts.Key) == "" {
		return nil, errors.New("safebrowsing: an API key is required")
	}
	if len(opts.Lists) == 0 {
		opts.Lists = DefaultLists
	}
	opts.BaseURL = strings.TrimSuffix(cmp.Or(opts.BaseURL, DefaultBaseURL), "/")
	if _, err := url.Parse(opts.BaseURL); err != nil {
		return nil, fmt.Errorf("safebrowsing: base URL: %w", err)
	}
	opts.Client = cmp.Or(opts.Client, http.DefaultClient)
	opts.Timeout = cmp.Or(opts.Timeout, DefaultTimeout)
	opts.MaxCached = cmp.Or(opts.MaxCached, DefaultMaxCached)
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return &Checker{
		opts:   opts,
		logger: cmp.Or(opts.Logger, slog.New(slog.DiscardHandler)),
		lists:  make(map[string]*prefixList),
		cache:  make(map[uint32]cached),
	}, nil
}

// Status describes the local lists.
type Status struct {
	// Updated is when the lists were last updated, if ever.
	Updated time.Time `json:"updated,omitzero"`

	// Prefixes is how many hash prefixes the lists hold, by list.
	Prefixes map[string]int `json:"prefixes"`
}

// Status describes the local lists.
func (c *Checker) Status() Status {
	c.mu.RLock()
	defer c.mu.RUnlock()
	st := Status{Updated: c.updated, Prefixes: make(map[string]int, len(c.lists))}
	for name, l := range c.lists {
		st.Prefixes[name] = len(l.prefixes)
	}
	return st
}

// Run keeps the local lists current until ctx is done: it updates them,
// then waits as long as the server asked (at least a minute, unless the
// server has more to send right away), backing off exponentially, with
// jitter, after failures.
func (c *Checker) Run(ctx context.Context) error {
	failures, immediate := 0, 0
	for {
		wait, err := c.Update(ctx)
		switch {
		case ctx.Err() != nil:
			return nil
		case err != nil:
			failures++
			wait = backoffFor(failures)
			c.logger.Warn("safebrowsing: updating lists failed", slog.Any("error", err), slog.Duration("retry", wait))
		case wait == 0 && immediate < maxImmediate:
			failures = 0
			immediate++
		default:
			failures, immediate = 0, 0
			wait = max(wait, minUpdateWait)
		}

		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}
}

// backoffFor returns how long to wait after n failures in a row.
func backoffFor(n int) time.Duration {
	d := backoffMin << min(n-1, 16)
	d = min(d, backoffMax)
	return d/2 + rand.N(d/2+1) // jitter: half to all of d
}

// Update fetches changes to the lists once, and returns how long the
// server asks to wait before the next update. A list whose update fails
// its checksum is dropped, so the next update fetches it whole.
func (c *Checker) Update(ctx context.Context) (time.Duration, error) {
	c.mu.RLock()
	q := url.Values{}
	for _, name := range c.opts.Lists {
		q.Add("names", name)
	}
	versioned := false
	for _, name := range c.opts.Lists {
		if l := c.lists[name]; l != nil && len(l.version) > 0 {
			versioned = true
		}
	}
	if versioned {
		for _, name := range c.opts.Lists {
			var v []byte
			if l := c.lists[name]; l != nil {
				v = l.version
			}
			q.Add("version", base64.StdEncoding.EncodeToString(v))
		}
	}
	c.mu.RUnlock()

	body, err := c.get(ctx, "/v5/hashLists:batchGet", q)
	if err != nil {
		return 0, err
	}
	updates, err := parseBatch(body)
	if err != nil {
		return 0, err
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	var wait time.Duration
	first := true
	var errs []error
	for _, u := range updates {
		if !slices.Contains(c.opts.Lists, u.Name) {
			continue
		}
		next, err := c.lists[u.Name].apply(u)
		if err != nil {
			delete(c.lists, u.Name) // fetch it whole next time
			errs = append(errs, fmt.Errorf("list %s: %w", u.Name, err))
			wait = 0
			first = false
			continue
		}
		c.lists[u.Name] = next
		if first || u.MinWait > wait {
			wait = u.MinWait
		}
		first = false
		c.logger.Debug("safebrowsing: list updated", slog.String("list", u.Name), slog.Int("prefixes", len(next.prefixes)), slog.Bool("partial", u.Partial))
	}
	c.updated = c.opts.Now()
	return wait, errors.Join(errs...)
}

// Threat is a match: the name, or a parent of it, that's listed, and what
// for.
type Threat struct {
	// Host is the listed host, such as "evil.example" for a lookup of
	// "www.evil.example".
	Host string

	// Types are the kinds of threat the host is listed for.
	Types []ThreatType
}

// String describes the threat for people.
func (t Threat) String() string {
	types := make([]string, 0, len(t.Types))
	for _, tt := range t.Types {
		types = append(types, tt.String())
	}
	return t.Host + " is listed by Google Safe Browsing for " + strings.Join(types, " and ")
}

// expression is one of a host's lookup expressions, as "host/", and its
// hash.
type expression struct {
	host string
	hash [32]byte
}

// expressions returns the lookup expressions for host: the host itself
// and up to four of its parents, from the last five labels down, but not
// the top-level domain alone, as the API's URL hashing describes for host
// names (with the path "/", since DNS has no path).
func expressions(host string) []expression {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if host == "" || !strings.Contains(host, ".") {
		return nil
	}
	hosts := []string{host}
	labels := strings.Split(host, ".")
	start := max(len(labels)-5, 1)
	for i := start; i < len(labels)-1; i++ {
		if h := strings.Join(labels[i:], "."); h != host {
			hosts = append(hosts, h)
		}
	}
	exprs := make([]expression, len(hosts))
	for i, h := range hosts {
		exprs[i] = expression{host: h, hash: sha256.Sum256([]byte(h + "/"))}
	}
	return exprs
}

// Lookup reports whether host, or a parent domain of it, is on the
// threat lists. It sends hash prefixes to the API only if one of host's
// expressions matches a local prefix and the cache can't answer; if that
// request fails, Lookup returns the error and no threat, so callers can
// fail open.
func (c *Checker) Lookup(ctx context.Context, host string) (Threat, bool, error) {
	exprs := expressions(host)
	now := c.opts.Now()

	var need []uint32
	c.mu.RLock()
	for _, e := range exprs {
		p := prefixOf(e.hash)
		if r, ok := c.cache[p]; ok && now.Before(r.expires) {
			if t, ok := match(e, r.hashes); ok {
				c.mu.RUnlock()
				return t, true, nil
			}
			continue
		}
		for _, name := range c.opts.Lists {
			if c.lists[name].contains(p) {
				if !slices.Contains(need, p) {
					need = append(need, p)
				}
				break
			}
		}
	}
	retry := c.searchErr
	c.mu.RUnlock()

	if len(need) == 0 {
		return Threat{}, false, nil
	}
	if now.Before(retry) {
		return Threat{}, false, errors.New("safebrowsing: backing off after a failed search")
	}

	results, err := c.search(ctx, need)
	if err != nil {
		return Threat{}, false, err
	}
	for _, e := range exprs {
		if hashes, ok := results[prefixOf(e.hash)]; ok {
			if t, ok := match(e, hashes); ok {
				return t, true, nil
			}
		}
	}
	return Threat{}, false, nil
}

// match reports whether e's hash is among hashes.
func match(e expression, hashes []FullHash) (Threat, bool) {
	for _, h := range hashes {
		if h.Hash == e.hash {
			return Threat{Host: e.host, Types: h.Threats}, true
		}
	}
	return Threat{}, false
}

// search asks the API for the full hashes of prefixes, caching the
// results, and returns them by prefix. Concurrent searches for the same
// prefixes share one request.
func (c *Checker) search(ctx context.Context, prefixes []uint32) (map[uint32][]FullHash, error) {
	slices.Sort(prefixes)
	var key strings.Builder
	q := url.Values{}
	for _, p := range prefixes {
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], p)
		q.Add("hashPrefixes", base64.StdEncoding.EncodeToString(b[:]))
		key.Write(b[:])
	}

	v, err, _ := c.group.Do(key.String(), func() (any, error) {
		body, err := c.get(ctx, "/v5/hashes:search", q)
		if err == nil {
			var r searchResult
			if r, err = parseSearch(body); err == nil {
				return c.store(prefixes, r), nil
			}
		}
		c.mu.Lock()
		c.backoff = min(max(c.backoff*2, backoffMin/4), backoffMax)
		c.searchErr = c.opts.Now().Add(c.backoff)
		c.mu.Unlock()
		return nil, err
	})
	if err != nil {
		return nil, err
	}
	return v.(map[uint32][]FullHash), nil
}

// store caches r, the result of searching for prefixes, and returns its
// hashes by prefix.
func (c *Checker) store(prefixes []uint32, r searchResult) map[uint32][]FullHash {
	byPrefix := make(map[uint32][]FullHash, len(prefixes))
	for _, p := range prefixes {
		byPrefix[p] = nil
	}
	for _, h := range r.hashes {
		p := prefixOf(h.Hash)
		if _, asked := byPrefix[p]; asked {
			byPrefix[p] = append(byPrefix[p], h)
		}
	}

	now := c.opts.Now()
	expires := now.Add(min(r.cache, maxCacheDuration))

	c.mu.Lock()
	defer c.mu.Unlock()
	c.backoff, c.searchErr = 0, time.Time{}
	if len(c.cache)+len(byPrefix) > c.opts.MaxCached {
		for p, e := range c.cache {
			if !now.Before(e.expires) {
				delete(c.cache, p)
			}
		}
		if len(c.cache)+len(byPrefix) > c.opts.MaxCached {
			clear(c.cache) // still full: start over rather than grow
		}
	}
	for p, hashes := range byPrefix {
		c.cache[p] = cached{hashes: hashes, expires: expires}
	}
	return byPrefix
}

// get makes a GET request to the API and returns the response body.
// Errors never include the API key, which is sent in a header, or the
// query, which holds hash prefixes.
func (c *Checker) get(ctx context.Context, path string, q url.Values) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, c.opts.Timeout)
	defer cancel()

	u := c.opts.BaseURL + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, fmt.Errorf("safebrowsing: %s: %w", path, err)
	}
	req.Header.Set("X-Goog-Api-Key", c.opts.Key)
	req.Header.Set("Accept", "application/x-protobuf")
	req.Header.Set("User-Agent", "doh (+https://github.com/picatz/doh)")

	resp, err := c.opts.Client.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err // without the URL
		}
		return nil, fmt.Errorf("safebrowsing: %s: %w", path, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse+1))
	if err != nil {
		return nil, fmt.Errorf("safebrowsing: %s: %w", path, err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("safebrowsing: %s: %s", path, resp.Status)
	}
	if len(body) > maxResponse {
		return nil, fmt.Errorf("safebrowsing: %s: response over %d bytes", path, maxResponse)
	}
	return body, nil
}
