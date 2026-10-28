package blocklist

import (
	"bytes"
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"
)

// Presets are well-known DNS blocklists, by name. DefaultPreset is used
// when a blocklist is enabled without naming one.
var Presets = map[string]string{
	"hagezi-light":  "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/light.txt",
	"hagezi-normal": "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/multi.txt",
	"hagezi-pro":    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.txt",
	"oisd-small":    "https://small.oisd.nl",
	"oisd-big":      "https://big.oisd.nl",
	"stevenblack":   "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",

	// The lists cube uses by default. Only their domain rules apply to DNS.
	"easylist":    "https://easylist-downloads.adblockplus.org/easylist.txt",
	"easyprivacy": "https://easylist-downloads.adblockplus.org/easyprivacy.txt",
}

// DefaultPreset is the preset named "default": HaGeZi's Multi NORMAL, which
// blocks ads, trackers, and malware while rarely breaking sites.
const DefaultPreset = "hagezi-normal"

// PresetNames returns the preset names, sorted.
func PresetNames() []string {
	return slices.Sorted(maps.Keys(Presets))
}

// Source is a blocklist to load.
type Source struct {
	// Name identifies the source in verdicts and logs.
	Name string

	// Location is an http or https URL, or a local file path.
	Location string
}

// ParseSource parses a source given as a preset name (or "default"), a
// URL, a file path, or name=location, as in cube's rulegen -source flag.
func ParseSource(s string) (Source, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return Source{}, errors.New("blocklist: empty source")
	}

	if s == "default" {
		s = DefaultPreset
	}

	if url, ok := Presets[s]; ok {
		return Source{Name: s, Location: url}, nil
	}

	if name, location, ok := strings.Cut(s, "="); ok && name != "" && !strings.Contains(name, "/") {
		if location == "" {
			return Source{}, fmt.Errorf("blocklist: source %q has no location", name)
		}
		return Source{Name: name, Location: location}, nil
	}

	if !isURL(s) && !strings.ContainsAny(s, `/\.`) {
		return Source{}, fmt.Errorf("blocklist: unknown preset %q (want one of %s, a URL, or a file path)", s, strings.Join(PresetNames(), ", "))
	}

	return Source{Name: s, Location: s}, nil
}

func isURL(s string) bool {
	return strings.HasPrefix(s, "https://") || strings.HasPrefix(s, "http://")
}

// Loader loads sources into a [List], downloading lists by URL with
// conditional requests and caching them on disk, so restarts work offline
// and unchanged lists aren't downloaded again.
type Loader struct {
	// Client downloads lists. If nil, [http.DefaultClient] is used.
	Client *http.Client

	// CacheDir, if set, stores downloaded lists. Writes are confined to it.
	CacheDir string

	// Logger reports sources that fail to load. If nil, nothing is logged.
	Logger *slog.Logger

	// MaxSize bounds the size of each list, so a misbehaving server can't
	// exhaust memory. If zero, [DefaultMaxSize] is used.
	MaxSize int64
}

// DefaultMaxSize is the default bound on a list's size. The largest common
// lists are a few megabytes.
const DefaultMaxSize = 64 << 20

func (l *Loader) maxSize() int64 { return cmp.Or(l.MaxSize, DefaultMaxSize) }

// Load loads every source, along with rules blocking block and allowing
// allow, into a list.
//
// A source that can't be loaded is skipped and logged, rather than failing
// the whole list, falling back to its cached copy if there is one. Load
// returns an error only if every source fails.
func (l *Loader) Load(ctx context.Context, sources []Source, block, allow []string) (*List, error) {
	var (
		b    Builder
		errs []error
	)

	for _, src := range sources {
		n, err := l.loadSource(ctx, &b, src)
		if err != nil {
			errs = append(errs, err)
			l.logger().WarnContext(ctx, "blocklist: skipping source", slog.String("source", src.Name), slog.Any("error", err))
			continue
		}
		l.logger().InfoContext(ctx, "blocklist: loaded source", slog.String("source", src.Name), slog.Int("rules", n))
	}

	if len(sources) > 0 && len(errs) == len(sources) {
		return nil, errors.Join(errs...)
	}

	b.Block("config", block...)
	b.Allow("config", allow...)

	return b.List(), nil
}

func (l *Loader) logger() *slog.Logger {
	if l.Logger == nil {
		return slog.New(slog.DiscardHandler)
	}
	return l.Logger
}

// loadSource adds the rules from src to b.
func (l *Loader) loadSource(ctx context.Context, b *Builder, src Source) (int, error) {
	if !isURL(src.Location) {
		f, err := os.Open(src.Location)
		if err != nil {
			return 0, err
		}
		defer f.Close()

		return b.Add(src.Name, io.LimitReader(f, l.maxSize()))
	}

	body, err := l.fetch(ctx, src.Location)
	if err != nil {
		return 0, err
	}

	return b.Add(src.Name, bytes.NewReader(body))
}

// cacheEntry is the metadata stored alongside a cached list.
type cacheEntry struct {
	URL          string    `json:"url"`
	ETag         string    `json:"etag,omitempty"`
	LastModified string    `json:"last_modified,omitempty"`
	Fetched      time.Time `json:"fetched"`
}

// fetch downloads url, revalidating a cached copy if there is one, and
// falling back to the cached copy if the download fails.
func (l *Loader) fetch(ctx context.Context, url string) ([]byte, error) {
	root := l.openCache()
	if root != nil {
		defer root.Close()
	}

	key := cacheKey(url)
	cached, entry := readCache(root, key)

	body, validators, err := l.download(ctx, url, entry)
	switch {
	case err != nil && cached != nil:
		l.logger().WarnContext(ctx, "blocklist: download failed, using cached copy",
			slog.String("url", url), slog.Time("fetched", entry.Fetched), slog.Any("error", err))
		return cached, nil
	case err != nil:
		return nil, err
	case body == nil:
		return cached, nil // not modified since the cached copy
	}

	if root != nil {
		validators.URL, validators.Fetched = url, time.Now().UTC()
		if err := writeCache(root, key, body, validators); err != nil {
			l.logger().WarnContext(ctx, "blocklist: caching list", slog.String("url", url), slog.Any("error", err))
		}
	}

	return body, nil
}

// download fetches url, sending validators from cached so an unchanged list
// returns 304 Not Modified, in which case it returns a nil body. Otherwise
// it returns the list and the validators to send next time.
func (l *Loader) download(ctx context.Context, url string, cached *cacheEntry) ([]byte, cacheEntry, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, cacheEntry{}, err
	}
	req.Header.Set("User-Agent", "doh (+https://github.com/picatz/doh)")

	if cached != nil {
		if cached.ETag != "" {
			req.Header.Set("If-None-Match", cached.ETag)
		}
		if cached.LastModified != "" {
			req.Header.Set("If-Modified-Since", cached.LastModified)
		}
	}

	resp, err := cmp.Or(l.Client, http.DefaultClient).Do(req)
	if err != nil {
		return nil, cacheEntry{}, err
	}
	defer resp.Body.Close()

	switch {
	case resp.StatusCode == http.StatusNotModified && cached != nil:
		return nil, cacheEntry{}, nil
	case resp.StatusCode != http.StatusOK:
		return nil, cacheEntry{}, fmt.Errorf("blocklist: %s: %s", url, resp.Status)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, l.maxSize()+1))
	if err != nil {
		return nil, cacheEntry{}, err
	}
	if int64(len(body)) > l.maxSize() {
		return nil, cacheEntry{}, fmt.Errorf("blocklist: %s: list exceeds %d bytes", url, l.maxSize())
	}

	return body, cacheEntry{ETag: resp.Header.Get("ETag"), LastModified: resp.Header.Get("Last-Modified")}, nil
}

// openCache opens the cache directory as an [os.Root], creating it if
// needed, so cache reads and writes can't escape it. It returns nil if
// there's no cache directory or it can't be opened.
func (l *Loader) openCache() *os.Root {
	if l.CacheDir == "" {
		return nil
	}

	if err := os.MkdirAll(l.CacheDir, 0o750); err != nil {
		l.logger().Warn("blocklist: creating cache dir", slog.Any("error", err))
		return nil
	}

	root, err := os.OpenRoot(l.CacheDir)
	if err != nil {
		l.logger().Warn("blocklist: opening cache dir", slog.Any("error", err))
		return nil
	}

	return root
}

// cacheKey names the cache files for url.
func cacheKey(url string) string {
	sum := sha256.Sum256([]byte(url))
	return hex.EncodeToString(sum[:16])
}

// readCache returns a cached list and its metadata, or nils if there's no
// usable cached copy.
func readCache(root *os.Root, key string) ([]byte, *cacheEntry) {
	if root == nil {
		return nil, nil
	}

	meta, err := root.ReadFile(key + ".json")
	if err != nil {
		return nil, nil
	}

	var entry cacheEntry
	if err := json.Unmarshal(meta, &entry); err != nil {
		return nil, nil
	}

	body, err := root.ReadFile(key + ".txt")
	if err != nil {
		return nil, nil
	}

	return body, &entry
}

// writeCache stores body and its metadata, writing each to a temporary
// file first so a crash never leaves a partial list behind.
func writeCache(root *os.Root, key string, body []byte, entry cacheEntry) error {
	meta, err := json.Marshal(entry)
	if err != nil {
		return err
	}

	// Write the list before its metadata, so metadata never describes a
	// list that wasn't stored.
	for _, file := range []struct {
		name string
		data []byte
	}{{key + ".txt", body}, {key + ".json", meta}} {
		tmp := file.name + ".tmp"
		if err := root.WriteFile(tmp, file.data, 0o640); err != nil {
			return err
		}
		if err := root.Rename(tmp, file.name); err != nil {
			return err
		}
	}

	return nil
}
