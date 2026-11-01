package blocklist

import (
	"bytes"
	"cmp"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"
)

// Preset categories, which group presets by what they protect against.
const (
	CategoryPrivacy  = "privacy"  // ads and trackers
	CategorySecurity = "security" // malware, phishing, scams, and abuse
	CategoryParental = "parental" // content some households restrict
)

// Preset is a well-known blocklist that can be named instead of a URL.
type Preset struct {
	// Name identifies the preset, such as "hagezi-pro".
	Name string `json:"name"`

	// Title and Description explain the preset to people choosing lists.
	Title       string `json:"title"`
	Description string `json:"description"`

	// Category is CategoryPrivacy, CategorySecurity, or CategoryParental.
	Category string `json:"category"`

	// URL is where the list is downloaded from.
	URL string `json:"url"`
}

// hagezi returns the URL of one of HaGeZi's Adblock Plus format lists.
func hagezi(name string) string {
	return "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/" + name + ".txt"
}

// Catalog is every preset, in the order they're presented.
var Catalog = []Preset{
	{Name: "hagezi-light", Category: CategoryPrivacy, URL: hagezi("light"),
		Title: "Ads and trackers (light)", Description: "HaGeZi's Light list: the most common ads, trackers, and malware, with almost no breakage."},
	{Name: "hagezi-normal", Category: CategoryPrivacy, URL: hagezi("multi"),
		Title: "Ads and trackers", Description: "HaGeZi's Multi NORMAL list: ads, trackers, and malware, rarely breaking sites. The \"default\" preset."},
	{Name: "hagezi-pro", Category: CategoryPrivacy, URL: hagezi("pro"),
		Title: "Ads and trackers (pro)", Description: "HaGeZi's Multi PRO list: stricter blocking, which occasionally breaks sites."},
	{Name: "oisd-small", Category: CategoryPrivacy, URL: "https://small.oisd.nl",
		Title: "OISD small", Description: "OISD's small list of ads, trackers, and malware."},
	{Name: "oisd-big", Category: CategoryPrivacy, URL: "https://big.oisd.nl",
		Title: "OISD big", Description: "OISD's big list of ads, trackers, and malware."},
	{Name: "stevenblack", Category: CategoryPrivacy, URL: "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
		Title: "StevenBlack hosts", Description: "StevenBlack's unified hosts file of ads and malware."},
	// The lists cube uses by default. Only their domain rules apply to DNS.
	{Name: "easylist", Category: CategoryPrivacy, URL: "https://easylist-downloads.adblockplus.org/easylist.txt",
		Title: "EasyList", Description: "EasyList's domain rules, for ads."},
	{Name: "easyprivacy", Category: CategoryPrivacy, URL: "https://easylist-downloads.adblockplus.org/easyprivacy.txt",
		Title: "EasyPrivacy", Description: "EasyPrivacy's domain rules, for trackers."},

	{Name: ThreatIntelPreset, Category: CategorySecurity, URL: hagezi("tif.medium"),
		Title: "Threat intelligence", Description: "Malware, phishing, scam, and command-and-control domains aggregated from dozens of threat intelligence feeds, without the noisiest sources. On by default."},
	{Name: "threat-intel-full", Category: CategorySecurity, URL: hagezi("tif"),
		Title: "Threat intelligence (full)", Description: "Every feed in the threat intelligence aggregate. Catches more, but is large (about 40 MB) and needs more memory."},
	{Name: "scams", Category: CategorySecurity, URL: hagezi("fake"),
		Title: "Scams and fake shops", Description: "Fake shops, fake streaming sites, and other fraud."},
	{Name: "abused-tlds", Category: CategorySecurity, URL: hagezi("spam-tlds-adblock"),
		Title: "Most abused TLDs", Description: "Whole top-level domains that are mostly used for spam and abuse."},
	{Name: "dynamic-dns", Category: CategorySecurity, URL: hagezi("dyndns"),
		Title: "Dynamic DNS", Description: "Dynamic DNS services, which malware uses to move its servers around."},
	{Name: "bypass-services", Category: CategorySecurity, URL: hagezi("doh-vpn-proxy-bypass"),
		Title: "Encrypted DNS, VPN, and proxy services", Description: "Services devices can use to route around this resolver's filtering."},

	{Name: "gambling", Category: CategoryParental, URL: hagezi("gambling"),
		Title: "Gambling", Description: "Gambling and betting sites."},
	{Name: "adult", Category: CategoryParental, URL: hagezi("nsfw"),
		Title: "Adult content", Description: "Pornography and other adult content."},
	{Name: "social", Category: CategoryParental, URL: hagezi("social"),
		Title: "Social networks", Description: "Social networks and their apps."},
}

// ThreatIntelPreset names the threat intelligence preset, which new
// policies use by default.
const ThreatIntelPreset = "threat-intel"

// Presets maps each preset's name to its URL. DefaultPreset is used when a
// blocklist is enabled without naming one.
var Presets = func() map[string]string {
	m := make(map[string]string, len(Catalog))
	for _, p := range Catalog {
		m[p.Name] = p.URL
	}
	return m
}()

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

	return Source{Name: publicName(s), Location: s}, nil
}

// publicName names an unnamed source by its location, without any URL
// credentials or query string, since names appear in logs and in the
// Extended DNS Errors sent to clients.
func publicName(location string) string {
	if !isURL(location) {
		return location
	}

	u, err := url.Parse(location)
	if err != nil {
		return "blocklist"
	}

	return u.Scheme + "://" + u.Host + u.EscapedPath()
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

// LoadSource loads one source into its own list.
func (l *Loader) LoadSource(ctx context.Context, src Source) (*List, error) {
	var b Builder
	if _, err := l.loadSource(ctx, &b, src); err != nil {
		return nil, err
	}
	// Name the source even if it has no rules, so verdicts can cite it.
	b.source(src.Name)
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

		body, err := l.readLimited(f)
		if err != nil {
			return 0, fmt.Errorf("blocklist: %s: %w", src.Location, err)
		}

		return b.Add(src.Name, bytes.NewReader(body))
	}

	body, err := l.fetch(ctx, src.Location)
	if err != nil {
		return 0, err
	}

	return b.Add(src.Name, bytes.NewReader(body))
}

// readLimited reads all of r, failing rather than truncating if it's larger
// than the size limit, since a list cut short could even end in a
// different, valid rule.
func (l *Loader) readLimited(r io.Reader) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r, l.maxSize()+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > l.maxSize() {
		return nil, fmt.Errorf("list exceeds %d bytes", l.maxSize())
	}
	return body, nil
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

	body, err := l.readLimited(resp.Body)
	if err != nil {
		return nil, cacheEntry{}, fmt.Errorf("blocklist: %s: %w", url, err)
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

// cacheKey names the cache file for url.
func cacheKey(url string) string {
	sum := sha256.Sum256([]byte(url))
	return hex.EncodeToString(sum[:16]) + ".cache"
}

// A cache file holds a list and its metadata together, so they're always
// replaced as a pair: a line of JSON metadata, then the list itself.

// readCache returns a cached list and its metadata, or nils if there's no
// usable cached copy.
func readCache(root *os.Root, key string) ([]byte, *cacheEntry) {
	if root == nil {
		return nil, nil
	}

	data, err := root.ReadFile(key)
	if err != nil {
		return nil, nil
	}

	meta, body, ok := bytes.Cut(data, []byte("\n"))
	if !ok {
		return nil, nil
	}

	var entry cacheEntry
	if err := json.Unmarshal(meta, &entry); err != nil {
		return nil, nil
	}

	return body, &entry
}

// writeCache stores body and its metadata as one file, written under a
// unique temporary name and then renamed into place, so concurrent
// writers, such as doh serve and doh blocklist check sharing a cache,
// never publish a partial file or mismatched metadata.
func writeCache(root *os.Root, key string, body []byte, entry cacheEntry) error {
	meta, err := json.Marshal(entry)
	if err != nil {
		return err
	}

	var suffix [8]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return err
	}
	tmp := key + "." + hex.EncodeToString(suffix[:]) + ".tmp"

	f, err := root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o640)
	if err != nil {
		return err
	}

	_, err = f.Write(append(append(meta, '\n'), body...))
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		err = root.Rename(tmp, key)
	}
	if err != nil {
		_ = root.Remove(tmp)
	}

	return err
}
