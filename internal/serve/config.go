// Package serve implements the DNS-over-HTTPS server behind "doh serve".
package serve

import (
	"encoding/json/v2"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/picatz/doh/internal/blocklist"
	"github.com/picatz/doh/internal/upstream"
	"github.com/picatz/doh/pkg/doh"
)

// Config configures a [Server]. Its JSON form is the "doh serve" config file.
type Config struct {
	// Listen is the TCP address to serve on. It defaults to ":443", or
	// ":8080" when Plaintext is set.
	Listen string `json:"listen,omitempty"`

	// DNSListen, if set, also serves plain DNS over UDP and TCP on this
	// address (typically ":53"), so clients on a local network that can't
	// speak DoH can use the server as their resolver. If no TLS or
	// plaintext setting is configured, only plain DNS is served.
	DNSListen string `json:"dns_listen,omitempty"`

	// Path is the URI path of the DoH endpoint. It defaults to
	// [doh.DefaultPath].
	Path string `json:"path,omitempty"`

	// Upstreams are the resolvers queries are forwarded to, tried in order.
	// See package [upstream] for the supported URL forms.
	Upstreams []string `json:"upstreams,omitempty"`

	// Timeout bounds how long each query may take, across all upstreams.
	Timeout Duration `json:"timeout,omitempty"`

	// TLS configures how certificates are obtained.
	TLS TLSConfig `json:"tls,omitzero"`

	// Plaintext serves unencrypted HTTP, for use behind a reverse proxy or
	// load balancer that terminates TLS. It can't be combined with TLS.
	Plaintext bool `json:"plaintext,omitempty"`

	// Log configures server logging.
	Log LogConfig `json:"log,omitzero"`

	// Admin configures the admin listener, for metrics and profiling.
	Admin AdminConfig `json:"admin,omitzero"`

	// Blocklist blocks ads, trackers, and malware by name.
	Blocklist BlocklistConfig `json:"blocklist,omitzero"`
}

// Blocklist responses.
const (
	// BlockNXDomain answers blocked names with NXDOMAIN, as if they didn't
	// exist. It's the default.
	BlockNXDomain = "nxdomain"

	// BlockNull answers A and AAAA queries for blocked names with the
	// unspecified address (0.0.0.0 or ::), and others with no records.
	BlockNull = "null"
)

// BlocklistConfig configures blocking names using filter lists. See package
// [blocklist] for the supported list formats.
type BlocklistConfig struct {
	// Sources are the lists to load: preset names (see
	// [blocklist.Presets], or "default"), URLs, or file paths, optionally
	// named as name=location.
	Sources []string `json:"sources,omitempty"`

	// Block lists extra domains to block, along with their subdomains.
	Block []string `json:"block,omitempty"`

	// Allow lists domains never to block, along with their subdomains,
	// whatever the lists say.
	Allow []string `json:"allow,omitempty"`

	// Response is how blocked names are answered: "nxdomain" (the default)
	// or "null".
	Response string `json:"response,omitempty"`

	// Refresh is how often lists are reloaded. It defaults to a day.
	Refresh Duration `json:"refresh,omitempty"`

	// CacheDir stores downloaded lists, so restarts work offline. It
	// defaults to "doh/blocklists" in the user's cache directory.
	CacheDir string `json:"cache_dir,omitempty"`
}

// enabled reports whether any blocking is configured.
func (b BlocklistConfig) enabled() bool {
	return len(b.Sources) > 0 || len(b.Block) > 0
}

// DefaultBlocklistRefresh is how often blocklists are reloaded by default.
const DefaultBlocklistRefresh = 24 * time.Hour

// AdminConfig configures the admin listener, which serves Prometheus
// metrics, expvar-style variables, pprof profiles, and flight recorder
// snapshots for operators.
type AdminConfig struct {
	// Listen is the address of the admin listener, such as
	// "localhost:9090". It's disabled if empty. It should only be reachable
	// by operators, since profiles reveal details about the process.
	Listen string `json:"listen,omitempty"`

	// FlightRecorder keeps the last few seconds of execution trace data in
	// memory, to snapshot from the admin listener when something goes
	// wrong. It's enabled automatically by SlowQuery.
	FlightRecorder bool `json:"flight_recorder,omitempty"`

	// SlowQuery, if set, saves a flight recorder snapshot to TraceDir when
	// a query takes at least this long, at most once a minute.
	SlowQuery Duration `json:"slow_query,omitempty"`

	// TraceDir is where slow query snapshots are saved.
	TraceDir string `json:"trace_dir,omitempty"`
}

// flightRecorder reports whether the flight recorder is enabled.
func (a AdminConfig) flightRecorder() bool {
	return a.FlightRecorder || a.SlowQuery > 0
}

// TLSConfig configures the server certificate, either from files or from
// an ACME certificate authority such as Let's Encrypt.
type TLSConfig struct {
	// CertFile and KeyFile are PEM-encoded certificate chain and private key
	// files. They are reloaded automatically when they change on disk.
	CertFile string `json:"cert_file,omitempty"`
	KeyFile  string `json:"key_file,omitempty"`

	// ACME obtains and renews certificates automatically.
	ACME ACMEConfig `json:"acme,omitzero"`
}

// ACMEConfig configures automatic certificates using the ACME protocol
// (RFC 8555), answering TLS-ALPN-01 challenges on the TLS listener and,
// optionally, HTTP-01 challenges on HTTPListen.
type ACMEConfig struct {
	// Domains are the host names to obtain certificates for. Setting any
	// domain enables ACME, and requests for other names are refused.
	Domains []string `json:"domains,omitempty"`

	// Email is the optional contact address for the ACME account.
	Email string `json:"email,omitempty"`

	// CacheDir stores account keys and certificates between restarts.
	// It defaults to "doh/acme" in the user's cache directory.
	CacheDir string `json:"cache_dir,omitempty"`

	// DirectoryURL is the ACME directory endpoint. It defaults to
	// Let's Encrypt's production directory.
	DirectoryURL string `json:"directory_url,omitempty"`

	// HTTPListen, if set, serves HTTP-01 challenges on this address
	// (typically ":80") and redirects other requests to HTTPS.
	HTTPListen string `json:"http_listen,omitempty"`
}

// LogConfig configures server logging.
type LogConfig struct {
	// Level is "debug", "info", "warn", or "error". It defaults to "info".
	// At "debug", every request is logged.
	Level string `json:"level,omitempty"`

	// Format is "text" or "json". It defaults to "text".
	Format string `json:"format,omitempty"`
}

// Defaults for [Config] fields.
const (
	DefaultListen          = ":443"
	DefaultPlaintextListen = ":8080"
	DefaultTimeout         = 5 * time.Second
)

// DefaultUpstreams are used when no upstreams are configured.
var DefaultUpstreams = []string{doh.Cloudflare, doh.Google}

// LoadFile reads a JSON config file into c, overriding the fields it sets.
//
// The file is decoded with encoding/json/v2, which, unlike encoding/json,
// rejects duplicate keys and matches names exactly. Unknown fields and
// trailing data are rejected too, so typos and mistakes don't go unnoticed.
func (c *Config) LoadFile(name string) error {
	f, err := os.Open(name)
	if err != nil {
		return fmt.Errorf("serve: reading config: %w", err)
	}
	defer f.Close()

	if err := json.UnmarshalRead(f, c, json.RejectUnknownMembers(true)); err != nil {
		return fmt.Errorf("serve: parsing config %s: %w", name, err)
	}

	return nil
}

// withDefaults returns a copy of c with defaults applied to unset fields.
func (c Config) withDefaults() Config {
	if c.Listen == "" {
		c.Listen = DefaultListen
		if c.Plaintext {
			c.Listen = DefaultPlaintextListen
		}
	}

	if c.Path == "" {
		c.Path = doh.DefaultPath
	}

	if len(c.Upstreams) == 0 {
		c.Upstreams = DefaultUpstreams
	}

	if c.Timeout == 0 {
		c.Timeout = Duration(DefaultTimeout)
	}

	if c.Blocklist.enabled() {
		if c.Blocklist.Response == "" {
			c.Blocklist.Response = BlockNXDomain
		}
		if c.Blocklist.Refresh == 0 {
			c.Blocklist.Refresh = Duration(DefaultBlocklistRefresh)
		}
		if c.Blocklist.CacheDir == "" {
			if dir, err := os.UserCacheDir(); err == nil {
				c.Blocklist.CacheDir = filepath.Join(dir, "doh", "blocklists")
			}
		}
	}

	if len(c.TLS.ACME.Domains) > 0 && c.TLS.ACME.CacheDir == "" {
		if dir, err := os.UserCacheDir(); err == nil {
			c.TLS.ACME.CacheDir = filepath.Join(dir, "doh", "acme")
		}
	}

	return c
}

// servesDoH reports whether c configures the DoH listener: with TLS, or
// in plaintext. Without either, only plain DNS is served on DNSListen.
func (c Config) servesDoH() bool {
	return c.Plaintext || c.TLS.CertFile != "" || c.TLS.KeyFile != "" || len(c.TLS.ACME.Domains) > 0
}

// Validate reports whether c is complete and consistent, after defaults.
func (c Config) Validate() error {
	listen := c.Listen
	c = c.withDefaults()

	var errs []error

	if err := validatePath(c.Path); err != nil {
		errs = append(errs, err)
	}

	if c.Timeout < 0 {
		errs = append(errs, errors.New("timeout must not be negative"))
	}

	if c.DNSListen != "" {
		if _, _, err := net.SplitHostPort(c.DNSListen); err != nil {
			errs = append(errs, fmt.Errorf("dns_listen: %w", err))
		}
	}

	for _, u := range c.Upstreams {
		if _, err := upstream.Parse(u, upstream.Options{}); err != nil {
			errs = append(errs, err)
		}
	}

	files := c.TLS.CertFile != "" || c.TLS.KeyFile != ""
	acme := len(c.TLS.ACME.Domains) > 0

	switch {
	case files && (c.TLS.CertFile == "" || c.TLS.KeyFile == ""):
		errs = append(errs, errors.New("tls: cert_file and key_file must be set together"))
	case files && acme:
		errs = append(errs, errors.New("tls: use either certificate files or ACME, not both"))
	case c.Plaintext && (files || acme):
		errs = append(errs, errors.New("plaintext can't be combined with TLS settings"))
	case !c.Plaintext && !files && !acme && c.DNSListen == "":
		errs = append(errs, errors.New("no TLS certificate configured: set a certificate and key, an ACME domain, or plaintext to serve behind a TLS-terminating proxy (or dns_listen to serve only plain DNS)"))
	case !c.servesDoH() && listen != "":
		errs = append(errs, errors.New("listen needs a TLS certificate, an ACME domain, or plaintext; without them only plain DNS is served on dns_listen"))
	}

	if c.TLS.ACME.HTTPListen != "" && !acme {
		errs = append(errs, errors.New("tls: acme http_listen requires an ACME domain"))
	}

	if acme && c.TLS.ACME.CacheDir == "" {
		errs = append(errs, errors.New("tls: acme cache_dir is required (no user cache directory found)"))
	}

	if c.Blocklist.enabled() {
		for _, src := range c.Blocklist.Sources {
			if _, err := blocklist.ParseSource(src); err != nil {
				errs = append(errs, err)
			}
		}

		switch c.Blocklist.Response {
		case BlockNXDomain, BlockNull:
		default:
			errs = append(errs, fmt.Errorf("blocklist response %q must be %q or %q", c.Blocklist.Response, BlockNXDomain, BlockNull))
		}

		if c.Blocklist.Refresh < Duration(time.Minute) {
			errs = append(errs, errors.New("blocklist refresh must be at least a minute"))
		}
	} else if len(c.Blocklist.Allow) > 0 {
		errs = append(errs, errors.New("blocklist allow needs blocklist sources or block domains"))
	}

	if c.Admin.Listen != "" {
		if _, _, err := net.SplitHostPort(c.Admin.Listen); err != nil {
			errs = append(errs, fmt.Errorf("admin listen: %w", err))
		}
	}

	switch {
	case c.Admin.SlowQuery < 0:
		errs = append(errs, errors.New("admin slow_query must not be negative"))
	case c.Admin.SlowQuery > 0 && c.Admin.TraceDir == "":
		errs = append(errs, errors.New("admin slow_query needs a trace_dir to save snapshots to"))
	case c.Admin.TraceDir != "" && c.Admin.SlowQuery == 0:
		errs = append(errs, errors.New("admin trace_dir is only used with slow_query"))
	case c.Admin.FlightRecorder && c.Admin.Listen == "" && c.Admin.SlowQuery == 0:
		errs = append(errs, errors.New("admin flight_recorder needs an admin listen address or slow_query to snapshot it"))
	}

	if _, err := c.Log.handler(os.Stderr); err != nil {
		errs = append(errs, err)
	}

	return errors.Join(errs...)
}

// validatePath reports whether p can serve the DoH endpoint: a clean,
// absolute path that isn't the health check, without the wildcard braces,
// percent escapes, or whitespace that [http.ServeMux] patterns interpret.
func validatePath(p string) error {
	switch {
	case p == "" || p[0] != '/':
		return fmt.Errorf("path %q must start with /", p)
	case path.Clean(p) != p:
		return fmt.Errorf("path %q must be clean, without empty, . or .. segments or a trailing slash (try %q)", p, path.Clean(p))
	case strings.ContainsAny(p, "{}% \t\r\n"):
		return fmt.Errorf("path %q must not contain braces, percent escapes, or whitespace", p)
	case p == HealthPath:
		return fmt.Errorf("path %q is reserved for the health check", p)
	default:
		return nil
	}
}

// handler returns the slog handler described by l.
func (l LogConfig) handler(w *os.File) (slog.Handler, error) {
	var level slog.Level
	if l.Level != "" {
		if err := level.UnmarshalText([]byte(l.Level)); err != nil {
			return nil, fmt.Errorf("log: invalid level %q", l.Level)
		}
	}

	opts := &slog.HandlerOptions{Level: level}

	switch l.Format {
	case "", "text":
		return slog.NewTextHandler(w, opts), nil
	case "json":
		return slog.NewJSONHandler(w, opts), nil
	default:
		return nil, fmt.Errorf("log: invalid format %q (want text or json)", l.Format)
	}
}

// Logger returns the logger described by l, writing to standard error.
func (l LogConfig) Logger() (*slog.Logger, error) {
	h, err := l.handler(os.Stderr)
	if err != nil {
		return nil, err
	}

	return slog.New(h), nil
}

// Duration is a [time.Duration] that encodes as text such as "5s" or
// "1m30s", in JSON and other text-based formats.
type Duration time.Duration

// MarshalText implements [encoding.TextMarshaler].
func (d Duration) MarshalText() ([]byte, error) {
	return []byte(time.Duration(d).String()), nil
}

// UnmarshalText implements [encoding.TextUnmarshaler].
func (d *Duration) UnmarshalText(b []byte) error {
	v, err := time.ParseDuration(string(b))
	if err != nil {
		return fmt.Errorf("duration must be a string such as \"5s\": %w", err)
	}

	*d = Duration(v)
	return nil
}
