// Package serve implements the DNS-over-HTTPS server behind "doh serve".
package serve

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

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
	// speak DoH can use the server as their resolver.
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
// Unknown fields are rejected, so typos don't silently go unnoticed.
func (c *Config) LoadFile(name string) error {
	b, err := os.ReadFile(name)
	if err != nil {
		return fmt.Errorf("serve: reading config: %w", err)
	}

	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()

	if err := dec.Decode(c); err != nil {
		return fmt.Errorf("serve: parsing config %s: %w", name, err)
	}

	if _, err := dec.Token(); err != io.EOF {
		return fmt.Errorf("serve: parsing config %s: unexpected data after the config object", name)
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

	if len(c.TLS.ACME.Domains) > 0 && c.TLS.ACME.CacheDir == "" {
		if dir, err := os.UserCacheDir(); err == nil {
			c.TLS.ACME.CacheDir = filepath.Join(dir, "doh", "acme")
		}
	}

	return c
}

// Validate reports whether c is complete and consistent, after defaults.
func (c Config) Validate() error {
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
	case !c.Plaintext && !files && !acme:
		errs = append(errs, errors.New("no TLS certificate configured: set a certificate and key, an ACME domain, or plaintext to serve behind a TLS-terminating proxy"))
	}

	if c.TLS.ACME.HTTPListen != "" && !acme {
		errs = append(errs, errors.New("tls: acme http_listen requires an ACME domain"))
	}

	if acme && c.TLS.ACME.CacheDir == "" {
		errs = append(errs, errors.New("tls: acme cache_dir is required (no user cache directory found)"))
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

// Duration is a [time.Duration] that encodes to and from JSON as a string
// such as "5s" or "1m30s".
type Duration time.Duration

// MarshalJSON implements [json.Marshaler].
func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).String())
}

// UnmarshalJSON implements [json.Unmarshaler].
func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return fmt.Errorf("duration must be a string such as \"5s\": %w", err)
	}

	v, err := time.ParseDuration(s)
	if err != nil {
		return err
	}

	*d = Duration(v)
	return nil
}
