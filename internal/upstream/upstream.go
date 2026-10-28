// Package upstream exchanges DNS messages with upstream resolvers over
// DNS-over-HTTPS, DNS-over-TLS, or plain DNS (UDP and TCP).
//
// Upstreams are identified by URL:
//
//	https://dns.google/dns-query   DNS-over-HTTPS (RFC 8484)
//	tls://1.1.1.1:853              DNS-over-TLS (RFC 7858)
//	tcp://9.9.9.9:53               DNS over TCP
//	udp://9.9.9.9:53               DNS over UDP, retried over TCP if truncated
//	9.9.9.9                        shorthand for udp://9.9.9.9:53
package upstream

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/picatz/doh/pkg/doh"
)

// DefaultTimeout bounds each exchange with a plain DNS or DNS-over-TLS
// upstream when the context has no earlier deadline.
const DefaultTimeout = 5 * time.Second

// Exchanger sends a DNS query to an upstream resolver and returns its
// response.
//
// Implementations must not modify the query, and must return a response
// whose ID matches the query's ID.
type Exchanger interface {
	Exchange(ctx context.Context, query *dns.Msg) (*dns.Msg, error)
}

// Options configures upstreams created by [Parse].
type Options struct {
	// HTTPClient is used for DNS-over-HTTPS upstreams.
	// If nil, [http.DefaultClient] is used.
	HTTPClient *http.Client

	// TLSConfig is used for DNS-over-TLS upstreams. Its ServerName defaults
	// to the upstream's host. If nil, a default configuration is used.
	TLSConfig *tls.Config

	// Timeout bounds each plain DNS and DNS-over-TLS exchange.
	// If zero, [DefaultTimeout] is used.
	Timeout time.Duration
}

// Parse returns an [Exchanger] for the upstream identified by rawURL.
func Parse(rawURL string, opts Options) (Exchanger, error) {
	if !strings.Contains(rawURL, "://") {
		rawURL = "udp://" + rawURL
	}

	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("upstream: invalid URL %q: %w", rawURL, err)
	}

	if u.Host == "" {
		return nil, fmt.Errorf("upstream: missing host in %q", rawURL)
	}

	timeout := opts.Timeout
	if timeout == 0 {
		timeout = DefaultTimeout
	}

	switch u.Scheme {
	case "https":
		client := opts.HTTPClient
		if client == nil {
			client = http.DefaultClient
		}
		return &dohUpstream{url: u.String(), client: client}, nil
	case "udp", "tcp":
		addr := withDefaultPort(u.Host, "53")
		return &dnsUpstream{
			addr: addr,
			udp:  u.Scheme == "udp",
			client: &dns.Client{
				Net:     "udp",
				Timeout: timeout,
			},
			tcpClient: &dns.Client{
				Net:     "tcp",
				Timeout: timeout,
			},
		}, nil
	case "tls":
		addr := withDefaultPort(u.Host, "853")

		tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
		if opts.TLSConfig != nil {
			tlsConfig = opts.TLSConfig.Clone()
		}
		if tlsConfig.ServerName == "" {
			tlsConfig.ServerName = u.Hostname()
		}

		return &dnsUpstream{
			addr: addr,
			tcpClient: &dns.Client{
				Net:       "tcp-tls",
				Timeout:   timeout,
				TLSConfig: tlsConfig,
			},
		}, nil
	default:
		return nil, fmt.Errorf("upstream: unsupported scheme %q in %q (want https, tls, tcp, or udp)", u.Scheme, rawURL)
	}
}

// withDefaultPort appends port to host if it has none.
func withDefaultPort(host, port string) string {
	if _, _, err := net.SplitHostPort(host); err == nil {
		return host
	}

	return net.JoinHostPort(strings.Trim(host, "[]"), port)
}

// dohUpstream is a DNS-over-HTTPS upstream.
type dohUpstream struct {
	url    string
	client *http.Client
}

func (u *dohUpstream) Exchange(ctx context.Context, query *dns.Msg) (*dns.Msg, error) {
	// RFC 8484, Section 4.1 recommends an ID of 0 to maximize HTTP cache
	// hits, so send a copy with ID 0 and restore the ID on the response.
	q := query.Copy()
	q.Id = 0

	resp, err := doh.Query(ctx, u.client, u.url, q)
	if err != nil {
		return nil, err
	}

	resp.Id = query.Id
	return resp, nil
}

func (u *dohUpstream) String() string { return u.url }

// dnsUpstream is a plain DNS or DNS-over-TLS upstream.
type dnsUpstream struct {
	addr string

	// udp reports whether queries are sent over UDP first, falling back
	// to tcpClient when the response is truncated.
	udp bool

	client    *dns.Client
	tcpClient *dns.Client
}

func (u *dnsUpstream) Exchange(ctx context.Context, query *dns.Msg) (*dns.Msg, error) {
	// Use a fresh random ID on the wire, so responses can't be spoofed by
	// guessing a client-chosen (often zero) ID.
	q := query.Copy()
	q.Id = dns.Id()

	client := u.tcpClient
	if u.udp {
		client = u.client
	}

	resp, _, err := client.ExchangeContext(ctx, q, u.addr)
	if err == nil && resp.Truncated && u.udp {
		resp, _, err = u.tcpClient.ExchangeContext(ctx, q, u.addr)
	}
	if err != nil {
		return nil, fmt.Errorf("upstream %s: %w", u, err)
	}

	if resp.Id != q.Id {
		return nil, fmt.Errorf("upstream %s: response ID mismatch", u)
	}

	resp.Id = query.Id
	return resp, nil
}

func (u *dnsUpstream) String() string {
	switch u.tcpClient.Net {
	case "tcp-tls":
		return "tls://" + u.addr
	default:
		if u.udp {
			return "udp://" + u.addr
		}
		return "tcp://" + u.addr
	}
}

// ErrAllFailed is returned by [Failover] when every upstream fails.
var ErrAllFailed = errors.New("upstream: all upstreams failed")

// Failover is an [Exchanger] that tries each upstream in order, returning
// the first successful response.
//
// A response with any DNS response code counts as success; only transport
// failures move on to the next upstream. If every upstream fails, the
// returned error matches [ErrAllFailed] and includes each upstream's error.
type Failover []Exchanger

func (f Failover) Exchange(ctx context.Context, query *dns.Msg) (*dns.Msg, error) {
	errs := []error{ErrAllFailed}

	for _, upstream := range f {
		resp, err := upstream.Exchange(ctx, query)
		if err == nil {
			return resp, nil
		}

		errs = append(errs, err)

		if ctx.Err() != nil {
			break
		}
	}

	return nil, errors.Join(errs...)
}

// Handler adapts an [Exchanger] to a [doh.Handler].
func Handler(e Exchanger) doh.Handler {
	return func(w http.ResponseWriter, r *http.Request, query *dns.Msg) (*dns.Msg, error) {
		return e.Exchange(r.Context(), query)
	}
}
