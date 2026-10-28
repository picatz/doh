// Package upstream exchanges DNS messages with upstream resolvers over
// DNS-over-HTTPS, DNS-over-TLS, or plain DNS (UDP and TCP).
//
// Upstreams are identified by URL:
//
//	https://dns.google/dns-query   DNS-over-HTTPS (RFC 8484)
//	http://127.0.0.1:8080/dns-query  DoH without TLS, such as to a local server
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
	"net/http/httptrace"
	"net/url"
	"slices"
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
	// HTTPClient is used for DNS-over-HTTPS upstreams. Its CheckRedirect
	// should refuse redirects to plain HTTP, as [CheckRedirect] does.
	// If nil, a client using [CheckRedirect] is used.
	HTTPClient *http.Client

	// TLSConfig is used for DNS-over-TLS upstreams. Its ServerName defaults
	// to the upstream's host. If nil, a default configuration is used.
	TLSConfig *tls.Config

	// Timeout bounds each plain DNS and DNS-over-TLS exchange.
	// If zero, [DefaultTimeout] is used.
	Timeout time.Duration

	// Dialer, if set, dials plain DNS and DNS-over-TLS connections, such as
	// to resolve upstream names with a particular resolver. DNS-over-HTTPS
	// upstreams dial with HTTPClient's transport instead.
	Dialer *net.Dialer
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
	case "https", "http":
		client := opts.HTTPClient
		if client == nil {
			client = &http.Client{CheckRedirect: CheckRedirect}
		}
		return &dohUpstream{url: u.String(), name: u.Redacted(), client: client}, nil
	case "udp", "tcp":
		addr := withDefaultPort(u.Host, "53")
		return &dnsUpstream{
			addr: addr,
			udp:  u.Scheme == "udp",
			client: &dns.Client{
				Net:     "udp",
				Timeout: timeout,
				Dialer:  opts.Dialer,
			},
			tcpClient: &dns.Client{
				Net:     "tcp",
				Timeout: timeout,
				Dialer:  opts.Dialer,
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
				Dialer:    opts.Dialer,
			},
		}, nil
	default:
		return nil, fmt.Errorf("upstream: unsupported scheme %q in %q (want https, http, tls, tcp, or udp)", u.Scheme, rawURL)
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
	name   string // url with any password redacted
	client *http.Client
}

func (u *dohUpstream) Exchange(ctx context.Context, query *dns.Msg) (*dns.Msg, error) {
	// RFC 8484, Section 4.1 recommends an ID of 0 to maximize HTTP cache
	// hits, so send a copy with ID 0 and restore the ID on the response.
	q := query.Copy()
	q.Id = 0

	if observe := tlsObserver(ctx); observe != nil {
		ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
			GotConn: func(info httptrace.GotConnInfo) {
				if c, ok := info.Conn.(interface{ ConnectionState() tls.ConnectionState }); ok {
					observe(c.ConnectionState())
				}
			},
		})
	}

	resp, err := doh.Query(ctx, u.client, u.url, q)
	if err != nil {
		return nil, err
	}

	if err := validate(query, resp); err != nil {
		return nil, fmt.Errorf("upstream %s: %w", u, err)
	}

	resp.Id = query.Id
	return resp, nil
}

func (u *dohUpstream) String() string { return u.name }

// CheckRedirect is an [http.Client] redirect policy for DNS-over-HTTPS
// upstreams: it follows up to 10 redirects, like the default policy, but
// refuses any to a URL that isn't HTTPS once the chain has used HTTPS,
// which would expose queries.
func CheckRedirect(req *http.Request, via []*http.Request) error {
	usedHTTPS := slices.ContainsFunc(via, func(r *http.Request) bool { return r.URL.Scheme == "https" })
	if usedHTTPS && req.URL.Scheme != "https" {
		return fmt.Errorf("refusing redirect from HTTPS to %s", req.URL.Redacted())
	}

	if len(via) >= 10 {
		return errors.New("stopped after 10 redirects")
	}

	return nil
}

// validate reports whether resp answers query: it must be a response, and
// echo the query's question. Only error responses may omit the question
// section, as some servers do when they can't parse a query.
func validate(query, resp *dns.Msg) error {
	if !resp.Response {
		return errors.New("got a query, not a response")
	}

	if len(resp.Question) == 0 {
		if resp.Rcode == dns.RcodeSuccess {
			return errors.New("successful response has no question")
		}
		return nil
	}

	if len(resp.Question) != len(query.Question) {
		return errors.New("response question doesn't match the query")
	}

	for i, q := range query.Question {
		r := resp.Question[i]
		if !strings.EqualFold(q.Name, r.Name) || q.Qtype != r.Qtype || q.Qclass != r.Qclass {
			return fmt.Errorf("response question %s doesn't match the query's %s", r.String(), q.String())
		}
	}

	return nil
}

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

	resp, err := u.exchange(ctx, client, q)
	if err == nil && resp.Truncated && u.udp {
		resp, _, err = u.tcpClient.ExchangeContext(ctx, q, u.addr)
	}
	if err != nil {
		return nil, fmt.Errorf("upstream %s: %w", u, err)
	}

	if resp.Id != q.Id {
		return nil, fmt.Errorf("upstream %s: response ID mismatch", u)
	}

	if err := validate(query, resp); err != nil {
		return nil, fmt.Errorf("upstream %s: %w", u, err)
	}

	resp.Id = query.Id
	return resp, nil
}

// exchange sends q with client, reporting the TLS connection state of
// DNS-over-TLS exchanges to the context's TLS observer, if any.
func (u *dnsUpstream) exchange(ctx context.Context, client *dns.Client, q *dns.Msg) (*dns.Msg, error) {
	observe := tlsObserver(ctx)
	if observe == nil || client.Net != "tcp-tls" {
		resp, _, err := client.ExchangeContext(ctx, q, u.addr)
		return resp, err
	}

	conn, err := client.DialContext(ctx, u.addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if c, ok := conn.Conn.(*tls.Conn); ok {
		observe(c.ConnectionState())
	}

	resp, _, err := client.ExchangeWithConnContext(ctx, q, conn)
	return resp, err
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

type tlsObserverKey struct{}

// WithTLSObserver returns a context that reports the TLS connection state
// of each DNS-over-HTTPS and DNS-over-TLS exchange made with it to observe,
// like [net/http/httptrace] does for HTTP requests.
func WithTLSObserver(ctx context.Context, observe func(tls.ConnectionState)) context.Context {
	return context.WithValue(ctx, tlsObserverKey{}, observe)
}

// tlsObserver returns the context's TLS observer, or nil.
func tlsObserver(ctx context.Context) func(tls.ConnectionState) {
	observe, _ := ctx.Value(tlsObserverKey{}).(func(tls.ConnectionState))
	return observe
}

// ErrAllFailed is returned by [Failover] when every upstream fails.
var ErrAllFailed = errors.New("upstream: all upstreams failed")

// Failover is an [Exchanger] that tries each upstream in order, returning
// the first successful response.
//
// When the context has a deadline, each upstream gets an equal share of the
// time remaining when it's tried, so a slow or unresponsive upstream still
// leaves time for the next.
//
// A response with any DNS response code counts as success; only transport
// failures move on to the next upstream. If every upstream fails, the
// returned error matches [ErrAllFailed] and includes each upstream's error.
type Failover []Exchanger

func (f Failover) Exchange(ctx context.Context, query *dns.Msg) (*dns.Msg, error) {
	errs := []error{ErrAllFailed}

	for i, upstream := range f {
		resp, err := f.exchange(ctx, upstream, len(f)-i, query)
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

// exchange queries upstream with an equal share of the time left before
// ctx's deadline among the remaining upstreams, so one unresponsive
// upstream can't use up the time the others need.
func (Failover) exchange(ctx context.Context, upstream Exchanger, remaining int, query *dns.Msg) (*dns.Msg, error) {
	if deadline, ok := ctx.Deadline(); ok && remaining > 1 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Until(deadline)/time.Duration(remaining))
		defer cancel()
	}

	return upstream.Exchange(ctx, query)
}

// Handler adapts an [Exchanger] to a [doh.Handler].
func Handler(e Exchanger) doh.Handler {
	return func(w http.ResponseWriter, r *http.Request, query *dns.Msg) (*dns.Msg, error) {
		return e.Exchange(r.Context(), query)
	}
}
