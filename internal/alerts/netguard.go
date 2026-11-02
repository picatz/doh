package alerts

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Delivery timeouts.
const (
	dialTimeout    = 5 * time.Second
	requestTimeout = 10 * time.Second
)

// errRefused reports a destination address doh won't connect to.
var errRefused = errors.New("refused")

// addrPolicy is which addresses a client may connect to.
type addrPolicy int

const (
	// anyAddr allows every address: the operator's https destinations.
	anyAddr addrPolicy = iota

	// publicOnly allows only publicly routable addresses: tenants'
	// destinations, so a tenant can't make the server reach services on
	// its own network (server-side request forgery).
	publicOnly

	// loopbackOnly allows only loopback addresses: the operator's http
	// destinations, for testing.
	loopbackOnly
)

// allows reports whether p allows connecting to a.
func (p addrPolicy) allows(a netip.Addr) bool {
	a = a.Unmap()
	switch p {
	case publicOnly:
		return public(a)
	case loopbackOnly:
		return a.IsLoopback()
	}
	return a.IsValid()
}

// nonPublic are special-purpose ranges that aren't publicly routable, or
// that embed or translate to other addresses, beyond those netip
// classifies ([RFC 6890], and IANA's IPv4 and IPv6 special-purpose
// address registries).
//
// [RFC 6890]: https://www.rfc-editor.org/rfc/rfc6890.html
var nonPublic = func() []netip.Prefix {
	var out []netip.Prefix
	for _, s := range []string{
		"0.0.0.0/8",       // "this network"
		"100.64.0.0/10",   // shared address space (CGNAT), RFC 6598
		"192.0.0.0/24",    // IETF protocol assignments
		"192.0.2.0/24",    // documentation (TEST-NET-1)
		"198.18.0.0/15",   // benchmarking
		"198.51.100.0/24", // documentation (TEST-NET-2)
		"203.0.113.0/24",  // documentation (TEST-NET-3)
		"240.0.0.0/4",     // reserved
		"64:ff9b::/96",    // NAT64, which could translate to private IPv4
		"64:ff9b:1::/48",  // local-use NAT64
		"100::/64",        // discard-only
		"2001::/32",       // Teredo, which embeds IPv4
		"2001:db8::/32",   // documentation
		"2002::/16",       // 6to4, which embeds IPv4
		"fec0::/10",       // deprecated site-local
	} {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}()

// public reports whether a is a publicly routable unicast address: not
// loopback, private, link-local (which includes cloud metadata services
// such as 169.254.169.254), multicast, unspecified, or special-purpose.
func public(a netip.Addr) bool {
	a = a.Unmap()
	if !a.IsGlobalUnicast() || a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() {
		return false
	}
	for _, p := range nonPublic {
		if p.Contains(a) {
			return false
		}
	}
	return true
}

// control refuses connections to addresses p doesn't allow, as a
// [net.Dialer]'s Control function, once the address to connect to is
// known.
func (p addrPolicy) control(_, address string, _ syscall.RawConn) error {
	ap, err := netip.ParseAddrPort(address)
	if err != nil || !p.allows(ap.Addr()) {
		return fmt.Errorf("%w: %s isn't an address alerts may be sent to", errRefused, address)
	}
	return nil
}

// lookupFunc resolves a host name to addresses.
type lookupFunc func(ctx context.Context, host string) ([]netip.Addr, error)

// defaultLookup resolves with the system's resolver.
func defaultLookup(ctx context.Context, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

// newClient returns an HTTP client for delivering alerts that connects
// only to addresses p allows, and never follows redirects.
//
// Every address a host name resolves to must be allowed, and each
// connection's address is checked again as it's made, by the dialer's
// Control function, so a name can't resolve to a public address when
// checked and a private one when dialed. With proxy, requests go through
// the environment's proxy (HTTPS_PROXY and the like), which then decides
// where they may go; it's used only where any address is allowed.
func newClient(p addrPolicy, lookup lookupFunc, proxy bool) *http.Client {
	dialer := &net.Dialer{Timeout: dialTimeout, Control: p.control}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(address)
			if err != nil {
				return nil, err
			}
			addrs, err := resolve(ctx, lookup, host)
			if err != nil {
				return nil, err
			}
			for _, a := range addrs {
				if !p.allows(a) {
					return nil, fmt.Errorf("%w: %s is at %s, which isn't an address alerts may be sent to", errRefused, host, a.Unmap())
				}
			}
			var errs []error
			for _, a := range addrs {
				conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(a.Unmap().String(), port))
				if err == nil {
					return conn, nil
				}
				errs = append(errs, err)
			}
			return nil, errors.Join(errs...)
		},
		ForceAttemptHTTP2:      true,
		TLSHandshakeTimeout:    dialTimeout,
		ResponseHeaderTimeout:  requestTimeout,
		MaxResponseHeaderBytes: 16 << 10,
		MaxIdleConns:           16,
		IdleConnTimeout:        time.Minute,
	}
	if proxy {
		transport.Proxy = http.ProxyFromEnvironment
	}
	return &http.Client{
		Transport: transport,
		Timeout:   requestTimeout,
		// Never follow redirects: a destination that redirects fails,
		// rather than sending an alert somewhere no one chose.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// resolve returns host's addresses: itself, if it's an address.
func resolve(ctx context.Context, lookup lookupFunc, host string) ([]netip.Addr, error) {
	if a, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{a}, nil
	}
	addrs, err := lookup(ctx, host)
	if err != nil {
		return nil, err
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("%s has no addresses", host)
	}
	return addrs, nil
}

// maxURLLength bounds destination URLs.
const maxURLLength = 2048

// checkURL parses a destination's URL, which must be https, or for the
// operator (the empty scope), http to a loopback address, for testing.
// For tenants, it refuses addresses and names that are obviously not
// public; the client refuses the rest when it connects.
func checkURL(scope string, t DestinationType, raw string) (*url.URL, error) {
	if raw == "" || len(raw) > maxURLLength {
		return nil, fmt.Errorf("%w: a destination needs a URL of at most %d characters", ErrInvalid, maxURLLength)
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.Opaque != "" {
		return nil, fmt.Errorf("%w: %q isn't an absolute URL, such as https://ntfy.sh/your-topic", ErrInvalid, raw)
	}
	if u.Fragment != "" || strings.Contains(raw, "#") {
		return nil, fmt.Errorf("%w: a destination URL can't have a fragment (#)", ErrInvalid)
	}
	if port := u.Port(); port != "" {
		if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("%w: invalid port %q", ErrInvalid, port)
		}
	}

	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	addr, err := netip.ParseAddr(host)
	isAddr := err == nil
	loopback := host == "localhost" || strings.HasSuffix(host, ".localhost") || isAddr && addr.IsLoopback()

	switch u.Scheme {
	case "https":
	case "http":
		if scope != "" || !loopback {
			return nil, fmt.Errorf("%w: destinations must use https (only the operator may use http, and only to a loopback address, for testing)", ErrInvalid)
		}
	default:
		return nil, fmt.Errorf("%w: destinations must use https", ErrInvalid)
	}

	if scope != "" {
		// A name without a dot resolves through the server's own search
		// domains, so it's as good as private.
		if loopback || isAddr && !public(addr) || !isAddr && !strings.Contains(host, ".") {
			return nil, fmt.Errorf("%w: %s isn't a public address; alerts can only be sent to services on the internet", ErrInvalid, u.Hostname())
		}
	}

	if t == Ntfy && strings.Trim(u.Path, "/") == "" {
		return nil, fmt.Errorf("%w: an ntfy URL names a topic, such as https://ntfy.sh/your-topic", ErrInvalid)
	}
	return u, nil
}

// redactURL returns u with any password replaced, for showing.
func redactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Redacted()
}
