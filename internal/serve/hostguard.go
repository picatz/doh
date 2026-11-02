package serve

import (
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/picatz/doh/internal/policy"
)

// The admin listener refuses requests whose Host header names a host it
// doesn't answer to, so DNS rebinding can't turn a browser into a way in.
//
// In a rebinding attack, a page on attacker.example has its name re-resolve
// to an address of the victim's network, such as 127.0.0.1 or a home
// server, and then reads from it in the victim's browser, as its own
// origin: the same-origin policy is satisfied, since the origin is still
// attacker.example. The one thing the browser can't hide is that name, in
// the Host header. So the listener only answers to names an attacker on
// the internet can't point at it:
//
//   - IP addresses, which aren't names at all;
//   - localhost and *.localhost, which browsers resolve to loopback
//     themselves (RFC 6761, Section 6.3);
//   - single-label names, such as "doh" from Docker or a router's DNS,
//     since public DNS has no names without a dot;
//   - names under suffixes that public DNS never delegates, which resolve
//     only on the local network: .local (mDNS), .home.arpa (RFC 8375),
//     .internal (ICANN's private use), and the routers' .lan,
//     .localdomain, and .home;
//   - *.ts.net, Tailscale's MagicDNS names, whose DNS Tailscale alone
//     answers, with the tailnet's own addresses;
//   - and names the operator configured: the hosts of --admin-origin,
//     --hostname and --acme-domain, and --admin-host.
//
// Names that resolve only locally are as trustworthy as the local
// network's name resolution: anyone on the link can claim a .local name
// over mDNS, or a single-label one over LLMNR. That's someone who can
// already reach the listener directly, except one bound to loopback,
// whose open profiling endpoints therefore also need a loopback host, or
// credentials (see [Server.requireOperator]).

// localSuffixes are the name suffixes that resolve only on a local
// network.
var localSuffixes = []string{".local", ".home.arpa", ".internal", ".lan", ".localdomain", ".home"}

// tailscaleSuffix is Tailscale's MagicDNS domain.
const tailscaleSuffix = ".ts.net"

// hostPattern is a host name the admin listener answers to: exactly, or
// with subdomains, any name under it.
type hostPattern struct {
	name       string
	subdomains bool
}

func (p hostPattern) matches(host string) bool {
	if p.subdomains {
		return strings.HasSuffix(host, "."+p.name)
	}
	return host == p.name
}

// parseAdminHost reads an --admin-host value: a host name, or "*." and
// one for its subdomains, without a scheme, port, or path.
func parseAdminHost(s string) (hostPattern, bool) {
	s = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), "."))
	var p hostPattern
	if rest, ok := strings.CutPrefix(s, "*."); ok {
		s, p.subdomains = rest, true
	}
	if s == "" || strings.ContainsAny(s, ":/@ *?#[]") {
		return hostPattern{}, false
	}
	name, ok := policy.NormalizeDomain(s)
	if !ok {
		return hostPattern{}, false
	}
	p.name = strings.TrimSuffix(name, ".")
	return p, true
}

// adminHostPatterns returns the hosts c configures the admin listener to
// answer to, beyond those it always does.
func adminHostPatterns(c Config) []hostPattern {
	var out []hostPattern
	add := func(h string) {
		if p, ok := parseAdminHost(h); ok && !slices.Contains(out, p) {
			out = append(out, p)
		}
	}
	for _, h := range c.Admin.Hosts {
		add(h)
	}
	for _, o := range c.Admin.Origins {
		if u, err := url.Parse(o); err == nil {
			add(u.Hostname())
		}
	}
	if c.Hostname != "" {
		add(c.Hostname)
	}
	for _, d := range c.TLS.ACME.Domains {
		add(d)
	}
	return out
}

// hostOf returns the host a Host header names, without its port, in lower
// case, without a trailing dot, and for an IPv6 literal, without its
// brackets. ok is false if it can't be a host.
func hostOf(hostport string) (host string, ok bool) {
	host = hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		host = h
	} else if strings.HasPrefix(hostport, "[") && strings.HasSuffix(hostport, "]") {
		host = hostport[1 : len(hostport)-1]
	}
	if len(host) > 255 || strings.ContainsAny(host, "/@ \t\\") {
		return "", false
	}
	return strings.ToLower(strings.TrimSuffix(host, ".")), true
}

// isLoopbackHost reports whether host names this machine to a browser: a
// loopback address, localhost, or a name under localhost.
func isLoopbackHost(host string) bool {
	if a, err := netip.ParseAddr(host); err == nil {
		return a.Unmap().IsLoopback()
	}
	return host == "localhost" || strings.HasSuffix(host, ".localhost")
}

// alwaysAllowedHost reports whether host is one the admin listener
// answers to whatever it's configured with: see the top of this file.
func alwaysAllowedHost(host string) bool {
	if host == "" {
		return true // not from a browser, which always sends one
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return true
	}
	if isLoopbackHost(host) || !strings.Contains(host, ".") {
		return true
	}
	for _, suffix := range localSuffixes {
		if strings.HasSuffix(host, suffix) {
			return true
		}
	}
	return strings.HasSuffix(host, tailscaleSuffix)
}

// configuredHost reports whether the operator configured the admin
// listener to answer to host.
func (s *Server) configuredHost(host string) bool {
	return slices.ContainsFunc(s.adminHosts, func(p hostPattern) bool { return p.matches(host) })
}

// hostGuard refuses requests to hosts the admin listener doesn't answer
// to, with 421 Misdirected Request, saying which setting would allow
// them. The health check answers to any host, for load balancers.
func (s *Server) hostGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, ok := hostOf(r.Host)
		if ok && (alwaysAllowedHost(host) || s.configuredHost(host)) || r.URL.Path == HealthPath {
			next.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		if !ok {
			writeError(w, http.StatusMisdirectedRequest, "the admin listener doesn't answer to the host "+strconv.Quote(r.Host))
			return
		}
		writeError(w, http.StatusMisdirectedRequest,
			"the admin listener doesn't answer to the host "+strconv.Quote(host)+", which protects it from DNS rebinding; "+
				"if that's the name you reach it at, restart doh serve with --admin-host "+host+
				" (or with --admin-origin, if the web UI is opened there)")
	})
}
