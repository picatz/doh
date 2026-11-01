package filter

import "net/netip"

// rebindingPrefixes are addresses a public name has no business resolving
// to, since they reach the client itself or its local network: the
// targets of DNS rebinding attacks.
//
// The shared address space 100.64.0.0/10 (RFC 6598) isn't included, since
// carrier-grade NAT and overlay networks such as Tailscale use it for
// addresses that public names legitimately point to.
var rebindingPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),      // "this network"; browsers treat 0.0.0.0 as localhost
	netip.MustParsePrefix("10.0.0.0/8"),     // RFC 1918
	netip.MustParsePrefix("127.0.0.0/8"),    // loopback
	netip.MustParsePrefix("169.254.0.0/16"), // link-local, including cloud metadata services
	netip.MustParsePrefix("172.16.0.0/12"),  // RFC 1918
	netip.MustParsePrefix("192.168.0.0/16"), // RFC 1918
	netip.MustParsePrefix("::/128"),         // unspecified
	netip.MustParsePrefix("::1/128"),        // loopback
	netip.MustParsePrefix("fc00::/7"),       // unique local (RFC 4193)
	netip.MustParsePrefix("fe80::/10"),      // link-local
}

// nat64 is the well-known NAT64 prefix (RFC 6052), whose addresses embed
// an IPv4 address in their last 32 bits.
var nat64 = netip.MustParsePrefix("64:ff9b::/96")

// IsRebindingTarget reports whether addr is a local address that a public
// name pointing to would let a web page reach: loopback, private,
// link-local, or unspecified, including such IPv4 addresses mapped into
// IPv6 or embedded in NAT64 addresses.
func IsRebindingTarget(addr netip.Addr) bool {
	addr = addr.Unmap().WithZone("")
	if nat64.Contains(addr) {
		b := addr.As16()
		addr = netip.AddrFrom4([4]byte(b[12:]))
	}
	for _, p := range rebindingPrefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}
