package filter

import "strings"

// firefoxCanary is the domain Firefox looks up to decide whether to enable
// its own DNS over HTTPS. A negative answer tells it this network filters
// DNS, so it keeps using the network's resolver.
//
// See https://support.mozilla.org/kb/canary-domain-use-application-dnsnet.
const firefoxCanary = "use-application-dns.net"

// privateRelayCanaries are the domains Apple devices look up before using
// iCloud Private Relay; negative answers tell them this network doesn't
// allow it.
//
// See https://developer.apple.com/support/prepare-your-network-for-icloud-private-relay/.
var privateRelayCanaries = newDomainSet([]string{"mask.icloud.com", "mask-h2.icloud.com"})

// Canary reports whether name is, or is under, a canary domain: one that
// software such as Firefox or iCloud Private Relay looks up to ask whether
// the network allows it to route around the network's resolver. Blocking
// a canary answers that question; it isn't an attempt to get around
// filtering.
func Canary(name string) bool {
	if name == firefoxCanary {
		return true
	}
	_, ok := privateRelayCanaries.match(name)
	return ok
}

// encryptedDNS are well-known public encrypted DNS services, which devices
// and apps can use to route around this resolver. The resolver's own
// upstreams are always exempt.
var encryptedDNS = newDomainSet([]string{
	"dns.google", "dns.google.com", "dns64.dns.google", "8888.google",
	"cloudflare-dns.com", "one.one.one.one", "1dot1dot1dot1.cloudflare-dns.com", "cloudflare-gateway.com",
	"dns.quad9.net", "dns9.quad9.net", "dns10.quad9.net", "dns11.quad9.net", "dns12.quad9.net",
	"doh.opendns.com", "dns.opendns.com", "doh.familyshield.opendns.com", "doh.umbrella.com",
	"dns.adguard.com", "dns.adguard-dns.com", "dns-family.adguard.com", "unfiltered.adguard-dns.com",
	"dns.nextdns.io", "doh.cleanbrowsing.org", "doh.mullvad.net", "dns.mullvad.net",
	"dns.controld.com", "freedns.controld.com", "doh.dns.sb", "dns.alidns.com", "doh.pub",
	"dns.twnic.tw", "ordns.he.net", "dns0.eu", "dns.switch.ch", "doh.libredns.gr",
	"dns.digitale-gesellschaft.ch", "doh.applied-privacy.net", "dns.njal.la", "doh.ffmuc.net",
	"dns.decloudus.com", "doh.xfinity.com", "doh.cox.net", "dns.brahma.world",
})

// safeSearch maps names to the hosts their providers serve safe search
// from. Answering a name with a CNAME to its safe host enforces safe
// search for every device, as the providers document.
var safeSearch = map[string]string{
	"www.bing.com": "strict.bing.com",

	"duckduckgo.com":     "safe.duckduckgo.com",
	"www.duckduckgo.com": "safe.duckduckgo.com",

	"www.youtube.com":          "restrict.youtube.com",
	"m.youtube.com":            "restrict.youtube.com",
	"youtubei.googleapis.com":  "restrict.youtube.com",
	"youtube.googleapis.com":   "restrict.youtube.com",
	"www.youtube-nocookie.com": "restrict.youtube.com",

	"www.pixabay.com": "safesearch.pixabay.com",
	"pixabay.com":     "safesearch.pixabay.com",
}

// googleSafeSearch is the host Google serves safe search from, for every
// one of its country domains.
const googleSafeSearch = "forcesafesearch.google.com"

// safeSearchTarget returns the safe search host for name, if it has one.
func safeSearchTarget(name string) (string, bool) {
	if target, ok := safeSearch[name]; ok {
		return target, true
	}

	// Google search runs on google.<suffix> for many public suffixes, such
	// as google.co.uk, with and without www.
	if reg := Registrable(name); strings.HasPrefix(reg, "google.") && (name == reg || name == "www."+reg) {
		return googleSafeSearch, true
	}
	return "", false
}
