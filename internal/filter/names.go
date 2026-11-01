package filter

import (
	"strings"

	"golang.org/x/net/publicsuffix"
)

// canonical lower-cases name and removes its trailing dot.
func canonical(name string) string {
	return strings.ToLower(strings.TrimSuffix(name, "."))
}

// Registrable returns the domain under which name was registered with a
// registry, such as "example.co.uk" for "www.example.co.uk", using the
// ICANN section of the Public Suffix List. It returns "" for names that
// are themselves public suffixes or are under an unknown TLD.
//
// Unlike [publicsuffix.EffectiveTLDPlusOne], suffixes from the list's
// private section, such as "github.io", are ignored, since registries only
// know about domains registered under ICANN suffixes.
func Registrable(name string) string {
	name = canonical(name)

	// Walk up from the full name, keeping the longest ICANN suffix seen.
	labels := strings.Split(name, ".")
	for i := 1; i < len(labels); i++ {
		suffix := strings.Join(labels[i:], ".")
		if ps, icann := publicsuffix.PublicSuffix(suffix); icann && ps == suffix {
			return strings.Join(labels[i-1:], ".")
		}
	}
	return ""
}

// localTLDs are top-level names that only make sense on a local network,
// whether reserved (RFC 6761, RFC 6762, RFC 8375, ICANN's .internal) or in
// common use by home routers. Answers for them aren't checked for
// rebinding, and they're never looked up in registries.
var localTLDs = map[string]bool{
	"local": true, "localhost": true, "localdomain": true, "internal": true,
	"lan": true, "home": true, "corp": true, "intranet": true, "private": true,
	"test": true, "invalid": true, "example": true,
}

// IsLocal reports whether name is local to a network: a single label, or
// under a local top-level name, home.arpa, or a reverse DNS zone.
func IsLocal(name string) bool {
	name = canonical(name)
	tld := name[strings.LastIndexByte(name, '.')+1:]
	switch {
	case !strings.Contains(name, "."), localTLDs[tld]:
		return true
	case name == "home.arpa", strings.HasSuffix(name, ".home.arpa"):
		return true
	case strings.HasSuffix(name, ".in-addr.arpa"), strings.HasSuffix(name, ".ip6.arpa"):
		return true
	}
	return false
}

// domainSet matches names against domains, along with their subdomains.
type domainSet map[string]bool

func newDomainSet(domains ...[]string) domainSet {
	s := make(domainSet)
	for _, ds := range domains {
		for _, d := range ds {
			if d = strings.TrimPrefix(canonical(strings.TrimSpace(d)), "*."); d != "" {
				s[d] = true
			}
		}
	}
	return s
}

// match returns the domain in s that name is, or is under.
func (s domainSet) match(name string) (string, bool) {
	if len(s) == 0 {
		return "", false
	}
	for d := name; ; {
		if s[d] {
			return d, true
		}
		_, parent, ok := strings.Cut(d, ".")
		if !ok {
			return "", false
		}
		d = parent
	}
}
