// Package policy defines the profiles a resolver applies to its clients:
// which protections are on, which lists block names, which names are
// always allowed or denied, and which devices each profile covers.
//
// A [Policy] is plain data, stored as a JSON file that operators can keep
// in version control, edit by hand, or change through the admin API. It is
// validated as a whole, so a policy that loads is a policy that applies.
//
// Clients are matched to a profile by, in order:
//
//  1. The DoH path: /dns-query/{profile} or /dns-query/{profile}/{device}.
//  2. Their address, against every profile's devices and clients. The
//     most specific prefix wins, so a device listed by address overrides
//     the network it's on.
//  3. The profile with ID [DefaultProfile], if there is one. Without it,
//     unmatched clients are refused, making the resolver closed.
package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strings"

	"github.com/picatz/doh/internal/blocklist"
)

// Version is the current policy file format version.
const Version = 1

// DefaultProfile is the ID of the profile that applies to clients no other
// profile matches.
const DefaultProfile = "default"

// Block responses.
const (
	// BlockNXDomain answers blocked names with NXDOMAIN, as if they didn't
	// exist. It's the default.
	BlockNXDomain = "nxdomain"

	// BlockNull answers A and AAAA queries for blocked names with the
	// unspecified address (0.0.0.0 or ::), and others with no records.
	BlockNull = "null"
)

// DefaultNewlyRegisteredDays is how young a domain's registration must be
// for newly registered domain protection to block it, unless a profile
// sets its own threshold.
const DefaultNewlyRegisteredDays = 30

// Policy is the set of profiles a resolver applies.
type Policy struct {
	// Version is the format version, [Version]. Zero is read as Version.
	Version int `json:"version,omitzero"`

	// Profiles are the policies for groups of clients, each with a unique
	// ID.
	Profiles []Profile `json:"profiles"`
}

// Profile is the policy for a group of clients, such as a household's
// phones, its streaming sticks, or a child's tablet.
type Profile struct {
	// ID identifies the profile in DoH paths, logs, and the API: 1 to 63
	// lower-case letters, digits, and hyphens, starting with a letter or
	// digit. It's an identifier, not a secret: anyone who knows it can use
	// the profile over DoH.
	ID string `json:"id"`

	// Name is a human-readable name, such as "Streaming sticks".
	Name string `json:"name,omitempty"`

	// Clients are the addresses or prefixes, such as "192.168.1.0/24",
	// whose queries use this profile.
	Clients []string `json:"clients,omitempty"`

	// Devices name individual clients, so logs show "living-room-tv"
	// rather than an address. Their addresses also select this profile.
	Devices []Device `json:"devices,omitempty"`

	// Security toggles the resolver's built-in protections.
	Security Security `json:"security"`

	// Lists are the blocklists to apply: preset names (see
	// [blocklist.Catalog]), URLs, or file paths, optionally named as
	// name=location.
	Lists []string `json:"lists,omitempty"`

	// Allow lists domains, with their subdomains, that are never blocked
	// by anything in this profile.
	Allow []string `json:"allow,omitempty"`

	// Deny lists domains, with their subdomains, that are always blocked.
	Deny []string `json:"deny,omitempty"`

	// BlockTLDs blocks every name under these top-level domains, such as
	// "zip".
	BlockTLDs []string `json:"block_tlds,omitempty"`

	// SafeSearch enforces the safe search modes that search engines and
	// video sites offer at the DNS level.
	SafeSearch bool `json:"safe_search"`

	// Rewrites answer names locally, such as a home server's name with its
	// LAN address.
	Rewrites []Rewrite `json:"rewrites,omitempty"`

	// BlockResponse is how blocked names are answered: [BlockNXDomain]
	// (the default) or [BlockNull].
	BlockResponse string `json:"block_response,omitempty"`

	// Logging controls the query log for this profile.
	Logging Logging `json:"logging,omitzero"`
}

// Device is a named client.
type Device struct {
	// Name identifies the device in logs: 1 to 63 lower-case letters,
	// digits, and hyphens. Over DoH, a device can also name itself in the
	// path, as /dns-query/{profile}/{device}.
	Name string `json:"name"`

	// Addrs are the device's addresses or prefixes.
	Addrs []string `json:"addrs,omitempty"`
}

// Security toggles the resolver's built-in protections. Each is
// independent of the profile's lists.
type Security struct {
	// Rebinding blocks public names that resolve to private, loopback, or
	// link-local addresses, which DNS rebinding attacks use to reach
	// devices on the local network from a web page.
	Rebinding bool `json:"rebinding"`

	// Homograph blocks internationalized names that mix scripts, or that
	// spell Latin-looking names entirely in look-alike letters, as
	// phishing domains such as "аpple.com" (with a Cyrillic а) do.
	Homograph bool `json:"homograph"`

	// NewlyRegistered blocks domains registered within the last
	// NewlyRegisteredDays days, which are disproportionately used for
	// phishing and malware. Registration dates come from the registries'
	// RDAP services; names under TLDs without RDAP aren't checked.
	NewlyRegistered bool `json:"newly_registered"`

	// NewlyRegisteredDays is the age below which a domain counts as newly
	// registered. It defaults to [DefaultNewlyRegisteredDays].
	NewlyRegisteredDays int `json:"newly_registered_days,omitzero"`

	// Tunneling blocks queries that look like data smuggled through DNS:
	// long, random-looking labels, NULL records, and bursts of unique
	// names under one domain from one client.
	Tunneling bool `json:"tunneling"`

	// Bypass blocks the ways devices route around this resolver: Apple's
	// iCloud Private Relay and well-known public encrypted DNS services.
	// Firefox is always told not to enable its own DoH when a profile
	// blocks anything.
	Bypass bool `json:"bypass"`
}

// Rewrite answers a name locally.
type Rewrite struct {
	// Name is the domain to answer, or "*.domain" for its subdomains.
	Name string `json:"name"`

	// Addrs are the IPv4 and IPv6 addresses to answer with.
	Addrs []string `json:"addrs"`
}

// Logging controls the query log for a profile.
type Logging struct {
	// Disabled keeps this profile's queries out of the query log, though
	// they're still counted in metrics.
	Disabled bool `json:"disabled,omitzero"`
}

// Defaults returns a policy with one default profile that has every
// protection on that works without false positives on typical networks,
// and blocks threats from the threat intelligence preset.
func Defaults() *Policy {
	return &Policy{
		Version: Version,
		Profiles: []Profile{{
			ID:   DefaultProfile,
			Name: "Default",
			Security: Security{
				Rebinding: true,
				Homograph: true,
			},
			Lists: []string{blocklist.ThreatIntelPreset},
		}},
	}
}

// Profile returns the profile with id, or nil.
func (p *Policy) Profile(id string) *Profile {
	if p == nil {
		return nil
	}
	if i := slices.IndexFunc(p.Profiles, func(pr Profile) bool { return pr.ID == id }); i >= 0 {
		return &p.Profiles[i]
	}
	return nil
}

// Clone returns a deep copy of p.
func (p *Policy) Clone() *Policy {
	if p == nil {
		return nil
	}
	b, err := json.Marshal(p)
	if err != nil {
		panic(err) // policies always encode
	}
	var c Policy
	if err := json.Unmarshal(b, &c); err != nil {
		panic(err)
	}
	return &c
}

// ETag returns a strong entity tag for p's canonical encoding, for
// conditional requests ([RFC 9110, Section 8.8.3]).
//
// [RFC 9110, Section 8.8.3]: https://www.rfc-editor.org/rfc/rfc9110.html#section-8.8.3
func (p *Policy) ETag() string {
	b, err := Marshal(p)
	if err != nil {
		panic(err)
	}
	sum := sha256.Sum256(b)
	return `"` + hex.EncodeToString(sum[:12]) + `"`
}

// Marshal encodes p as indented JSON, the policy file format.
func Marshal(p *Policy) ([]byte, error) {
	b, err := json.Marshal(p, json.Deterministic(true), jsontext.WithIndent("  "))
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// Unmarshal decodes and validates a policy, rejecting unknown fields,
// duplicate keys, and trailing data so mistakes don't go unnoticed.
func Unmarshal(b []byte) (*Policy, error) {
	var p Policy
	if err := json.Unmarshal(b, &p, json.RejectUnknownMembers(true)); err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return &p, nil
}

// idPattern matches profile IDs and device names.
var idPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// ValidID reports whether id can name a profile or device.
func ValidID(id string) bool { return idPattern.MatchString(id) }

// Validate reports every problem with p, so they can be fixed at once.
func (p *Policy) Validate() error {
	var errs []error

	if p.Version != 0 && p.Version != Version {
		errs = append(errs, fmt.Errorf("version %d is not supported (want %d)", p.Version, Version))
	}

	ids := make(map[string]bool)
	addrs := make(map[netip.Prefix]string)
	devices := make(map[string]bool)

	for i, pr := range p.Profiles {
		at := fmt.Sprintf("profiles[%d]", i)
		if pr.ID != "" {
			at = fmt.Sprintf("profile %q", pr.ID)
		}
		fail := func(format string, args ...any) {
			errs = append(errs, fmt.Errorf("%s: %s", at, fmt.Sprintf(format, args...)))
		}

		switch {
		case !ValidID(pr.ID):
			fail("id must be 1 to 63 lower-case letters, digits, and hyphens, starting with a letter or digit")
		case ids[pr.ID]:
			fail("duplicate id")
		}
		ids[pr.ID] = true

		claim := func(s, owner string) {
			prefix, err := ParsePrefix(s)
			if err != nil {
				fail("%v", err)
				return
			}
			if other, ok := addrs[prefix]; ok {
				fail("%s is also claimed by %s", prefix, other)
				return
			}
			addrs[prefix] = owner
		}

		for _, c := range pr.Clients {
			claim(c, fmt.Sprintf("profile %q", pr.ID))
		}
		for _, d := range pr.Devices {
			if !ValidID(d.Name) {
				fail("device name %q must be 1 to 63 lower-case letters, digits, and hyphens", d.Name)
			}
			if devices[pr.ID+"/"+d.Name] {
				fail("duplicate device %q", d.Name)
			}
			devices[pr.ID+"/"+d.Name] = true
			for _, a := range d.Addrs {
				claim(a, fmt.Sprintf("device %q", d.Name))
			}
		}

		for _, l := range pr.Lists {
			if _, err := blocklist.ParseSource(l); err != nil {
				fail("%v", err)
			}
		}
		if dup := firstDuplicate(pr.Lists); dup != "" {
			fail("list %q appears twice", dup)
		}

		for _, d := range slices.Concat(pr.Allow, pr.Deny) {
			if _, ok := NormalizeDomain(d); !ok {
				fail("invalid domain %q", d)
			}
		}
		for _, t := range pr.BlockTLDs {
			if n, ok := NormalizeDomain(t); !ok || strings.Contains(n, ".") {
				fail("invalid TLD %q (want a single label such as \"zip\")", t)
			}
		}

		for _, rw := range pr.Rewrites {
			if _, ok := NormalizeDomain(strings.TrimPrefix(rw.Name, "*.")); !ok {
				fail("rewrite: invalid name %q", rw.Name)
			}
			if len(rw.Addrs) == 0 {
				fail("rewrite %q: needs at least one address", rw.Name)
			}
			for _, a := range rw.Addrs {
				if _, err := netip.ParseAddr(a); err != nil {
					fail("rewrite %q: invalid address %q", rw.Name, a)
				}
			}
		}

		switch pr.BlockResponse {
		case "", BlockNXDomain, BlockNull:
		default:
			fail("block_response %q must be %q or %q", pr.BlockResponse, BlockNXDomain, BlockNull)
		}

		if d := pr.Security.NewlyRegisteredDays; d < 0 || d > 365 {
			fail("security.newly_registered_days must be between 1 and 365")
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("policy: %w", errors.Join(errs...))
	}
	return nil
}

// firstDuplicate returns the first string that appears twice in s, or "".
func firstDuplicate(s []string) string {
	seen := make(map[string]bool, len(s))
	for _, v := range s {
		if seen[v] {
			return v
		}
		seen[v] = true
	}
	return ""
}

// ParsePrefix parses an address, as a single-address prefix, or a prefix
// such as "192.168.1.0/24", masking any host bits. IPv4-mapped IPv6
// addresses are unmapped, so they match the IPv4 clients they are.
func ParsePrefix(s string) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("invalid prefix %q", s)
		}
		if p.Addr().Is4In6() {
			p = netip.PrefixFrom(p.Addr().Unmap(), max(p.Bits()-96, 0))
		}
		return p.Masked(), nil
	}

	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("invalid address %q", s)
	}
	a = a.Unmap().WithZone("")
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// NormalizeDomain lower-cases a domain, trims a trailing dot and any "*."
// prefix, and reports whether it's a valid name.
func NormalizeDomain(d string) (string, bool) {
	d = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(d)), ".")
	d = strings.TrimPrefix(d, "*.")
	if d == "" || len(d) > 253 {
		return "", false
	}
	if _, err := netip.ParseAddr(d); err == nil {
		return "", false
	}
	for label := range strings.SplitSeq(d, ".") {
		if label == "" || len(label) > 63 {
			return "", false
		}
		for _, c := range []byte(label) {
			if !('a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '-' || c == '_') {
				return "", false
			}
		}
	}
	return d, true
}
