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
	"cmp"
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
	"time"

	"github.com/picatz/doh/internal/blocklist"
	"github.com/picatz/doh/internal/services"
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

	// Tenants are the groups of people who share this server, such as
	// families or friends, each managing their own profiles. Profiles
	// without a tenant belong to the server's operator.
	Tenants []Tenant `json:"tenants,omitempty"`

	// Profiles are the policies for groups of clients, each with a unique
	// ID.
	Profiles []Profile `json:"profiles"`
}

// DefaultMaxTenantProfiles bounds each tenant's profiles, unless the
// tenant sets its own limit.
const DefaultMaxTenantProfiles = 20

// Tenant is a group of people who manage their own profiles on a shared
// server, without seeing or affecting anyone else's.
//
// What a tenant's profiles may do is bounded, since they run on someone
// else's server: they may only select clients by address within the
// tenant's Networks, and may only use preset blocklists, unless the
// operator allows CustomLists.
type Tenant struct {
	// ID identifies the tenant, as [ValidID] describes.
	ID string `json:"id"`

	// Name is a human-readable name, such as "The Smiths".
	Name string `json:"name,omitempty"`

	// Networks are the addresses or prefixes the tenant's profiles may
	// select clients and devices by, such as the tenant's home network.
	// Tenants' networks can't overlap. Without any, the tenant's devices
	// select its profiles by DoH path or host name only.
	Networks []string `json:"networks,omitempty"`

	// CustomLists lets the tenant's profiles use blocklists by HTTPS URL,
	// which the server downloads. Without it, they may use presets only.
	// File paths are never allowed.
	CustomLists bool `json:"custom_lists,omitzero"`

	// MaxProfiles bounds the tenant's profiles. It defaults to
	// DefaultMaxTenantProfiles.
	MaxProfiles int `json:"max_profiles,omitzero"`
}

// Profile is the policy for a group of clients, such as a household's
// phones, its streaming sticks, or a child's tablet.
type Profile struct {
	// ID identifies the profile in DoH paths, host names, logs, and the
	// API, as [ValidID] describes. It's an identifier, not a secret: anyone
	// who knows it can use the profile.
	ID string `json:"id"`

	// Name is a human-readable name, such as "Streaming sticks".
	Name string `json:"name,omitempty"`

	// Tenant is the ID of the tenant the profile belongs to, or empty for
	// the server's operator.
	Tenant string `json:"tenant,omitempty"`

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

	// Services blocks apps and sites by name, such as "tiktok" or
	// "roblox": see [services.Catalog].
	Services []string `json:"services,omitempty"`

	// Schedules block more at certain times, such as social apps during
	// homework, or everything but school sites at bedtime.
	Schedules []Schedule `json:"schedules,omitempty"`

	// TimeZone is the IANA time zone schedules follow, such as
	// "America/New_York". It defaults to the server's local time zone.
	TimeZone string `json:"time_zone,omitempty"`

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
	// Name identifies the device in logs, as [ValidID] describes. Over
	// DoH, a device can also name itself in the path, as
	// /dns-query/{profile}/{device}, or in the host name, as
	// {device}--{profile}.{hostname}.
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

// Schedule blocks more during a recurring period, in the profile's time
// zone.
type Schedule struct {
	// Name describes it, such as "Bedtime" or "Homework".
	Name string `json:"name"`

	// Days are the days it starts on: "mon", "tue", "wed", "thu", "fri",
	// "sat", and "sun". Empty means every day.
	Days []string `json:"days,omitempty"`

	// Start and End are times of day, as "21:00" and "07:00". A period
	// that ends before it starts runs past midnight, into the next day.
	Start string `json:"start"`
	End   string `json:"end"`

	// BlockAll blocks every name but the profile's allowed domains, the
	// schedule's Allow, and names local to the network.
	BlockAll bool `json:"block_all,omitzero"`

	// Allow lists domains, with their subdomains, that BlockAll lets
	// through, such as school sites.
	Allow []string `json:"allow,omitempty"`

	// Services, Lists, and Deny are blocked during the period, as the
	// profile's own are always.
	Services []string `json:"services,omitempty"`
	Lists    []string `json:"lists,omitempty"`
	Deny     []string `json:"deny,omitempty"`
}

// Weekdays are the day names schedules use, from Sunday, as
// [time.Weekday] counts them.
var Weekdays = [7]string{"sun", "mon", "tue", "wed", "thu", "fri", "sat"}

// ParseClock parses a time of day as "HH:MM", returning minutes since
// midnight.
func ParseClock(s string) (int, error) {
	t, err := time.Parse("15:04", s)
	if err != nil || len(s) != 5 {
		return 0, fmt.Errorf("time %q must be HH:MM, such as 21:00", s)
	}
	return t.Hour()*60 + t.Minute(), nil
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

// Tenant returns the tenant with id, or nil.
func (p *Policy) Tenant(id string) *Tenant {
	if p == nil {
		return nil
	}
	if i := slices.IndexFunc(p.Tenants, func(t Tenant) bool { return t.ID == id }); i >= 0 {
		return &p.Tenants[i]
	}
	return nil
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

// idPattern matches profile IDs and device names: DNS labels of lower-case
// letters, digits, and hyphens, which neither start nor end with a hyphen.
var idPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// IDSeparator separates a device name from a profile ID in a host name
// label, as in "tablet--kids.dns.example.com". IDs can't contain it.
const IDSeparator = "--"

// ValidID reports whether id can name a profile or device: 1 to 63
// lower-case letters, digits, and hyphens, starting and ending with a
// letter or digit, without [IDSeparator]. Such IDs are valid DNS labels,
// so they can appear in host names.
func ValidID(id string) bool {
	return idPattern.MatchString(id) && !strings.Contains(id, IDSeparator)
}

// Validate reports every problem with p, so they can be fixed at once.
func (p *Policy) Validate() error {
	var errs []error

	if p.Version != 0 && p.Version != Version {
		errs = append(errs, fmt.Errorf("version %d is not supported (want %d)", p.Version, Version))
	}

	tenants := make(map[string]*Tenant, len(p.Tenants))
	var networks []tenantNetwork
	for i := range p.Tenants {
		t := &p.Tenants[i]
		at := fmt.Sprintf("tenants[%d]", i)
		if t.ID != "" {
			at = fmt.Sprintf("tenant %q", t.ID)
		}
		switch {
		case !ValidID(t.ID):
			errs = append(errs, fmt.Errorf("%s: id must be 1 to 63 lower-case letters, digits, and single hyphens, starting and ending with a letter or digit", at))
		case tenants[t.ID] != nil:
			errs = append(errs, fmt.Errorf("%s: duplicate id", at))
		}
		tenants[t.ID] = t

		if t.MaxProfiles < 0 {
			errs = append(errs, fmt.Errorf("%s: max_profiles must not be negative", at))
		}
		for _, n := range t.Networks {
			prefix, err := ParsePrefix(n)
			if err != nil {
				errs = append(errs, fmt.Errorf("%s: %v", at, err))
				continue
			}
			for _, other := range networks {
				if other.prefix.Overlaps(prefix) {
					errs = append(errs, fmt.Errorf("%s: network %s overlaps tenant %q's %s", at, prefix, other.tenant, other.prefix))
				}
			}
			networks = append(networks, tenantNetwork{t.ID, prefix})
		}
	}

	ids := make(map[string]bool)
	addrs := make(map[netip.Prefix]string)
	devices := make(map[string]bool)
	tenantProfiles := make(map[string]int)

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
			fail("id must be 1 to 63 lower-case letters, digits, and single hyphens, starting and ending with a letter or digit")
		case ids[pr.ID]:
			fail("duplicate id")
		}
		ids[pr.ID] = true

		var tenant *Tenant
		if pr.Tenant != "" {
			if tenant = tenants[pr.Tenant]; tenant == nil {
				fail("no tenant %q", pr.Tenant)
			} else {
				tenantProfiles[pr.Tenant]++
			}
			if pr.ID == DefaultProfile {
				fail("the default profile belongs to the server's operator, not a tenant")
			}
		}

		claim := func(s, owner string) {
			prefix, err := ParsePrefix(s)
			if err != nil {
				fail("%v", err)
				return
			}
			// A tenant may only claim addresses in its own networks, so
			// it can't capture anyone else's clients.
			if tenant != nil && !tenant.contains(prefix) {
				fail("%s is outside tenant %q's networks", prefix, tenant.ID)
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
				fail("device name %q must be 1 to 63 lower-case letters, digits, and single hyphens, starting and ending with a letter or digit", d.Name)
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
			src, err := blocklist.ParseSource(l)
			if err != nil {
				fail("%v", err)
				continue
			}
			// Lists are downloaded or read by the server, so tenants may
			// only use presets, or with CustomLists, HTTPS URLs: never
			// files, or plain HTTP.
			if tenant != nil && !isPreset(src) && (!tenant.CustomLists || !strings.HasPrefix(src.Location, "https://")) {
				if tenant.CustomLists {
					fail("list %q: tenants' custom lists must be HTTPS URLs", l)
				} else {
					fail("list %q: tenant %q may only use preset lists", l, tenant.ID)
				}
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

		for _, id := range pr.Services {
			if _, ok := services.Lookup(id); !ok {
				fail("unknown service %q (want one of %s)", id, strings.Join(services.IDs(), ", "))
			}
		}
		if pr.TimeZone != "" {
			if _, err := time.LoadLocation(pr.TimeZone); err != nil || pr.TimeZone == "Local" {
				fail("time_zone %q must be an IANA time zone, such as America/New_York", pr.TimeZone)
			}
		}
		for j, sc := range pr.Schedules {
			at := fmt.Sprintf("schedule %q", sc.Name)
			if sc.Name == "" {
				at = fmt.Sprintf("schedules[%d]", j)
			}
			if n := strings.TrimSpace(sc.Name); n == "" || len(n) > 64 {
				fail("%s: name it with 1 to 64 characters, such as Bedtime", at)
			}
			for _, d := range sc.Days {
				if !slices.Contains(Weekdays[:], d) {
					fail("%s: day %q must be one of %s", at, d, strings.Join(Weekdays[:], ", "))
				}
			}
			start, err1 := ParseClock(sc.Start)
			end, err2 := ParseClock(sc.End)
			switch {
			case err1 != nil:
				fail("%s: %v", at, err1)
			case err2 != nil:
				fail("%s: %v", at, err2)
			case start == end:
				fail("%s: starts and ends at the same time", at)
			}
			if !sc.BlockAll && len(sc.Services) == 0 && len(sc.Lists) == 0 && len(sc.Deny) == 0 {
				fail("%s: blocks nothing; set block_all, services, lists, or deny", at)
			}
			for _, id := range sc.Services {
				if _, ok := services.Lookup(id); !ok {
					fail("%s: unknown service %q", at, id)
				}
			}
			for _, d := range slices.Concat(sc.Allow, sc.Deny) {
				if _, ok := NormalizeDomain(d); !ok {
					fail("%s: invalid domain %q", at, d)
				}
			}
			for _, l := range sc.Lists {
				src, err := blocklist.ParseSource(l)
				if err != nil {
					fail("%s: %v", at, err)
					continue
				}
				if tenant != nil && !isPreset(src) && (!tenant.CustomLists || !strings.HasPrefix(src.Location, "https://")) {
					if tenant.CustomLists {
						fail("%s: list %q: tenants' custom lists must be HTTPS URLs", at, l)
					} else {
						fail("%s: list %q: tenant %q may only use preset lists", at, l, tenant.ID)
					}
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

	for id, n := range tenantProfiles {
		if limit := cmp.Or(tenants[id].MaxProfiles, DefaultMaxTenantProfiles); n > limit {
			errs = append(errs, fmt.Errorf("tenant %q: has %d profiles, more than its limit of %d", id, n, limit))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("policy: %w", errors.Join(errs...))
	}
	return nil
}

// tenantNetwork is a network a tenant owns.
type tenantNetwork struct {
	tenant string
	prefix netip.Prefix
}

// contains reports whether prefix lies within one of t's networks.
func (t *Tenant) contains(prefix netip.Prefix) bool {
	for _, n := range t.Networks {
		network, err := ParsePrefix(n)
		if err == nil && network.Bits() <= prefix.Bits() && network.Contains(prefix.Addr()) {
			return true
		}
	}
	return false
}

// isPreset reports whether src is a preset list, by its name and URL.
func isPreset(src blocklist.Source) bool {
	url, ok := blocklist.Presets[src.Name]
	return ok && url == src.Location
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
