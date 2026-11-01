// Package filter decides how a resolver answers each query under a
// [policy.Policy]: which profile applies to the client, and whether the
// query is allowed, blocked, or answered locally, with a reason that can
// be logged, shown to people, and traced check by check.
//
// Queries go through these checks in order, and the first that matches
// decides:
//
//	upstream          the resolver's own upstream hosts are never filtered
//	rewrite           the profile's local answers
//	allow             the profile's allowed domains, which skip every other check
//	deny              the profile's denied domains
//	service           the profile's blocked services, such as TikTok
//	schedule          the profile's schedules in effect now
//	bypass            Firefox's DoH canary; with Security.Bypass, Private Relay and public encrypted DNS
//	tld               the profile's blocked top-level domains
//	list              the profile's blocklists, unless a list has an exception for the name
//	homograph         Security.Homograph
//	tunneling         Security.Tunneling
//	newly-registered  Security.NewlyRegistered
//	safe-search       SafeSearch, answering with the provider's safe host
//
// Answers are then checked too, unless the name was allowed:
//
//	cname             CNAME targets on the profile's deny list, blocked services, schedules in effect, blocked TLDs, or blocklists, uncovering trackers and apps cloaked behind other names
//	rebinding         Security.Rebinding
package filter

import (
	"cmp"
	"context"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/picatz/doh/internal/api"
	"github.com/picatz/doh/internal/blocklist"
	"github.com/picatz/doh/internal/policy"
	"github.com/picatz/doh/internal/rdap"
)

// Reasons, which name the check that decided a query.
const (
	ReasonUpstream        = "upstream"
	ReasonLocal           = "local"
	ReasonRewrite         = "rewrite"
	ReasonAllow           = "allow"
	ReasonDeny            = "deny"
	ReasonService         = "service"
	ReasonSchedule        = "schedule"
	ReasonBypass          = "bypass"
	ReasonTLD             = "tld"
	ReasonList            = "list"
	ReasonHomograph       = "homograph"
	ReasonTunneling       = "tunneling"
	ReasonNewlyRegistered = "newly-registered"
	ReasonSafeSearch      = "safe-search"
	ReasonCNAME           = "cname"
	ReasonRebinding       = "rebinding"
)

// BlockedTTL is the TTL of synthesized answers, short so policy changes
// take effect quickly.
const BlockedTTL = 60

// Options configures an [Engine].
type Options struct {
	// Lists holds the loaded blocklists. Profiles' lists are looked up in
	// it by source; lists it hasn't loaded block nothing.
	Lists *blocklist.Registry

	// Ages looks up domain registration dates. If nil, newly registered
	// domain checks are skipped.
	Ages *rdap.Ages

	// State carries per-client state, such as tunneling detection, across
	// engines as the policy changes. If nil, a new one is used.
	State *State

	// Exempt are names, with their subdomains, that are never filtered:
	// the resolver's own upstream hosts, so blocking can't cut the
	// resolver off from its upstreams when it resolves their names itself.
	Exempt []string

	// Local are domains, with their subdomains, that are local to the
	// network, like the names [IsLocal] reports: their answers may point
	// to private addresses, and they aren't looked up in registries. They
	// are typically the domains forwarded to a local resolver.
	Local []string

	// Baseline applies to every profile, in addition to its own settings.
	Baseline Baseline

	// Now returns the current time, for schedules. Nil means time.Now.
	Now func() time.Time
}

// Baseline is policy applied to every profile, such as from command-line
// flags.
type Baseline struct {
	// Lists are blocklist sources, as in [policy.Profile.Lists].
	Lists []string

	// Allow and Deny are domains, as in [policy.Profile].
	Allow, Deny []string

	// BlockResponse is used by profiles that don't set their own.
	BlockResponse string
}

// State is per-client state that outlives policy changes.
type State struct {
	tunnels *tunnelTracker
}

// NewState returns empty state.
func NewState() *State { return &State{tunnels: newTunnelTracker()} }

// Engine applies a policy. It's immutable and safe for concurrent use;
// build a new one when the policy changes.
type Engine struct {
	policy   *policy.Policy
	opts     Options
	profiles map[string]*Profile
	sources  []blocklist.Source
	exempt   domainSet
	local    domainSet

	// clients maps prefixes to the profile and device they select;
	// bits4 and bits6 are the prefix lengths in use, longest first.
	clients      map[netip.Prefix]clientMatch
	bits4, bits6 []int
}

type clientMatch struct {
	profile *Profile
	device  string
}

// Profile is a compiled [policy.Profile].
type Profile struct {
	engine *Engine
	config policy.Profile

	lists         []blocklist.Source
	allow, deny   domainSet
	tlds          domainSet
	rewrites      map[string][]netip.Addr // by exact name
	wildRewrites  map[string][]netip.Addr // by parent of *.name
	blockResponse string
	filters       bool
	devices       map[string]bool
	services      serviceSet
	schedules     []schedule
	location      *time.Location
}

// New compiles p, which must be valid.
func New(p *policy.Policy, opts Options) (*Engine, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	if opts.State == nil {
		opts.State = NewState()
	}

	e := &Engine{
		policy:   p.Clone(),
		opts:     opts,
		profiles: make(map[string]*Profile, len(p.Profiles)),
		clients:  make(map[netip.Prefix]clientMatch),
		exempt:   newDomainSet(opts.Exempt),
		local:    newDomainSet(opts.Local),
	}

	seen := make(map[blocklist.Source]bool)
	bits := make(map[[2]int]bool)

	for _, cfg := range e.policy.Profiles {
		pr := &Profile{
			engine:        e,
			config:        cfg,
			allow:         newDomainSet(cfg.Allow, opts.Baseline.Allow),
			deny:          newDomainSet(cfg.Deny, opts.Baseline.Deny),
			tlds:          newDomainSet(cfg.BlockTLDs),
			rewrites:      make(map[string][]netip.Addr),
			wildRewrites:  make(map[string][]netip.Addr),
			blockResponse: cmp.Or(cfg.BlockResponse, opts.Baseline.BlockResponse, policy.BlockNXDomain),
			devices:       make(map[string]bool),
			services:      newServiceSet(cfg.Services),
			location:      time.Local,
		}

		if cfg.TimeZone != "" {
			loc, err := time.LoadLocation(cfg.TimeZone)
			if err != nil {
				return nil, fmt.Errorf("filter: profile %q: %w", cfg.ID, err)
			}
			pr.location = loc
		}
		for _, sc := range cfg.Schedules {
			compiled, err := compileSchedule(sc)
			if err != nil {
				return nil, fmt.Errorf("filter: profile %q: %w", cfg.ID, err)
			}
			pr.schedules = append(pr.schedules, compiled)
			for _, src := range compiled.lists {
				if !seen[src] {
					seen[src] = true
					e.sources = append(e.sources, src)
				}
			}
		}

		for _, l := range slices.Concat(cfg.Lists, opts.Baseline.Lists) {
			src, err := blocklist.ParseSource(l)
			if err != nil {
				return nil, err
			}
			if !slices.Contains(pr.lists, src) {
				pr.lists = append(pr.lists, src)
			}
			if !seen[src] {
				seen[src] = true
				e.sources = append(e.sources, src)
			}
		}

		for _, rw := range cfg.Rewrites {
			name := canonical(rw.Name)
			target := pr.rewrites
			if parent, ok := strings.CutPrefix(name, "*."); ok {
				name, target = parent, pr.wildRewrites
			}
			for _, a := range rw.Addrs {
				target[name] = append(target[name], netip.MustParseAddr(a).Unmap())
			}
		}

		sec := cfg.Security
		pr.filters = len(pr.lists) > 0 || len(pr.deny) > 0 || len(pr.tlds) > 0 || cfg.SafeSearch ||
			len(cfg.Services) > 0 || len(cfg.Schedules) > 0 ||
			sec.Rebinding || sec.Homograph || sec.NewlyRegistered || sec.Tunneling || sec.Bypass

		claim := func(s, device string) {
			prefix, _ := policy.ParsePrefix(s) // validated
			e.clients[prefix] = clientMatch{profile: pr, device: device}
			bits[[2]int{prefix.Addr().BitLen(), prefix.Bits()}] = true
		}
		for _, c := range cfg.Clients {
			claim(c, "")
		}
		for _, d := range cfg.Devices {
			pr.devices[d.Name] = true
			for _, a := range d.Addrs {
				claim(a, d.Name)
			}
		}

		e.profiles[cfg.ID] = pr
	}

	for b := range bits {
		if b[0] == 32 {
			e.bits4 = append(e.bits4, b[1])
		} else {
			e.bits6 = append(e.bits6, b[1])
		}
	}
	slices.SortFunc(e.bits4, func(a, b int) int { return b - a })
	slices.SortFunc(e.bits6, func(a, b int) int { return b - a })

	return e, nil
}

// now returns the current time.
func (e *Engine) now() time.Time {
	if e.opts.Now != nil {
		return e.opts.Now()
	}
	return time.Now()
}

// Policy returns a copy of the policy the engine applies.
func (e *Engine) Policy() *policy.Policy { return e.policy.Clone() }

// Sources returns every blocklist source the engine's profiles use, for
// loading into the registry.
func (e *Engine) Sources() []blocklist.Source { return slices.Clone(e.sources) }

// Profile returns the profile with id, or nil.
func (e *Engine) Profile(id string) *Profile { return e.profiles[id] }

// Match returns the profile for a client address, and the device it's
// named as, if any: the profile with the most specific matching prefix, or
// the default profile. It returns nil if no profile applies.
func (e *Engine) Match(client netip.Addr) (*Profile, string) {
	if client.IsValid() {
		client = client.Unmap().WithZone("")
		bits := e.bits6
		if client.Is4() {
			bits = e.bits4
		}
		for _, b := range bits {
			prefix, err := client.Prefix(b)
			if err != nil {
				continue
			}
			if m, ok := e.clients[prefix]; ok {
				return m.profile, m.device
			}
		}
	}
	return e.profiles[policy.DefaultProfile], ""
}

// isLocal reports whether name is local to the network.
func (e *Engine) isLocal(name string) bool {
	if IsLocal(name) {
		return true
	}
	_, ok := e.local.match(name)
	return ok
}

// ID returns the profile's ID.
func (p *Profile) ID() string { return p.config.ID }

// Tenant returns the ID of the tenant the profile belongs to, or "" for
// the server's operator.
func (p *Profile) Tenant() string { return p.config.Tenant }

// HasDevice reports whether the profile names device.
func (p *Profile) HasDevice(device string) bool { return p.devices[device] }

// Logged reports whether the profile's queries are logged.
func (p *Profile) Logged() bool { return !p.config.Logging.Disabled }

// Query is a question to check.
type Query struct {
	// Name is the queried name, with or without a trailing dot.
	Name string

	// Type is the queried record type, such as [dns.TypeA].
	Type uint16

	// Client is the client's address, if known.
	Client netip.Addr
}

// Decision is the outcome of checking a query, with what's needed to
// answer it.
type Decision struct {
	api.Decision

	// Addrs answer a rewritten query.
	Addrs []netip.Addr

	// Target is the name a rewritten query is answered with a CNAME to,
	// whose records then answer it.
	Target string
}

// Trace collects the checks a query goes through, for explanations. A nil
// Trace collects nothing.
type Trace struct {
	Checks []api.Check
}

// Add records a check. It does nothing on a nil Trace.
func (t *Trace) Add(check, result, format string, args ...any) {
	if t != nil {
		t.Checks = append(t.Checks, api.Check{Check: check, Result: result, Detail: fmt.Sprintf(format, args...)})
	}
}

func allow(reason, rule, detail string) Decision {
	return Decision{Decision: api.Decision{Action: api.ActionAllow, Reason: reason, Rule: rule, Detail: detail}}
}

func block(reason, rule, source, detail string) Decision {
	return Decision{Decision: api.Decision{Action: api.ActionBlock, Reason: reason, Rule: rule, Source: source, Detail: detail}}
}

// Check decides how to answer q before it's resolved.
func (p *Profile) Check(ctx context.Context, q Query, t *Trace) Decision {
	name := canonical(q.Name)
	sec := p.config.Security

	if d, ok := p.engine.exempt.match(name); ok {
		t.Add(ReasonUpstream, api.CheckMatch, "%s is an upstream resolver's host", d)
		return allow(ReasonUpstream, d, "upstream resolver host")
	}

	if addrs, rule, ok := p.rewrite(name); ok {
		t.Add(ReasonRewrite, api.CheckMatch, "rewritten to %v", addrs)
		return Decision{Decision: api.Decision{Action: api.ActionRewrite, Reason: ReasonRewrite, Rule: rule, Detail: "answered locally"}, Addrs: addrs}
	}
	t.Add(ReasonRewrite, api.CheckPass, "no rewrite")

	if d, ok := p.allow.match(name); ok {
		t.Add(ReasonAllow, api.CheckMatch, "%s is allowed", d)
		return allow(ReasonAllow, d, "allowed by profile "+p.config.ID)
	}
	t.Add(ReasonAllow, api.CheckPass, "not on the allow list")

	if d, ok := p.deny.match(name); ok {
		t.Add(ReasonDeny, api.CheckMatch, "%s is denied", d)
		return block(ReasonDeny, d, "", "denied by profile "+p.config.ID)
	}
	t.Add(ReasonDeny, api.CheckPass, "not on the deny list")

	if d, ok := p.serviceBlock(name, t); ok {
		return d
	}
	if d, ok := p.scheduleBlock(name, t); ok {
		return d
	}

	if name == firefoxCanary && p.filters {
		t.Add(ReasonBypass, api.CheckMatch, "Firefox's DoH canary: telling Firefox to use this resolver")
		return block(ReasonBypass, name, "", "Firefox DoH canary")
	}
	if sec.Bypass {
		if d, ok := privateRelayCanaries.match(name); ok {
			t.Add(ReasonBypass, api.CheckMatch, "iCloud Private Relay canary %s", d)
			return block(ReasonBypass, d, "", "iCloud Private Relay")
		}
		if d, ok := encryptedDNS.match(name); ok {
			t.Add(ReasonBypass, api.CheckMatch, "%s is a public encrypted DNS service", d)
			return block(ReasonBypass, d, "", "public encrypted DNS service")
		}
		t.Add(ReasonBypass, api.CheckPass, "not a bypass service")
	} else {
		t.Add(ReasonBypass, api.CheckSkip, "bypass protection is off")
	}

	if d, ok := p.tlds.match(name[strings.LastIndexByte(name, '.')+1:]); ok {
		t.Add(ReasonTLD, api.CheckMatch, ".%s is blocked", d)
		return block(ReasonTLD, d, "", "blocked TLD ."+d)
	}
	t.Add(ReasonTLD, api.CheckPass, "TLD not blocked")

	if v, ok := p.listBlock(name, t); ok {
		return block(ReasonList, v.Rule.Domain, v.Source, "blocked by "+v.Source)
	}

	if sec.Homograph {
		if why, ok := Homograph(name); ok {
			t.Add(ReasonHomograph, api.CheckMatch, "%s", why)
			return block(ReasonHomograph, name, "", why)
		}
		t.Add(ReasonHomograph, api.CheckPass, "not a look-alike name")
	} else {
		t.Add(ReasonHomograph, api.CheckSkip, "homograph protection is off")
	}

	registrable := Registrable(name)

	if sec.Tunneling {
		if d, ok := p.tunneling(q, name, registrable); ok {
			t.Add(ReasonTunneling, api.CheckMatch, "%s", d.Detail)
			return d
		}
		t.Add(ReasonTunneling, api.CheckPass, "doesn't look like tunneling")
	} else {
		t.Add(ReasonTunneling, api.CheckSkip, "tunneling protection is off")
	}

	if sec.NewlyRegistered {
		if d, ok := p.newlyRegistered(ctx, registrable, t); ok {
			return d
		}
	} else {
		t.Add(ReasonNewlyRegistered, api.CheckSkip, "newly registered domain protection is off")
	}

	if p.config.SafeSearch {
		if target, ok := safeSearchTarget(name); ok {
			t.Add(ReasonSafeSearch, api.CheckMatch, "answered with %s", target)
			return Decision{Decision: api.Decision{Action: api.ActionRewrite, Reason: ReasonSafeSearch, Rule: name, Detail: "safe search enforced"}, Target: target + "."}
		}
		t.Add(ReasonSafeSearch, api.CheckPass, "not a search or video site")
	} else {
		t.Add(ReasonSafeSearch, api.CheckSkip, "safe search is off")
	}

	return allow("", "", "")
}

// rewrite returns the profile's local answer for name, if it has one.
func (p *Profile) rewrite(name string) ([]netip.Addr, string, bool) {
	if addrs, ok := p.rewrites[name]; ok {
		return addrs, name, true
	}
	for d := name; ; {
		_, parent, ok := strings.Cut(d, ".")
		if !ok {
			return nil, "", false
		}
		if addrs, ok := p.wildRewrites[parent]; ok {
			return addrs, "*." + parent, true
		}
		d = parent
	}
}

// listBlock returns the list rule that blocks name, unless any of the
// profile's lists has an exception for it.
func (p *Profile) listBlock(name string, t *Trace) (blocklist.Verdict, bool) {
	if len(p.lists) == 0 {
		t.Add(ReasonList, api.CheckSkip, "no blocklists")
		return blocklist.Verdict{}, false
	}

	var lists []*blocklist.List
	for _, src := range p.lists {
		if l := p.engine.opts.Lists.List(src); l != nil {
			lists = append(lists, l)
		}
	}

	for _, l := range lists {
		if v, ok := l.Exception(name); ok {
			t.Add(ReasonList, api.CheckPass, "%s has an exception for %s", v.Source, v.Rule.Domain)
			return blocklist.Verdict{}, false
		}
	}
	for _, l := range lists {
		if v, ok := l.Block(name); ok {
			t.Add(ReasonList, api.CheckMatch, "%s blocks %s", v.Source, v.Rule.Domain)
			return v, true
		}
	}

	t.Add(ReasonList, api.CheckPass, "on none of %d lists (%d loaded)", len(p.lists), len(lists))
	return blocklist.Verdict{}, false
}

// tunneling reports whether q looks like DNS tunneling.
func (p *Profile) tunneling(q Query, name, registrable string) (Decision, bool) {
	if isTunnelType(q.Type) {
		return block(ReasonTunneling, name, "", dns.TypeToString[q.Type]+" records are only used by tunnels"), true
	}
	if registrable == "" || p.engine.isLocal(name) {
		return Decision{}, false
	}
	if label, ok := encodedLabel(name, registrable); ok {
		return block(ReasonTunneling, registrable, "", fmt.Sprintf("label %.20s… looks like encoded data", label)), true
	}
	if q.Client.IsValid() && p.engine.opts.State.tunnels.observe(q.Client, registrable, name) {
		return block(ReasonTunneling, registrable, "", fmt.Sprintf("burst of %d+ unique names under %s", tunnelBurst, registrable)), true
	}
	return Decision{}, false
}

// newlyRegistered reports whether registrable was registered recently.
func (p *Profile) newlyRegistered(ctx context.Context, registrable string, t *Trace) (Decision, bool) {
	ages := p.engine.opts.Ages
	switch {
	case ages == nil:
		t.Add(ReasonNewlyRegistered, api.CheckSkip, "registration lookups are unavailable")
		return Decision{}, false
	case registrable == "" || p.engine.isLocal(registrable):
		t.Add(ReasonNewlyRegistered, api.CheckSkip, "not a registered domain")
		return Decision{}, false
	}

	age, ok := ages.Age(ctx, registrable)
	if !ok {
		t.Add(ReasonNewlyRegistered, api.CheckPass, "registration date of %s unknown (allowed)", registrable)
		return Decision{}, false
	}

	days := cmp.Or(p.config.Security.NewlyRegisteredDays, policy.DefaultNewlyRegisteredDays)
	if age < time.Duration(days)*24*time.Hour {
		detail := fmt.Sprintf("%s was registered %s ago", registrable, humanAge(age))
		t.Add(ReasonNewlyRegistered, api.CheckMatch, "%s, under %d days", detail, days)
		return block(ReasonNewlyRegistered, registrable, "", detail), true
	}

	t.Add(ReasonNewlyRegistered, api.CheckPass, "%s was registered %s ago", registrable, humanAge(age))
	return Decision{}, false
}

// humanAge formats an age in days, or hours under a day.
func humanAge(d time.Duration) string {
	if d < 24*time.Hour {
		return fmt.Sprintf("%d hours", int(d.Hours()))
	}
	return fmt.Sprintf("%d days", int(d.Hours()/24))
}

// CheckResponse decides whether resp, the answer to q, may be returned:
// whether its CNAME chain leads to a blocked name, or a public name points
// to a local address.
func (p *Profile) CheckResponse(q Query, resp *dns.Msg, t *Trace) Decision {
	name := canonical(q.Name)

	if _, ok := p.engine.exempt.match(name); ok {
		return allow(ReasonUpstream, "", "")
	}
	if _, ok := p.allow.match(name); ok {
		t.Add(ReasonCNAME, api.CheckSkip, "name is allowed")
		t.Add(ReasonRebinding, api.CheckSkip, "name is allowed")
		return allow(ReasonAllow, "", "")
	}

	if d, ok := p.cnameBlock(resp, t); ok {
		return d
	}

	if !p.config.Security.Rebinding {
		t.Add(ReasonRebinding, api.CheckSkip, "rebinding protection is off")
		return allow("", "", "")
	}
	if p.engine.isLocal(name) {
		t.Add(ReasonRebinding, api.CheckSkip, "local names may point to local addresses")
		return allow("", "", "")
	}
	for _, rr := range resp.Answer {
		for _, addr := range addrsOf(rr) {
			if IsRebindingTarget(addr) {
				detail := fmt.Sprintf("public name pointed to local address %s", addr)
				t.Add(ReasonRebinding, api.CheckMatch, "%s", detail)
				return block(ReasonRebinding, addr.String(), "", detail)
			}
		}
	}
	t.Add(ReasonRebinding, api.CheckPass, "no local addresses")

	return allow("", "", "")
}

// cnameBlock checks each CNAME target in resp against the profile's deny
// list, blocked TLDs, and blocklists.
func (p *Profile) cnameBlock(resp *dns.Msg, t *Trace) (Decision, bool) {
	checked := 0
	for _, rr := range resp.Answer {
		cname, ok := rr.(*dns.CNAME)
		if !ok {
			continue
		}
		checked++
		target := canonical(cname.Target)
		if _, ok := p.allow.match(target); ok {
			continue
		}
		if d, ok := p.deny.match(target); ok {
			t.Add(ReasonCNAME, api.CheckMatch, "CNAME target %s is denied", target)
			return block(ReasonCNAME, d, "", "CNAME to denied "+target), true
		}
		if d, ok := p.targetBlock(target); ok {
			t.Add(ReasonCNAME, api.CheckMatch, "%s", d.Detail)
			return d, true
		}
		if d, ok := p.tlds.match(target[strings.LastIndexByte(target, '.')+1:]); ok {
			t.Add(ReasonCNAME, api.CheckMatch, "CNAME target %s is under blocked TLD .%s", target, d)
			return block(ReasonCNAME, d, "", "CNAME to blocked TLD ."+d), true
		}
		if v, ok := p.listBlock(target, nil); ok {
			t.Add(ReasonCNAME, api.CheckMatch, "CNAME target %s is blocked by %s", target, v.Source)
			return block(ReasonCNAME, v.Rule.Domain, v.Source, "CNAME to "+target+", blocked by "+v.Source), true
		}
	}
	if checked == 0 {
		t.Add(ReasonCNAME, api.CheckPass, "no CNAMEs")
	} else {
		t.Add(ReasonCNAME, api.CheckPass, "%d CNAME targets allowed", checked)
	}
	return Decision{}, false
}

// addrsOf returns the addresses rr points to: A and AAAA records, and the
// address hints of SVCB and HTTPS records (RFC 9460, Section 7.3).
func addrsOf(rr dns.RR) []netip.Addr {
	var ips []net.IP
	switch rr := rr.(type) {
	case *dns.A:
		ips = append(ips, rr.A)
	case *dns.AAAA:
		ips = append(ips, rr.AAAA)
	case *dns.HTTPS:
		ips = svcbHints(rr.Value)
	case *dns.SVCB:
		ips = svcbHints(rr.Value)
	}

	addrs := make([]netip.Addr, 0, len(ips))
	for _, ip := range ips {
		if a, ok := netip.AddrFromSlice(ip); ok {
			addrs = append(addrs, a)
		}
	}
	return addrs
}

func svcbHints(kvs []dns.SVCBKeyValue) []net.IP {
	var ips []net.IP
	for _, kv := range kvs {
		switch kv := kv.(type) {
		case *dns.SVCBIPv4Hint:
			ips = append(ips, kv.Hint...)
		case *dns.SVCBIPv6Hint:
			ips = append(ips, kv.Hint...)
		}
	}
	return ips
}

// Block returns the profile's answer to a blocked query.
//
// Blocked names get NXDOMAIN, or with [policy.BlockNull], the unspecified
// address for A and AAAA queries and no records for others, with a
// synthetic SOA so resolvers and HTTP caches keep negative answers only
// briefly ([RFC 2308, Section 5]). EDNS clients are told why with an
// Extended DNS Error ([RFC 8914, Section 4.16]), so a block isn't mistaken
// for a failure.
//
// [RFC 2308, Section 5]: https://www.rfc-editor.org/rfc/rfc2308.html#section-5
// [RFC 8914, Section 4.16]: https://www.rfc-editor.org/rfc/rfc8914.html#section-4.16
func (p *Profile) Block(query *dns.Msg, d Decision) *dns.Msg {
	resp := new(dns.Msg).SetReply(query)
	resp.RecursionAvailable = true

	q := query.Question[0]
	name := canonical(q.Name)

	// Name the SOA after the blocked domain when the rule is one, as
	// resolvers expect negative answers from the zone's apex.
	soaName := name
	if d.Rule != "" && (name == d.Rule || strings.HasSuffix(name, "."+d.Rule)) {
		soaName = d.Rule
	}

	switch {
	case p.blockResponse == policy.BlockNull && q.Qtype == dns.TypeA:
		resp.Answer = append(resp.Answer, &dns.A{Hdr: header(q.Name, dns.TypeA), A: net.IPv4zero})
	case p.blockResponse == policy.BlockNull && q.Qtype == dns.TypeAAAA:
		resp.Answer = append(resp.Answer, &dns.AAAA{Hdr: header(q.Name, dns.TypeAAAA), AAAA: net.IPv6zero})
	case p.blockResponse == policy.BlockNull:
		resp.Ns = append(resp.Ns, SOA(soaName))
	default:
		resp.Rcode = dns.RcodeNameError
		resp.Ns = append(resp.Ns, SOA(soaName))
	}

	text := "blocked: " + d.Reason
	if d.Reason == ReasonList {
		text = "blocked by " + d.Source
	}
	return withEDE(query, resp, dns.ExtendedErrorCodeBlocked, text)
}

// Rewrite returns the profile's local answer for a rewritten query: the
// rewrite's addresses of the queried family, or a CNAME to its target, to
// which the caller appends the target's records.
func (p *Profile) Rewrite(query *dns.Msg, d Decision) *dns.Msg {
	resp := new(dns.Msg).SetReply(query)
	resp.Authoritative, resp.RecursionAvailable = true, true

	q := query.Question[0]
	if d.Target != "" {
		resp.Answer = append(resp.Answer, &dns.CNAME{Hdr: header(q.Name, dns.TypeCNAME), Target: d.Target})
		return resp
	}

	for _, a := range d.Addrs {
		switch {
		case a.Is4() && q.Qtype == dns.TypeA:
			resp.Answer = append(resp.Answer, &dns.A{Hdr: header(q.Name, dns.TypeA), A: a.AsSlice()})
		case a.Is6() && q.Qtype == dns.TypeAAAA:
			resp.Answer = append(resp.Answer, &dns.AAAA{Hdr: header(q.Name, dns.TypeAAAA), AAAA: a.AsSlice()})
		}
	}
	if len(resp.Answer) == 0 {
		resp.Ns = append(resp.Ns, SOA(canonical(q.Name)))
	}
	return resp
}

// Refuse returns the answer to a query from a client no profile covers.
func Refuse(query *dns.Msg) *dns.Msg {
	resp := new(dns.Msg).SetRcode(query, dns.RcodeRefused)
	resp.RecursionAvailable = true
	return withEDE(query, resp, dns.ExtendedErrorCodeProhibited, "no profile for this client")
}

// withEDE adds an Extended DNS Error to resp if query used EDNS.
func withEDE(query, resp *dns.Msg, code uint16, text string) *dns.Msg {
	if opt := query.IsEdns0(); opt != nil {
		resp.SetEdns0(dns.DefaultMsgSize, opt.Do())
		resp.IsEdns0().Option = append(resp.IsEdns0().Option, &dns.EDNS0_EDE{InfoCode: code, ExtraText: text})
	}
	return resp
}

func header(name string, rrtype uint16) dns.RR_Header {
	return dns.RR_Header{Name: name, Rrtype: rrtype, Class: dns.ClassINET, Ttl: BlockedTTL}
}

// SOA returns a synthetic SOA record for a locally answered zone, with
// every timer set to [BlockedTTL].
func SOA(zone string) *dns.SOA {
	return &dns.SOA{
		Hdr:     dns.RR_Header{Name: dns.Fqdn(zone), Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: BlockedTTL},
		Ns:      "localhost.",
		Mbox:    "nobody.invalid.",
		Serial:  1,
		Refresh: BlockedTTL,
		Retry:   BlockedTTL,
		Expire:  BlockedTTL,
		Minttl:  BlockedTTL,
	}
}

// Features describes the built-in protections profiles can toggle, for
// people choosing them.
func Features() []api.Feature {
	return []api.Feature{
		{ID: "rebinding", Category: blocklist.CategorySecurity, Default: true,
			Title:       "DNS rebinding protection",
			Description: "Blocks public names that point to private, loopback, or link-local addresses, which web pages use to attack devices on your network. Local names, such as printer.lan, are exempt."},
		{ID: "homograph", Category: blocklist.CategorySecurity, Default: true,
			Title:       "Look-alike domain protection",
			Description: "Blocks internationalized names that mix scripts or spell Latin-looking names in other alphabets, such as аpple.com with a Cyrillic а."},
		{ID: "newly_registered", Category: blocklist.CategorySecurity,
			Title:       "Newly registered domains",
			Description: "Blocks domains registered in the last 30 days (or as many as you choose), which are often used for phishing and malware. Dates come from the registries' RDAP services, which see the domain looked up but not who asked; TLDs without RDAP aren't checked."},
		{ID: "tunneling", Category: blocklist.CategorySecurity,
			Title:       "DNS tunneling protection",
			Description: "Blocks queries that look like data smuggled through DNS: long random labels, NULL records, and bursts of unique names under one domain. Some security software queries this way; allow its domains if needed."},
		{ID: "bypass", Category: blocklist.CategorySecurity,
			Title:       "Block bypass methods",
			Description: "Stops devices routing around this resolver through iCloud Private Relay or public encrypted DNS services."},
		{ID: "safe_search", Category: blocklist.CategoryParental,
			Title:       "Safe search",
			Description: "Enforces safe search on Google, Bing, DuckDuckGo, and Pixabay, and restricted mode on YouTube."},
	}
}
