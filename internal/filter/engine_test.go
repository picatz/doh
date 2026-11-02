package filter

import (
	"context"
	"fmt"

	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/picatz/doh/internal/api"
	"github.com/picatz/doh/internal/blocklist"
	"github.com/picatz/doh/internal/policy"
	"github.com/picatz/doh/internal/rdap"
)

// lists returns a registry with one file list, named "test", loaded.
func lists(t *testing.T, content string) (*blocklist.Registry, string) {
	t.Helper()

	path := filepath.Join(t.TempDir(), "list.txt")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	reg := blocklist.NewRegistry(&blocklist.Loader{}, nil)
	t.Cleanup(reg.Close)

	src := blocklist.Source{Name: "test", Location: path}
	reg.Sync([]blocklist.Source{src})
	if err := reg.Wait(t.Context(), src); err != nil {
		t.Fatal(err)
	}
	return reg, "test=" + path
}

// engine compiles profiles into an engine.
func engine(t testing.TB, opts Options, profiles ...policy.Profile) *Engine {
	t.Helper()
	e, err := New(&policy.Policy{Profiles: profiles}, opts)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func TestEngine_Match(t *testing.T) {
	e := engine(t, Options{},
		policy.Profile{ID: "default"},
		policy.Profile{ID: "lan", Clients: []string{"192.168.1.0/24", "fd00::/8"}},
		policy.Profile{ID: "streaming", Devices: []policy.Device{{Name: "tv", Addrs: []string{"192.168.1.50"}}}},
	)

	for _, tt := range []struct {
		client, profile, device string
	}{
		{"192.168.1.10", "lan", ""},
		{"192.168.1.50", "streaming", "tv"},        // the more specific prefix wins
		{"::ffff:192.168.1.50", "streaming", "tv"}, // IPv4-mapped clients match as IPv4
		{"10.0.0.1", "default", ""},
		{"fd00::1", "lan", ""},
		{"2001:db8::1", "default", ""},
	} {
		pr, device := e.Match(netip.MustParseAddr(tt.client))
		if pr == nil || pr.ID() != tt.profile || device != tt.device {
			t.Errorf("Match(%s) = %v, %q; want %s, %q", tt.client, pr, device, tt.profile, tt.device)
		}
	}

	if pr, _ := e.Match(netip.Addr{}); pr == nil || pr.ID() != "default" {
		t.Errorf("Match(invalid) = %v, want default", pr)
	}
}

func TestEngine_MatchClosed(t *testing.T) {
	// Without a default profile, unknown clients get no profile.
	e := engine(t, Options{}, policy.Profile{ID: "home", Clients: []string{"192.168.1.0/24"}})

	if pr, _ := e.Match(netip.MustParseAddr("203.0.113.9")); pr != nil {
		t.Errorf("Match(unknown) = %s, want nil", pr.ID())
	}
	if pr, _ := e.Match(netip.MustParseAddr("192.168.1.9")); pr == nil {
		t.Error("Match(known) = nil, want home")
	}

	resp := Refuse(new(dns.Msg).SetQuestion("example.com.", dns.TypeA).SetEdns0(1232, false))
	if resp.Rcode != dns.RcodeRefused || ede(resp) == nil || ede(resp).InfoCode != dns.ExtendedErrorCodeProhibited {
		t.Errorf("Refuse = %v, want REFUSED with a Prohibited EDE", resp)
	}
}

func TestNew_RejectsInvalidPolicy(t *testing.T) {
	for _, p := range []policy.Profile{
		{ID: "Bad ID"},
		{ID: "x", Clients: []string{"not-an-ip"}},
		{ID: "x", Lists: []string{"no-such-preset"}},
		{ID: "x", BlockResponse: "drop"},
		{ID: "x", Rewrites: []policy.Rewrite{{Name: "nas.lan", Addrs: []string{"nope"}}}},
	} {
		if _, err := New(&policy.Policy{Profiles: []policy.Profile{p}}, Options{}); err == nil {
			t.Errorf("New(%+v) succeeded, want an error", p)
		}
	}
}

func TestProfile_Check(t *testing.T) {
	reg, list := lists(t, "||ads.example^\n@@||ok.ads.example^\n||cloak.example^\n")

	e := engine(t, Options{Lists: reg, Exempt: []string{"dns.google"}}, policy.Profile{
		ID:        "default",
		Lists:     []string{list},
		Allow:     []string{"allowed.example", "dns.quad9.net"},
		Deny:      []string{"denied.example"},
		BlockTLDs: []string{"zip"},
		Rewrites: []policy.Rewrite{
			{Name: "nas.home.arpa", Addrs: []string{"192.168.1.5", "fd00::5"}},
			{Name: "*.lab.example", Addrs: []string{"10.0.0.1"}},
		},
		SafeSearch: true,
		Security:   policy.Security{Homograph: true, Bypass: true, Tunneling: true},
	})
	pr := e.Profile("default")

	for _, tt := range []struct {
		name   string
		qtype  uint16
		action string
		reason string
		rule   string
	}{
		{"example.com", dns.TypeA, api.ActionAllow, "", ""},
		{"x.ads.example", dns.TypeA, api.ActionBlock, ReasonList, "ads.example"},
		{"ok.ads.example", dns.TypeA, api.ActionAllow, "", ""}, // the list's exception
		{"denied.example", dns.TypeA, api.ActionBlock, ReasonDeny, "denied.example"},
		{"a.allowed.example", dns.TypeA, api.ActionAllow, ReasonAllow, "allowed.example"},
		{"file.zip", dns.TypeA, api.ActionBlock, ReasonTLD, "zip"},
		{"dns.google", dns.TypeA, api.ActionAllow, ReasonUpstream, "dns.google"}, // an upstream, though a bypass service
		{"cloudflare-dns.com", dns.TypeA, api.ActionBlock, ReasonBypass, "cloudflare-dns.com"},
		{"dns.quad9.net", dns.TypeA, api.ActionAllow, ReasonAllow, "dns.quad9.net"}, // allowing beats bypass protection
		{"mask.icloud.com", dns.TypeAAAA, api.ActionBlock, ReasonBypass, "mask.icloud.com"},
		{"use-application-dns.net", dns.TypeA, api.ActionBlock, ReasonBypass, "use-application-dns.net"},
		{"nas.home.arpa", dns.TypeA, api.ActionRewrite, ReasonRewrite, "nas.home.arpa"},
		{"a.lab.example", dns.TypeA, api.ActionRewrite, ReasonRewrite, "*.lab.example"},
		{"lab.example", dns.TypeA, api.ActionAllow, "", ""}, // wildcards cover subdomains only
		{"www.google.co.uk", dns.TypeA, api.ActionRewrite, ReasonSafeSearch, "www.google.co.uk"},
		{"www.youtube.com", dns.TypeHTTPS, api.ActionRewrite, ReasonSafeSearch, "www.youtube.com"},
		{"xn--pple-43d.com", dns.TypeA, api.ActionBlock, ReasonHomograph, "xn--pple-43d.com"}, // аpple.com
		{"x.example.com", dns.TypeNULL, api.ActionBlock, ReasonTunneling, "x.example.com"},
		{"mzxw6ytboi2dqmzxw6ytboi2dqmzxw6ytboi2dqmzxw6ytboi2dqmz.t.example.com", dns.TypeA, api.ActionBlock, ReasonTunneling, "example.com"},
		{"0123456789abcdef0123456789abcdef.cdn.example.com", dns.TypeA, api.ActionAllow, "", ""}, // a hex hash isn't encoded data
	} {
		t.Run(tt.name, func(t *testing.T) {
			var trace Trace
			d := pr.Check(t.Context(), Query{Name: tt.name + ".", Type: tt.qtype}, &trace)
			if d.Action != tt.action || d.Reason != tt.reason || d.Rule != tt.rule {
				t.Errorf("Check = %+v, want %s/%s/%s; trace %+v", d.Decision, tt.action, tt.reason, tt.rule, trace.Checks)
			}
			if tt.reason != "" && tt.reason != ReasonUpstream {
				last := trace.Checks[len(trace.Checks)-1]
				if last.Result != api.CheckMatch || last.Check != tt.reason {
					t.Errorf("last check = %+v, want a %s match", last, tt.reason)
				}
			}
		})
	}
}

func TestProfile_CanaryOnlyWhenFiltering(t *testing.T) {
	e := engine(t, Options{}, policy.Profile{ID: "default"})
	if d := e.Profile("default").Check(t.Context(), Query{Name: firefoxCanary, Type: dns.TypeA}, nil); d.Action != api.ActionAllow {
		t.Errorf("a profile that filters nothing answered the canary with %+v, want it forwarded", d.Decision)
	}
}

func TestProfile_TunnelingBurst(t *testing.T) {
	e := engine(t, Options{}, policy.Profile{ID: "default", Security: policy.Security{Tunneling: true}})
	pr := e.Profile("default")
	client := netip.MustParseAddr("192.168.1.9")
	other := netip.MustParseAddr("192.168.1.10")

	var blocked int
	for i := range tunnelBurst + 10 {
		d := pr.Check(t.Context(), Query{Name: fmt.Sprintf("q%d.exfil.example.com.", i), Type: dns.TypeA, Client: client}, nil)
		if d.Action == api.ActionBlock {
			blocked++
		}
	}
	if blocked < 10 {
		t.Errorf("blocked %d of a burst of unique names, want the domain flagged", blocked)
	}

	// The flag applies to that client and domain only.
	if d := pr.Check(t.Context(), Query{Name: "q0.exfil.example.com.", Type: dns.TypeA, Client: other}, nil); d.Action != api.ActionAllow {
		t.Errorf("another client was blocked: %+v", d.Decision)
	}
	if d := pr.Check(t.Context(), Query{Name: "www.example.org.", Type: dns.TypeA, Client: client}, nil); d.Action != api.ActionAllow {
		t.Errorf("another domain was blocked: %+v", d.Decision)
	}
}

func TestTunnelTracker_Expires(t *testing.T) {
	tr := newTunnelTracker()
	now := time.Unix(0, 0)
	tr.now = func() time.Time { return now }
	client := netip.MustParseAddr("192.0.2.1")

	for i := range tunnelBurst {
		tr.observe(client, "example.com", fmt.Sprint(i))
	}
	if !tr.observe(client, "example.com", "x") {
		t.Fatal("not flagged after a burst")
	}

	now = now.Add(tunnelCooldown)
	if tr.observe(client, "example.com", "y") {
		t.Error("still flagged after the cooldown")
	}

	// Names spread over windows aren't a burst.
	for i := range tunnelBurst * 2 {
		now = now.Add(tunnelPeriod / tunnelBurst * 2)
		if tr.observe(client, "slow.example", fmt.Sprint(i)) {
			t.Fatalf("flagged a slow trickle at %d", i)
		}
	}
}

func TestProfile_CheckResponse(t *testing.T) {
	reg, list := lists(t, "||tracker.example^\n")
	e := engine(t, Options{Lists: reg}, policy.Profile{
		ID:       "default",
		Lists:    []string{list},
		Allow:    []string{"nas.example.com"},
		Deny:     []string{"denied.example"},
		Security: policy.Security{Rebinding: true},
	})
	pr := e.Profile("default")

	answer := func(name string, rrs ...string) *dns.Msg {
		m := new(dns.Msg).SetQuestion(name, dns.TypeA)
		for _, s := range rrs {
			rr, err := dns.NewRR(s)
			if err != nil {
				t.Fatal(err)
			}
			m.Answer = append(m.Answer, rr)
		}
		return m
	}

	for _, tt := range []struct {
		desc   string
		resp   *dns.Msg
		reason string
	}{
		{"public address", answer("www.example.com.", "www.example.com. 60 IN A 93.184.215.14"), ""},
		{"private address", answer("evil.example.com.", "evil.example.com. 60 IN A 192.168.1.1"), ReasonRebinding},
		{"loopback", answer("evil.example.com.", "evil.example.com. 60 IN A 127.0.0.1"), ReasonRebinding},
		{"unspecified", answer("evil.example.com.", "evil.example.com. 60 IN A 0.0.0.0"), ReasonRebinding},
		{"metadata service", answer("evil.example.com.", "evil.example.com. 60 IN A 169.254.169.254"), ReasonRebinding},
		{"ipv6 loopback", answer("evil.example.com.", "evil.example.com. 60 IN AAAA ::1"), ReasonRebinding},
		{"mapped private", answer("evil.example.com.", "evil.example.com. 60 IN AAAA ::ffff:10.0.0.1"), ReasonRebinding},
		{"nat64 private", answer("evil.example.com.", "evil.example.com. 60 IN AAAA 64:ff9b::a00:1"), ReasonRebinding},
		{"https hint", answer("evil.example.com.", `evil.example.com. 60 IN HTTPS 1 . ipv4hint="10.1.2.3"`), ReasonRebinding},
		{"cgnat allowed", answer("box.example.com.", "box.example.com. 60 IN A 100.101.102.103"), ""},
		{"allowed name", answer("nas.example.com.", "nas.example.com. 60 IN A 192.168.1.5"), ""},
		{"local name", answer("printer.lan.", "printer.lan. 60 IN A 192.168.1.7"), ""},
		{"cname to tracker", answer("metrics.shop.example.", "metrics.shop.example. 60 IN CNAME x.tracker.example.", "x.tracker.example. 60 IN A 203.0.113.1"), ReasonCNAME},
		{"cname to denied", answer("a.shop.example.", "a.shop.example. 60 IN CNAME denied.example.", "denied.example. 60 IN A 203.0.113.1"), ReasonCNAME},
		{"cname allowed", answer("cdn.shop.example.", "cdn.shop.example. 60 IN CNAME cdn.provider.example.", "cdn.provider.example. 60 IN A 203.0.113.1"), ""},
	} {
		t.Run(tt.desc, func(t *testing.T) {
			q := tt.resp.Question[0]
			d := pr.CheckResponse(Query{Name: q.Name, Type: q.Qtype}, tt.resp, nil)
			if d.Reason != tt.reason && !(tt.reason == "" && (d.Reason == ReasonAllow || d.Reason == "")) {
				t.Errorf("CheckResponse = %+v, want reason %q", d.Decision, tt.reason)
			}
			if (tt.reason != "") != (d.Action == api.ActionBlock) {
				t.Errorf("CheckResponse action %s, want block %v", d.Action, tt.reason != "")
			}
		})
	}
}

func TestProfile_RebindingOff(t *testing.T) {
	e := engine(t, Options{}, policy.Profile{ID: "default"})
	resp, _ := dns.NewRR("evil.example.com. 60 IN A 127.0.0.1")
	m := new(dns.Msg).SetQuestion("evil.example.com.", dns.TypeA)
	m.Answer = append(m.Answer, resp)
	if d := e.Profile("default").CheckResponse(Query{Name: "evil.example.com.", Type: dns.TypeA}, m, nil); d.Action != api.ActionAllow {
		t.Errorf("rebinding blocked while off: %+v", d.Decision)
	}
}

func ede(m *dns.Msg) *dns.EDNS0_EDE {
	if opt := m.IsEdns0(); opt != nil {
		for _, o := range opt.Option {
			if e, ok := o.(*dns.EDNS0_EDE); ok {
				return e
			}
		}
	}
	return nil
}

func TestProfile_Block(t *testing.T) {
	for _, tt := range []struct {
		response string
		qtype    uint16
		rcode    int
		answer   string
	}{
		{policy.BlockNXDomain, dns.TypeA, dns.RcodeNameError, ""},
		{policy.BlockNull, dns.TypeA, dns.RcodeSuccess, "0.0.0.0"},
		{policy.BlockNull, dns.TypeAAAA, dns.RcodeSuccess, "::"},
		{policy.BlockNull, dns.TypeMX, dns.RcodeSuccess, ""},
	} {
		e := engine(t, Options{}, policy.Profile{ID: "default", BlockResponse: tt.response})
		query := new(dns.Msg).SetQuestion("x.ads.example.", tt.qtype).SetEdns0(1232, true)
		resp := e.Profile("default").Block(query, block(ReasonList, "ads.example", "test", ""))

		if resp.Rcode != tt.rcode {
			t.Errorf("%s %s: rcode %s, want %s", tt.response, dns.TypeToString[tt.qtype], dns.RcodeToString[resp.Rcode], dns.RcodeToString[tt.rcode])
		}
		switch {
		case tt.answer != "" && (len(resp.Answer) != 1 || !strings.Contains(resp.Answer[0].String(), tt.answer)):
			t.Errorf("%s %s: answer %v, want %s", tt.response, dns.TypeToString[tt.qtype], resp.Answer, tt.answer)
		case tt.answer == "" && (len(resp.Ns) != 1 || resp.Ns[0].Header().Name != "ads.example."):
			t.Errorf("%s %s: authority %v, want an SOA for the blocked domain", tt.response, dns.TypeToString[tt.qtype], resp.Ns)
		}
		if e := ede(resp); e == nil || e.ExtraText != "blocked by test" {
			t.Errorf("EDE = %v, want blocked by test", e)
		}
		if !resp.IsEdns0().Do() {
			t.Error("DO bit not echoed")
		}
	}

	// Rules that aren't domains name the SOA after the query.
	e := engine(t, Options{}, policy.Profile{ID: "default"})
	resp := e.Profile("default").Block(new(dns.Msg).SetQuestion("evil.example.com.", dns.TypeA), block(ReasonRebinding, "127.0.0.1", "", ""))
	if resp.Ns[0].Header().Name != "evil.example.com." {
		t.Errorf("SOA %v, want one for the query name", resp.Ns[0])
	}
}

func TestProfile_Rewrite(t *testing.T) {
	e := engine(t, Options{}, policy.Profile{ID: "default"})
	pr := e.Profile("default")
	addrs := []netip.Addr{netip.MustParseAddr("192.168.1.5"), netip.MustParseAddr("fd00::5")}

	a := pr.Rewrite(new(dns.Msg).SetQuestion("nas.lan.", dns.TypeA), Decision{Addrs: addrs})
	if len(a.Answer) != 1 || a.Answer[0].(*dns.A).A.String() != "192.168.1.5" {
		t.Errorf("A rewrite = %v", a.Answer)
	}
	aaaa := pr.Rewrite(new(dns.Msg).SetQuestion("nas.lan.", dns.TypeAAAA), Decision{Addrs: addrs})
	if len(aaaa.Answer) != 1 || aaaa.Answer[0].(*dns.AAAA).AAAA.String() != "fd00::5" {
		t.Errorf("AAAA rewrite = %v", aaaa.Answer)
	}
	mx := pr.Rewrite(new(dns.Msg).SetQuestion("nas.lan.", dns.TypeMX), Decision{Addrs: addrs})
	if len(mx.Answer) != 0 || mx.Rcode != dns.RcodeSuccess || len(mx.Ns) != 1 {
		t.Errorf("MX rewrite = %v, want NODATA", mx)
	}
	cname := pr.Rewrite(new(dns.Msg).SetQuestion("www.bing.com.", dns.TypeA), Decision{Target: "strict.bing.com."})
	if len(cname.Answer) != 1 || cname.Answer[0].(*dns.CNAME).Target != "strict.bing.com." {
		t.Errorf("CNAME rewrite = %v", cname.Answer)
	}
}

// rdapServer serves an RDAP bootstrap for .com and .org, with domains
// registered at the given times.
func rdapServer(t *testing.T, registered map[string]time.Time) *rdap.Ages {
	t.Helper()

	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/bootstrap" {
			fmt.Fprintf(w, `{"version":"1.0","services":[[["com","org"],["%s/rdap/"]]]}`, srv.URL)
			return
		}
		domain := strings.TrimPrefix(r.URL.Path, "/rdap/domain/")
		when, ok := registered[domain]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/rdap+json")
		fmt.Fprintf(w, `{"objectClassName":"domain","ldhName":%q,"events":[{"eventAction":"registration","eventDate":%q}]}`, domain, when.Format(time.RFC3339))
	}))
	t.Cleanup(srv.Close)

	return &rdap.Ages{Client: &rdap.Client{BootstrapURL: srv.URL + "/bootstrap"}}
}

func TestProfile_NewlyRegistered(t *testing.T) {
	ages := rdapServer(t, map[string]time.Time{
		"fresh.com":   time.Now().Add(-3 * 24 * time.Hour),
		"old.com":     time.Now().Add(-10 * 365 * 24 * time.Hour),
		"twoweek.org": time.Now().Add(-14 * 24 * time.Hour),
	})

	e := engine(t, Options{Ages: ages},
		policy.Profile{ID: "default", Security: policy.Security{NewlyRegistered: true}},
		policy.Profile{ID: "strict", Security: policy.Security{NewlyRegistered: true, NewlyRegisteredDays: 7}},
	)

	for _, tt := range []struct {
		profile, name string
		blocked       bool
	}{
		{"default", "www.fresh.com", true},
		{"default", "old.com", false},
		{"default", "twoweek.org", true},
		{"strict", "twoweek.org", false},  // older than this profile's threshold
		{"default", "unknown.com", false}, // not found: fail open
		{"default", "example.net", false}, // TLD without RDAP: fail open
		{"default", "printer.lan", false}, // never looked up
	} {
		var trace Trace
		d := e.Profile(tt.profile).Check(t.Context(), Query{Name: tt.name, Type: dns.TypeA}, &trace)
		if got := d.Action == api.ActionBlock; got != tt.blocked {
			t.Errorf("%s %s: %+v, want blocked %v; trace %+v", tt.profile, tt.name, d.Decision, tt.blocked, trace.Checks)
		}
		if tt.blocked && d.Reason != ReasonNewlyRegistered {
			t.Errorf("%s: reason %q", tt.name, d.Reason)
		}
	}
}

func TestProfile_NewlyRegisteredUnavailable(t *testing.T) {
	e := engine(t, Options{}, policy.Profile{ID: "default", Security: policy.Security{NewlyRegistered: true}})
	var trace Trace
	if d := e.Profile("default").Check(context.Background(), Query{Name: "fresh.com", Type: dns.TypeA}, &trace); d.Action != api.ActionAllow {
		t.Errorf("Check = %+v, want allowed without registration lookups", d.Decision)
	}
}

func TestBaseline(t *testing.T) {
	reg, list := lists(t, "||ads.example^\n")
	e := engine(t, Options{Lists: reg, Baseline: Baseline{Lists: []string{list}, Deny: []string{"base.example"}, Allow: []string{"ok.ads.example"}, BlockResponse: policy.BlockNull}},
		policy.Profile{ID: "default"},
		policy.Profile{ID: "kids", BlockResponse: policy.BlockNXDomain, Allow: []string{"base.example"}},
	)

	if got := len(e.Sources()); got != 1 {
		t.Errorf("Sources() has %d sources, want the baseline list shared once", got)
	}

	check := func(profile, name string) Decision {
		return e.Profile(profile).Check(t.Context(), Query{Name: name, Type: dns.TypeA}, nil)
	}
	if d := check("default", "x.ads.example"); d.Reason != ReasonList {
		t.Errorf("baseline list not applied: %+v", d.Decision)
	}
	if d := check("default", "ok.ads.example"); d.Action != api.ActionAllow {
		t.Errorf("baseline allow not applied: %+v", d.Decision)
	}
	if d := check("default", "base.example"); d.Reason != ReasonDeny {
		t.Errorf("baseline deny not applied: %+v", d.Decision)
	}
	if d := check("kids", "base.example"); d.Action != api.ActionAllow {
		t.Errorf("a profile's allow didn't override the baseline deny: %+v", d.Decision)
	}

	q := new(dns.Msg).SetQuestion("x.ads.example.", dns.TypeA)
	if resp := e.Profile("default").Block(q, check("default", "x.ads.example")); resp.Rcode != dns.RcodeSuccess {
		t.Errorf("baseline block response not used: %s", dns.RcodeToString[resp.Rcode])
	}
	if resp := e.Profile("kids").Block(q, check("kids", "x.ads.example")); resp.Rcode != dns.RcodeNameError {
		t.Errorf("profile block response not used: %s", dns.RcodeToString[resp.Rcode])
	}
}

func TestIsRebindingTarget(t *testing.T) {
	for addr, want := range map[string]bool{
		"10.1.2.3": true, "172.16.0.1": true, "172.32.0.1": false, "192.168.0.1": true,
		"127.0.0.1": true, "0.0.0.0": true, "169.254.169.254": true, "100.64.0.1": false,
		"8.8.8.8": false, "::1": true, "::": true, "fe80::1": true, "fd12::1": true,
		"2001:db8::1": false, "::ffff:127.0.0.1": true, "64:ff9b::808:808": false,
	} {
		if got := IsRebindingTarget(netip.MustParseAddr(addr)); got != want {
			t.Errorf("IsRebindingTarget(%s) = %v, want %v", addr, got, want)
		}
	}
}

func TestEntropy(t *testing.T) {
	if h := entropy("aaaa"); h != 0 {
		t.Errorf("entropy(aaaa) = %v", h)
	}
	if h := entropy("ab"); h != 1 {
		t.Errorf("entropy(ab) = %v", h)
	}
	if h := entropy(strings.Repeat("0123456789abcdef", 4)); h != 4 {
		t.Errorf("entropy(hex) = %v", h)
	}
}

func TestFeatures(t *testing.T) {
	ids := make(map[string]bool)
	for _, f := range Features() {
		if f.ID == "" || f.Title == "" || f.Description == "" || ids[f.ID] {
			t.Errorf("bad feature %+v", f)
		}
		ids[f.ID] = true
	}

	// Defaults match the default policy.
	def := policy.Defaults().Profiles[0].Security
	for id, on := range map[string]bool{
		"rebinding": def.Rebinding, "homograph": def.Homograph, "newly_registered": def.NewlyRegistered, "tunneling": def.Tunneling, "bypass": def.Bypass,
		"typosquatting": def.Typosquatting, "dga": def.DGA, "safe_browsing": def.SafeBrowsing,
	} {
		for _, f := range Features() {
			if f.ID == id && f.Default != on {
				t.Errorf("feature %s default %v, but the default policy has %v", id, f.Default, on)
			}
		}
	}
}

func TestCanary(t *testing.T) {
	for name, want := range map[string]bool{
		"use-application-dns.net":      true,
		"mask.icloud.com":              true,
		"mask-h2.icloud.com":           true,
		"dns.google":                   false,
		"icloud.com":                   false,
		"use-application-dns.net.evil": false,
	} {
		if got := Canary(name); got != want {
			t.Errorf("Canary(%q) = %v, want %v", name, got, want)
		}
	}
}
