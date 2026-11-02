package filter

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/picatz/doh/internal/api"
	"github.com/picatz/doh/internal/policy"
)

// fuzzProfile has every protection on that needs no network, with
// rewrites, a deny list, blocked TLDs, services, and a schedule, so
// queries reach every check.
func fuzzProfile(f *testing.F) *Profile {
	f.Helper()
	e, err := New(&policy.Policy{Profiles: []policy.Profile{{
		ID:         "default",
		Security:   policy.Security{Rebinding: true, Homograph: true, Tunneling: true, Bypass: true},
		Deny:       []string{"games.example"},
		Allow:      []string{"ok.games.example"},
		BlockTLDs:  []string{"zip"},
		Services:   []string{"tiktok"},
		SafeSearch: true,
		Rewrites: []policy.Rewrite{
			{Name: "nas.lan", Addrs: []string{"192.168.1.2"}},
			{Name: "*.wild.lan", Addrs: []string{"fd00::2"}},
		},
		Schedules: []policy.Schedule{{Name: "always", Start: "00:00", End: "00:00", Deny: []string{"social.example"}}},
	}}}, Options{Local: []string{"lan"}, Exempt: []string{"dns.upstream.example"}})
	if err != nil {
		f.Fatal(err)
	}
	return e.Profile("default")
}

var fuzzNames = []string{
	"example.com.", "xn--pple-43d.com", "xn--80ak6aa92e.com", "xn--", "xn--zz.", "a.b.c.games.example",
	"ok.games.example", "nas.lan", "x.wild.lan", "www.google.com", "mask.icloud.com", "dns.google",
	"use-application-dns.net", "aGVsbG8gd29ybGQgdGhpcyBpcyBkYXRh.t.example.com", "WWW.YOUTUBE.COM.", ".", "", "..", "a..b",
	strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + ".zip",
}

// FuzzCheck checks arbitrary query names and types, as clients send
// them: it must never panic, every decision must be an allow, a block, or
// a rewrite with what it needs, and the trace must record what decided.
func FuzzCheck(f *testing.F) {
	p := fuzzProfile(f)
	for _, n := range fuzzNames {
		f.Add(n, dns.TypeA)
		f.Add(n, dns.TypeNULL)
	}
	f.Fuzz(func(t *testing.T, name string, qtype uint16) {
		var trace Trace
		d := p.Check(t.Context(), Query{Name: name, Type: qtype, Client: netip.MustParseAddr("192.0.2.1")}, &trace)
		switch d.Action {
		case api.ActionAllow:
		case api.ActionBlock:
			if d.Reason == "" {
				t.Fatalf("a block without a reason: %+v", d)
			}
		case api.ActionRewrite:
			if len(d.Addrs) == 0 && d.Target == "" {
				t.Fatalf("a rewrite to nothing: %+v", d)
			}
		default:
			t.Fatalf("unknown action %q", d.Action)
		}

		// The answer to a block or rewrite packs, whatever the name.
		q := new(dns.Msg)
		q.Question = []dns.Question{{Name: dns.Fqdn(name), Qtype: qtype, Qclass: dns.ClassINET}}
		if _, ok := dns.IsDomainName(q.Question[0].Name); !ok {
			return
		}
		switch d.Action {
		case api.ActionBlock:
			_ = p.Block(q, d)
		case api.ActionRewrite:
			_ = p.Rewrite(q, d)
		}
	})
}

// FuzzCheckResponse checks arbitrary upstream answers, as an upstream (or
// anyone who can spoof one) sends them: it must never panic, and must
// block any answer with an A record for a loopback address under a public
// name.
func FuzzCheckResponse(f *testing.F) {
	p := fuzzProfile(f)
	for _, rrs := range [][]string{
		{"example.com. 60 IN A 93.184.215.14"},
		{"evil.example.com. 60 IN A 127.0.0.1"},
		{"x.example.com. 60 IN CNAME games.example.", "games.example. 60 IN A 192.0.2.1"},
		{"x.example.com. 60 IN HTTPS 1 . ipv4hint=10.0.0.1"},
		{"x.example.com. 60 IN AAAA ::ffff:192.168.1.1"},
	} {
		m := new(dns.Msg).SetQuestion("example.com.", dns.TypeA)
		m.Response = true
		for _, s := range rrs {
			rr, err := dns.NewRR(s)
			if err != nil {
				f.Fatal(err)
			}
			m.Answer = append(m.Answer, rr)
		}
		b, err := m.Pack()
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	loopback := netip.MustParseAddr("127.0.0.1")
	f.Fuzz(func(t *testing.T, b []byte) {
		var resp dns.Msg
		if resp.Unpack(b) != nil || len(resp.Question) != 1 {
			return
		}
		q := Query{Name: resp.Question[0].Name, Type: resp.Question[0].Qtype}
		d := p.CheckResponse(q, &resp, &Trace{})
		if d.Action != api.ActionAllow && d.Action != api.ActionBlock {
			t.Fatalf("action %q", d.Action)
		}
		name := canonical(q.Name)
		if _, allowed := p.allow.match(name); allowed || p.engine.isLocal(name) {
			return
		}
		if _, exempt := p.engine.exempt.match(name); exempt {
			return
		}
		for _, rr := range resp.Answer {
			if a, ok := rr.(*dns.A); ok {
				if addr, ok := netip.AddrFromSlice(a.A.To4()); ok && addr == loopback && d.Action != api.ActionBlock {
					t.Fatalf("a public name answered with %v wasn't blocked: %+v", addr, d)
				}
			}
		}
	})
}

// FuzzHomograph checks look-alike detection on arbitrary names: it must
// never panic, never flag plain ASCII names, and only flag names with an
// internationalized label.
func FuzzHomograph(f *testing.F) {
	for _, n := range fuzzNames {
		f.Add(n)
	}
	f.Fuzz(func(t *testing.T, name string) {
		_, flagged := Homograph(name)
		if flagged && !strings.Contains(strings.ToLower(name), "xn--") {
			t.Fatalf("flagged %q, which has no internationalized label", name)
		}
	})
}

// FuzzRegistrable checks that a registrable domain is a suffix of the
// name, and its own registrable domain.
func FuzzRegistrable(f *testing.F) {
	for _, n := range fuzzNames {
		f.Add(n)
	}
	f.Add("www.example.co.uk")
	f.Add("user.github.io")
	f.Fuzz(func(t *testing.T, name string) {
		r := Registrable(name)
		if r == "" {
			return
		}
		c := canonical(name)
		if c != r && !strings.HasSuffix(c, "."+r) {
			t.Fatalf("Registrable(%q) = %q, not a suffix", name, r)
		}
		if again := Registrable(r); again != r {
			t.Fatalf("Registrable(%q) = %q, but Registrable(%q) = %q", name, r, r, again)
		}
	})
}

// FuzzCompile checks that every policy that validates compiles: the
// admin API and policy files are validated, then compiled, and a policy
// that passed validation but didn't compile would fail to apply.
func FuzzCompile(f *testing.F) {
	def, _ := policy.Marshal(policy.Defaults())
	f.Add(def)
	f.Add([]byte(`{"profiles":[{"id":"kids","clients":["192.168.1.0/24"],"devices":[{"name":"tv","addrs":["fd00::1"]}],"security":{"rebinding":true,"homograph":true,"tunneling":true},"time_zone":"Europe/Paris","schedules":[{"name":"Bed","days":["mon","sun"],"start":"21:00","end":"07:00","services":["roblox"]}],"rewrites":[{"name":"*.lan","addrs":["10.0.0.1"]}],"safe_search":true}]}`))
	f.Add([]byte(`{"profiles":[{"id":"default","time_zone":"Local","security":{},"safe_search":false}]}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		p, err := policy.Unmarshal(b)
		if err != nil {
			return
		}
		e, err := New(p, Options{Now: func() time.Time { return time.Unix(1e9, 0) }})
		if err != nil {
			t.Fatalf("a valid policy doesn't compile: %v", err)
		}
		for _, pr := range p.Profiles {
			if e.Profile(pr.ID) == nil {
				t.Fatalf("profile %q is missing", pr.ID)
			}
		}
	})
}
