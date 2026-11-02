package filter

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/miekg/dns"
	"github.com/picatz/doh/internal/api"
	"github.com/picatz/doh/internal/policy"
)

// fakeReputation lists names, or fails.
type fakeReputation struct {
	listed map[string]string
	err    error
	calls  int
}

func (r *fakeReputation) Lookup(_ context.Context, name string) (string, bool, error) {
	r.calls++
	if r.err != nil {
		return "", false, r.err
	}
	why, ok := r.listed[name]
	return why, ok, nil
}

// traced returns the result of check in t's trace, or "".
func traced(t *Trace, check string) string {
	for _, c := range t.Checks {
		if c.Check == check {
			return c.Result + " " + c.Detail
		}
	}
	return ""
}

func TestProfile_ThreatChecks(t *testing.T) {
	rep := &fakeReputation{listed: map[string]string{"phish.example.com": "phish.example.com is listed by Google Safe Browsing for phishing or social engineering"}}
	on := policy.Security{Typosquatting: true, DGA: true, SafeBrowsing: true}
	e := engine(t, Options{Reputation: rep, Local: []string{"corp.example"}},
		policy.Profile{ID: "default", Security: on, Allow: []string{"paypa1.com"}},
		policy.Profile{ID: "off", Clients: []string{"10.0.0.0/8"}},
	)
	pr := e.Profile("default")

	for _, tt := range []struct {
		name, reason, rule, detail string
	}{
		{"paypal-login.com", ReasonTyposquatting, "paypal-login.com", `looks like paypal.com: paypal-login.com adds "login"`},
		{"www.paypal.com.example.net", ReasonTyposquatting, "example.net", "looks like paypal.com: www.paypal.com.example.net puts paypal.com inside another domain"},
		{"xjwqkzrtvbnmplkq.com", ReasonDGA, "xjwqkzrtvbnmplkq.com", "xjwqkzrtvbnmplkq.com looks machine-generated"},
		{"phish.example.com", ReasonSafeBrowsing, "phish.example.com", "phish.example.com is listed by Google Safe Browsing"},
	} {
		var tr Trace
		d := pr.Check(t.Context(), Query{Name: tt.name + ".", Type: dns.TypeA}, &tr)
		if d.Action != api.ActionBlock || d.Reason != tt.reason || d.Rule != tt.rule || !strings.HasPrefix(d.Detail, tt.detail) {
			t.Errorf("Check(%s) = %+v; want %s blocking %s with %q", tt.name, d.Decision, tt.reason, tt.rule, tt.detail)
		}
		if got := traced(&tr, tt.reason); !strings.HasPrefix(got, api.CheckMatch+" "+tt.detail) {
			t.Errorf("Check(%s) traced %s as %q", tt.name, tt.reason, got)
		}
	}

	// Legitimate names pass every check, and say so.
	for _, name := range []string{"www.paypal.com", "wikipedia.org", "login.microsoftonline.com", "paypa1.com", "printer.corp.example", "nas.lan"} {
		var tr Trace
		if d := pr.Check(t.Context(), Query{Name: name, Type: dns.TypeA}, &tr); d.Action != api.ActionAllow {
			t.Errorf("Check(%s) = %+v, want it allowed", name, d.Decision)
		}
	}
	var tr Trace
	pr.Check(t.Context(), Query{Name: "wikipedia.org", Type: dns.TypeA}, &tr)
	for check, want := range map[string]string{
		ReasonTyposquatting: "doesn't look like a brand's domain",
		ReasonDGA:           "doesn't look machine-generated",
		ReasonSafeBrowsing:  "not on Safe Browsing's lists",
	} {
		if got := traced(&tr, check); got != api.CheckPass+" "+want {
			t.Errorf("trace of %s = %q", check, got)
		}
	}

	// Local names aren't sent to the reputation service.
	calls := rep.calls
	pr.Check(t.Context(), Query{Name: "printer.corp.example", Type: dns.TypeA}, nil)
	pr.Check(t.Context(), Query{Name: "nas.lan", Type: dns.TypeA}, nil)
	if rep.calls != calls {
		t.Errorf("local names were looked up (%d calls)", rep.calls-calls)
	}

	// Profiles with the protections off skip them.
	tr = Trace{}
	if d := e.Profile("off").Check(t.Context(), Query{Name: "paypal-login.com", Type: dns.TypeA}, &tr); d.Action != api.ActionAllow {
		t.Errorf("a profile with typosquatting off blocked: %+v", d.Decision)
	}
	for _, check := range []string{ReasonTyposquatting, ReasonDGA, ReasonSafeBrowsing} {
		if got := traced(&tr, check); !strings.HasPrefix(got, api.CheckSkip) {
			t.Errorf("off profile traced %s as %q", check, got)
		}
	}
}

func TestProfile_SafeBrowsingFailsOpen(t *testing.T) {
	rep := &fakeReputation{err: errors.New("unavailable")}
	pr := engine(t, Options{Reputation: rep}, policy.Profile{ID: "default", Security: policy.Security{SafeBrowsing: true}}).Profile("default")
	var tr Trace
	if d := pr.Check(t.Context(), Query{Name: "phish.example.com", Type: dns.TypeA}, &tr); d.Action != api.ActionAllow {
		t.Errorf("a failed lookup blocked: %+v", d.Decision)
	}
	if got := traced(&tr, ReasonSafeBrowsing); got != api.CheckPass+" lookup failed (allowed): unavailable" {
		t.Errorf("trace = %q", got)
	}

	// Without a service, the check is skipped and says why.
	pr = engine(t, Options{}, policy.Profile{ID: "default", Security: policy.Security{SafeBrowsing: true}}).Profile("default")
	tr = Trace{}
	pr.Check(t.Context(), Query{Name: "phish.example.com", Type: dns.TypeA}, &tr)
	if got := traced(&tr, ReasonSafeBrowsing); got != api.CheckSkip+" Safe Browsing isn't set up on this server" {
		t.Errorf("trace without a service = %q", got)
	}
}

func BenchmarkProfile_Check(b *testing.B) {
	pr := engine(b, Options{}, policy.Profile{ID: "default", Security: policy.Security{Homograph: true, Typosquatting: true, DGA: true}}).Profile("default")
	for _, name := range []string{"www.example.com", "cdn.assets.some-long-legitimate-name.co.uk"} {
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				pr.Check(context.Background(), Query{Name: name, Type: dns.TypeA}, nil)
			}
		})
	}
}
