package blocklist

import (
	"errors"
	"io"
	"slices"
	"strings"
	"testing"
	"testing/iotest"
)

func rules(t *testing.T, input string) []Rule {
	t.Helper()

	var out []Rule
	for rule, err := range Rules(strings.NewReader(input)) {
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, rule)
	}
	return out
}

func TestRules(t *testing.T) {
	block := func(domain string) Rule { return Rule{Domain: domain} }
	blockAll := func(domain string) Rule { return Rule{Domain: domain, Subdomains: true} }
	allowAll := func(domain string) Rule { return Rule{Domain: domain, Subdomains: true, Allow: true} }

	tests := []struct {
		name string
		line string
		want []Rule
	}{
		// Adblock Plus.
		{name: "abp", line: "||Ads.Example.com^", want: []Rule{blockAll("ads.example.com")}},
		{name: "abp without separator", line: "||ads.example.com", want: []Rule{blockAll("ads.example.com")}},
		{name: "abp with end anchor", line: "||ads.example.com^|", want: []Rule{blockAll("ads.example.com")}},
		{name: "abp important", line: "||ads.example.com^$important", want: []Rule{blockAll("ads.example.com")}},
		{name: "abp exception", line: "@@||cdn.example.com^", want: []Rule{allowAll("cdn.example.com")}},
		{name: "abp third-party", line: "||ads.example.com^$third-party"},
		{name: "abp badfilter", line: "||ads.example.com^$badfilter"},
		{name: "abp important and badfilter", line: "||ads.example.com^$important,badfilter"},
		{name: "abp path", line: "||example.com^/ads/*"},
		{name: "abp wildcard host", line: "||ads*.example.com^"},
		{name: "abp url pattern", line: "|https://example.com/ads"},
		{name: "abp generic pattern", line: "/banner/*/ad_"},
		{name: "cosmetic", line: "example.com##.ad-banner"},
		{name: "cosmetic exception", line: "example.com#@#.ad-banner"},
		{name: "scriptlet", line: "example.com#%#//scriptlet('abort-on-property-read', 'ads')"},
		{name: "comment", line: "! Title: EasyList"},
		{name: "header", line: "[Adblock Plus 2.0]"},

		// hosts files.
		{name: "hosts", line: "0.0.0.0 ads.example.com", want: []Rule{block("ads.example.com")}},
		{name: "hosts several names", line: "127.0.0.1 a.example.com b.example.com", want: []Rule{block("a.example.com"), block("b.example.com")}},
		{name: "hosts ipv6", line: ":: ads.example.com", want: []Rule{block("ads.example.com")}},
		{name: "hosts comment", line: "0.0.0.0 ads.example.com # tracker", want: []Rule{block("ads.example.com")}},
		{name: "hosts localhost", line: "127.0.0.1 localhost"},
		{name: "hosts local names", line: "::1 ip6-localhost ip6-loopback"},
		{name: "hosts address as name", line: "0.0.0.0 0.0.0.0"},
		{name: "hosts comment line", line: "# 0.0.0.0 ads.example.com"},

		// Domain lists.
		{name: "domain", line: "ads.example.com", want: []Rule{block("ads.example.com")}},
		{name: "domain trailing dot", line: "ads.example.com.", want: []Rule{block("ads.example.com")}},
		{name: "domain leading dot", line: ".ads.example.com", want: []Rule{block("ads.example.com")}},
		{name: "domain with port", line: "ads.example.com:443", want: []Rule{block("ads.example.com")}},
		{name: "domain comment", line: "ads.example.com # tracker", want: []Rule{block("ads.example.com")}},
		{name: "wildcard domain", line: "*.ads.example.com", want: []Rule{blockAll("ads.example.com")}},
		{name: "single label", line: "localhost"},
		{name: "address", line: "192.0.2.1"},
		{name: "invalid characters", line: "ads!.example.com"},
		{name: "blank", line: "   "},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := rules(t, test.line); !slices.Equal(got, test.want) {
				t.Errorf("got %+v, want %+v", got, test.want)
			}
		})
	}
}

func TestRules_ReadError(t *testing.T) {
	r := iotest.ErrReader(errors.New("broken"))

	var gotErr error
	for _, err := range Rules(r) {
		gotErr = err
	}

	if gotErr == nil || gotErr.Error() != "broken" {
		t.Errorf("got error %v, want the read error", gotErr)
	}
}

func TestRules_StopsEarly(t *testing.T) {
	var n int
	for range Rules(strings.NewReader("0.0.0.0 a.example b.example c.example\nd.example\n")) {
		n++
		if n == 2 {
			break
		}
	}

	if n != 2 {
		t.Errorf("got %d rules, want iteration to stop at 2", n)
	}
}

func TestList_Lookup(t *testing.T) {
	var b Builder
	if _, err := b.Add("abp", strings.NewReader(`
||ads.example.com^
||tracker.example^
@@||ok.tracker.example^
`)); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Add("hosts", strings.NewReader("0.0.0.0 exact.example.net\n")); err != nil {
		t.Fatal(err)
	}
	b.Allow("config", "allowed.ads.example.com")
	b.Block("config", "*.blocked.example.org")

	list := b.List()

	tests := []struct {
		name    string
		blocked bool
		rule    string
		source  string
	}{
		{name: "ads.example.com", blocked: true, rule: "ads.example.com", source: "abp"},
		{name: "a.b.ads.example.com.", blocked: true, rule: "ads.example.com", source: "abp"},
		{name: "ADS.Example.COM", blocked: true, rule: "ads.example.com", source: "abp"},
		{name: "example.com"},
		{name: "notads.example.com"},
		{name: "tracker.example", blocked: true, rule: "tracker.example", source: "abp"},
		{name: "ok.tracker.example", rule: "ok.tracker.example", source: "abp"},
		{name: "x.ok.tracker.example", rule: "ok.tracker.example", source: "abp"},
		{name: "exact.example.net", blocked: true, rule: "exact.example.net", source: "hosts"},
		{name: "sub.exact.example.net"},
		{name: "allowed.ads.example.com", rule: "allowed.ads.example.com", source: "config"},
		{name: "blocked.example.org", blocked: true, rule: "blocked.example.org", source: "config"},
		{name: "x.blocked.example.org", blocked: true, rule: "blocked.example.org", source: "config"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			v := list.Lookup(test.name)

			if v.Blocked != test.blocked || v.Rule.Domain != test.rule || v.Source != test.source {
				t.Errorf("got %+v, want blocked=%t by %q from %q", v, test.blocked, test.rule, test.source)
			}

			if test.rule != "" && v.Rule.Allow == test.blocked {
				t.Errorf("got rule %+v, want Allow=%t", v.Rule, !test.blocked)
			}
		})
	}

	if got := list.Len(); got != 4 {
		t.Errorf("got %d block rules, want 4", got)
	}
}

func TestList_Nil(t *testing.T) {
	var list *List
	if v := list.Lookup("ads.example.com"); v.Blocked {
		t.Error("nil list blocked a name")
	}
	if list.Len() != 0 {
		t.Error("nil list has rules")
	}
}

func TestBuilder_KeepsBroaderRule(t *testing.T) {
	var b Builder
	if _, err := b.Add("a", strings.NewReader("||ads.example.com^\n0.0.0.0 ads.example.com\n")); err != nil {
		t.Fatal(err)
	}

	if v := b.List().Lookup("x.ads.example.com"); !v.Blocked {
		t.Error("an exact duplicate narrowed a rule covering subdomains")
	}
}

func BenchmarkList_Lookup(b *testing.B) {
	var builder Builder
	for i := range 100_000 {
		builder.Block("bench", "ads"+strings.Repeat("x", i%7)+".example"+string(rune('a'+i%26))+".com")
	}
	list := builder.List()

	for b.Loop() {
		list.Lookup("a.b.c.www.example.com")
	}
}

func TestBuilder_AddIsAllOrNothing(t *testing.T) {
	var b Builder
	b.Block("good", "ads.example.com")

	// An exception, then a read error: the exception must not apply.
	r := io.MultiReader(strings.NewReader("@@||ads.example.com^\n"), iotest.ErrReader(errors.New("broken")))
	if _, err := b.Add("bad", r); err == nil {
		t.Fatal("expected the read error")
	}

	if v := b.List().Lookup("ads.example.com"); !v.Blocked {
		t.Errorf("got %+v, want the failed source's exception discarded", v)
	}
}
