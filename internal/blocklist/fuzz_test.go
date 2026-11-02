package blocklist

import (
	"strings"
	"testing"
)

// FuzzRules parses list content in every supported format: hosts files,
// Adblock Plus domain rules, and plain domain lists. It must never
// panic; every rule's domain must be normalized; and a list built from
// the content must block every block rule's domain unless an exception
// covers it.
func FuzzRules(f *testing.F) {
	for _, s := range []string{
		"0.0.0.0 ads.example.com tracker.example # comment\n127.0.0.1 localhost\n",
		"||ads.example.com^\n@@||ok.example.com^$important\n||x.example^$third-party\n! comment\n[Adblock Plus 2.0]\n",
		"example.com\n*.wild.example\nnodots\nEXAMPLE.ORG.\nexample.net:443\n",
		"example.com##.banner\n||a.example/path^\n:: ip6.example\n",
		strings.Repeat("a.", 130) + "com\n",
		"\x00\xff\n\r\n\t\n",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, content string) {
		var rules []Rule
		for rule, err := range Rules(strings.NewReader(content)) {
			if err != nil {
				return // a line over the scanner's limit
			}
			rules = append(rules, rule)
			if got, ok := normalize(rule.Domain); !ok || got != rule.Domain {
				t.Fatalf("rule domain %q isn't normalized (%q, %v)", rule.Domain, got, ok)
			}
			if rule.Allow && !rule.Subdomains {
				t.Fatalf("an exception that doesn't cover subdomains: %+v", rule)
			}
		}

		var b Builder
		if _, err := b.Add("fuzz", strings.NewReader(content)); err != nil {
			t.Fatal(err)
		}
		l := b.List()
		for _, rule := range rules {
			if v := l.Lookup(rule.Domain); !rule.Allow && !v.Blocked && !v.Rule.Allow {
				t.Fatalf("%q was parsed as a block rule but isn't blocked: %+v", rule.Domain, v)
			}
		}
	})
}

// FuzzParseSource parses blocklist sources as flags and policies give
// them: it must never panic, and what it accepts must have a name and a
// location.
func FuzzParseSource(f *testing.F) {
	for _, s := range []string{"default", "oisd-small", "ads=https://example.com/list.txt", "/etc/hosts", "x=", "=y", "http://", " "} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		src, err := ParseSource(s)
		if err != nil {
			return
		}
		if src.Name == "" || src.Location == "" {
			t.Fatalf("ParseSource(%q) = %+v", s, src)
		}
	})
}
