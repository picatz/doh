package policy

import (
	"net/netip"
	"strings"
	"testing"
)

func TestDefaults_Valid(t *testing.T) {
	p := Defaults()
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	if p.Profile(DefaultProfile) == nil {
		t.Fatal("no default profile")
	}
}

func TestMarshalRoundTrip(t *testing.T) {
	p := &Policy{Version: Version, Profiles: []Profile{{
		ID:       "kids",
		Name:     "Kids",
		Clients:  []string{"192.168.1.0/24"},
		Devices:  []Device{{Name: "tablet", Addrs: []string{"192.168.1.20"}}},
		Security: Security{Rebinding: true, NewlyRegistered: true, NewlyRegisteredDays: 14},
		Lists:    []string{"threat-intel"},
		Rewrites: []Rewrite{{Name: "nas.home.arpa", Addrs: []string{"192.168.1.5"}}},
	}}}

	b, err := Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Unmarshal(b)
	if err != nil {
		t.Fatal(err)
	}
	if got.ETag() != p.ETag() {
		t.Errorf("round trip changed the policy:\n%s", b)
	}
	if strings.Contains(string(b), `"newly_registered_days": 0`) {
		t.Error("zero values leak into the file")
	}

	// Entity tags change with the content.
	p.Profiles[0].SafeSearch = true
	if got.ETag() == p.ETag() {
		t.Error("ETag didn't change")
	}
}

func TestUnmarshal_Rejects(t *testing.T) {
	for _, tt := range []struct{ desc, json string }{
		{"unknown field", `{"profiles":[{"id":"a","securty":{}}]}`},
		{"duplicate key", `{"profiles":[{"id":"a","id":"b"}]}`},
		{"trailing data", `{"profiles":[]} {}`},
		{"future version", `{"version":2,"profiles":[]}`},
		{"not json", `profiles: []`},
	} {
		if _, err := Unmarshal([]byte(tt.json)); err == nil {
			t.Errorf("%s: Unmarshal succeeded", tt.desc)
		}
	}
}

func TestValidate(t *testing.T) {
	for _, tt := range []struct {
		desc     string
		profiles []Profile
	}{
		{"empty id", []Profile{{}}},
		{"upper-case id", []Profile{{ID: "Kids"}}},
		{"id with slash", []Profile{{ID: "a/b"}}},
		{"long id", []Profile{{ID: strings.Repeat("a", 64)}}},
		{"duplicate id", []Profile{{ID: "a"}, {ID: "a"}}},
		{"bad client", []Profile{{ID: "a", Clients: []string{"300.1.1.1"}}}},
		{"bad prefix", []Profile{{ID: "a", Clients: []string{"10.0.0.0/33"}}}},
		{"address claimed twice", []Profile{{ID: "a", Clients: []string{"10.0.0.0/8"}}, {ID: "b", Clients: []string{"10.1.2.3/8"}}}},
		{"device and client clash", []Profile{{ID: "a", Clients: []string{"10.0.0.1"}, Devices: []Device{{Name: "d", Addrs: []string{"10.0.0.1"}}}}}},
		{"bad device name", []Profile{{ID: "a", Devices: []Device{{Name: "Living Room"}}}}},
		{"duplicate device", []Profile{{ID: "a", Devices: []Device{{Name: "d"}, {Name: "d"}}}}},
		{"unknown preset", []Profile{{ID: "a", Lists: []string{"no-such-list"}}}},
		{"duplicate list", []Profile{{ID: "a", Lists: []string{"threat-intel", "threat-intel"}}}},
		{"bad allow", []Profile{{ID: "a", Allow: []string{"not a domain"}}}},
		{"ip as deny", []Profile{{ID: "a", Deny: []string{"192.0.2.1"}}}},
		{"multi-label tld", []Profile{{ID: "a", BlockTLDs: []string{"co.uk"}}}},
		{"rewrite without addrs", []Profile{{ID: "a", Rewrites: []Rewrite{{Name: "nas.lan"}}}}},
		{"rewrite bad addr", []Profile{{ID: "a", Rewrites: []Rewrite{{Name: "nas.lan", Addrs: []string{"nas"}}}}}},
		{"block response", []Profile{{ID: "a", BlockResponse: "refused"}}},
		{"days", []Profile{{ID: "a", Security: Security{NewlyRegisteredDays: 400}}}},
	} {
		if err := (&Policy{Profiles: tt.profiles}).Validate(); err == nil {
			t.Errorf("%s: Validate succeeded", tt.desc)
		}
	}

	// Every problem is reported at once.
	err := (&Policy{Profiles: []Profile{{ID: "Bad"}, {ID: "b", BlockResponse: "x"}}}).Validate()
	if err == nil || strings.Count(err.Error(), "\n") != 1 {
		t.Errorf("Validate = %v, want two problems", err)
	}
}

func TestParsePrefix(t *testing.T) {
	for in, want := range map[string]string{
		"192.168.1.5":         "192.168.1.5/32",
		"192.168.1.5/24":      "192.168.1.0/24",
		"::ffff:192.168.1.5":  "192.168.1.5/32",
		"::ffff:10.0.0.0/104": "10.0.0.0/8",
		"fd00::1":             "fd00::1/128",
		"fe80::1%eth0":        "fe80::1/128",
		"2001:db8::/32":       "2001:db8::/32",
	} {
		got, err := ParsePrefix(in)
		if err != nil || got != netip.MustParsePrefix(want) {
			t.Errorf("ParsePrefix(%q) = %v, %v; want %s", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "nas", "1.2.3.4/40", "1.2.3"} {
		if _, err := ParsePrefix(bad); err == nil {
			t.Errorf("ParsePrefix(%q) succeeded", bad)
		}
	}
}

func TestNormalizeDomain(t *testing.T) {
	for in, want := range map[string]string{
		"Example.COM.":   "example.com",
		"*.ads.example":  "ads.example",
		" gef.sh ":       "gef.sh",
		"_dmarc.example": "_dmarc.example",
	} {
		if got, ok := NormalizeDomain(in); !ok || got != want {
			t.Errorf("NormalizeDomain(%q) = %q, %v", in, got, ok)
		}
	}
	for _, bad := range []string{"", ".", "a..b", "1.2.3.4", "has space.com", "ünicode.de", strings.Repeat("a", 64) + ".com"} {
		if _, ok := NormalizeDomain(bad); ok {
			t.Errorf("NormalizeDomain(%q) succeeded", bad)
		}
	}
}

func TestClone_Independent(t *testing.T) {
	p := Defaults()
	c := p.Clone()
	c.Profiles[0].Lists[0] = "changed"
	if p.Profiles[0].Lists[0] == "changed" {
		t.Error("Clone shares memory with the original")
	}
}
