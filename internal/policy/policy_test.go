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
		{"trailing hyphen", []Profile{{ID: "kids-"}}},
		{"separator in id", []Profile{{ID: "a--b"}}},
		{"separator in device", []Profile{{ID: "a", Devices: []Device{{Name: "x--y"}}}}},
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

func TestValidate_Tenants(t *testing.T) {
	smiths := Tenant{ID: "smiths", Name: "The Smiths", Networks: []string{"192.168.10.0/24"}}
	jones := Tenant{ID: "jones", Networks: []string{"192.168.20.0/24", "fd20::/64"}, CustomLists: true}

	valid := &Policy{
		Tenants: []Tenant{smiths, jones},
		Profiles: []Profile{
			{ID: "default"},
			{ID: "smiths-kids", Tenant: "smiths", Clients: []string{"192.168.10.0/26"}, Lists: []string{"threat-intel", "default"}},
			{ID: "jones", Tenant: "jones", Devices: []Device{{Name: "tv", Addrs: []string{"192.168.20.9", "fd20::9"}}}, Lists: []string{"mine=https://lists.example/block.txt"}},
			{ID: "roaming", Tenant: "smiths"}, // DoH and host names only
		},
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid tenant policy: %v", err)
	}

	for _, tt := range []struct {
		desc     string
		tenants  []Tenant
		profiles []Profile
		want     string
	}{
		{"unknown tenant", nil, []Profile{{ID: "x", Tenant: "nobody"}}, `no tenant "nobody"`},
		{"bad tenant id", []Tenant{{ID: "Bad"}}, nil, "id must be"},
		{"duplicate tenant", []Tenant{{ID: "a"}, {ID: "a"}}, nil, "duplicate id"},
		{"overlapping networks", []Tenant{{ID: "a", Networks: []string{"10.0.0.0/8"}}, {ID: "b", Networks: []string{"10.1.0.0/16"}}}, nil, "overlaps"},
		{"bad network", []Tenant{{ID: "a", Networks: []string{"10.0.0.0/33"}}}, nil, "invalid prefix"},
		{"client outside networks", []Tenant{smiths}, []Profile{{ID: "x", Tenant: "smiths", Clients: []string{"0.0.0.0/0"}}}, "outside tenant"},
		{"wider than its network", []Tenant{smiths}, []Profile{{ID: "x", Tenant: "smiths", Clients: []string{"192.168.0.0/16"}}}, "outside tenant"},
		{"device outside networks", []Tenant{smiths}, []Profile{{ID: "x", Tenant: "smiths", Devices: []Device{{Name: "d", Addrs: []string{"10.9.9.9"}}}}}, "outside tenant"},
		{"no networks at all", []Tenant{{ID: "a"}}, []Profile{{ID: "x", Tenant: "a", Clients: []string{"192.168.1.5"}}}, "outside tenant"},
		{"custom list without permission", []Tenant{smiths}, []Profile{{ID: "x", Tenant: "smiths", Lists: []string{"https://lists.example/x.txt"}}}, "only use preset"},
		{"file list", []Tenant{jones}, []Profile{{ID: "x", Tenant: "jones", Lists: []string{"/etc/shadow"}}}, "HTTPS"},
		{"named file list", []Tenant{jones}, []Profile{{ID: "x", Tenant: "jones", Lists: []string{"threat-intel=/etc/passwd"}}}, "HTTPS"},
		{"plain http list", []Tenant{jones}, []Profile{{ID: "x", Tenant: "jones", Lists: []string{"http://169.254.169.254/latest"}}}, "HTTPS"},
		{"tenant default profile", []Tenant{smiths}, []Profile{{ID: "default", Tenant: "smiths"}}, "belongs to the server's operator"},
		{"over the profile limit", []Tenant{{ID: "a", MaxProfiles: 1}}, []Profile{{ID: "x", Tenant: "a"}, {ID: "y", Tenant: "a"}}, "more than its limit of 1"},
		{"negative limit", []Tenant{{ID: "a", MaxProfiles: -1}}, nil, "must not be negative"},
	} {
		err := (&Policy{Tenants: tt.tenants, Profiles: tt.profiles}).Validate()
		if err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%s: Validate = %v, want an error containing %q", tt.desc, err, tt.want)
		}
	}

	// The operator's own profiles aren't bound by tenants' rules.
	operator := &Policy{Tenants: []Tenant{smiths}, Profiles: []Profile{{ID: "lab", Clients: []string{"10.0.0.0/8"}, Lists: []string{"/etc/doh/block.txt"}}}}
	if err := operator.Validate(); err != nil {
		t.Errorf("operator profile: %v", err)
	}

	// A tenant may not take addresses another profile already claims.
	clash := &Policy{Tenants: []Tenant{smiths}, Profiles: []Profile{
		{ID: "lab", Clients: []string{"192.168.10.5"}},
		{ID: "x", Tenant: "smiths", Clients: []string{"192.168.10.5"}},
	}}
	if err := clash.Validate(); err == nil || !strings.Contains(err.Error(), "also claimed") {
		t.Errorf("clashing claim: %v", err)
	}
}

func TestValidate_ServicesAndSchedules(t *testing.T) {
	valid := &Policy{Profiles: []Profile{{
		ID:       "kids",
		Services: []string{"tiktok", "roblox"},
		TimeZone: "America/New_York",
		Schedules: []Schedule{
			{Name: "Bedtime", Start: "21:00", End: "07:00", BlockAll: true, Allow: []string{"school.example"}},
			{Name: "Homework", Days: []string{"mon", "tue", "wed", "thu", "fri"}, Start: "15:00", End: "18:00", Services: []string{"youtube"}, Lists: []string{"social"}},
		},
	}}}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid schedules: %v", err)
	}

	for _, tt := range []struct {
		desc    string
		profile Profile
		want    string
	}{
		{"unknown service", Profile{ID: "a", Services: []string{"myspace"}}, `unknown service "myspace"`},
		{"bad time zone", Profile{ID: "a", TimeZone: "Mars/Olympus"}, "IANA time zone"},
		{"local time zone", Profile{ID: "a", TimeZone: "Local"}, "IANA time zone"},
		{"unnamed", Profile{ID: "a", Schedules: []Schedule{{Start: "1:00", End: "2:00", BlockAll: true}}}, "name it"},
		{"bad day", Profile{ID: "a", Schedules: []Schedule{{Name: "x", Days: []string{"monday"}, Start: "01:00", End: "02:00", BlockAll: true}}}, `day "monday"`},
		{"bad start", Profile{ID: "a", Schedules: []Schedule{{Name: "x", Start: "9pm", End: "02:00", BlockAll: true}}}, "HH:MM"},
		{"out of range", Profile{ID: "a", Schedules: []Schedule{{Name: "x", Start: "24:30", End: "02:00", BlockAll: true}}}, "HH:MM"},
		{"blocks nothing", Profile{ID: "a", Schedules: []Schedule{{Name: "x", Start: "09:00", End: "10:00"}}}, "blocks nothing"},
		{"bad scheduled service", Profile{ID: "a", Schedules: []Schedule{{Name: "x", Start: "09:00", End: "10:00", Services: []string{"nope"}}}}, "unknown service"},
		{"bad allow", Profile{ID: "a", Schedules: []Schedule{{Name: "x", Start: "09:00", End: "10:00", BlockAll: true, Allow: []string{"not a domain"}}}}, "invalid domain"},
	} {
		err := (&Policy{Profiles: []Profile{tt.profile}}).Validate()
		if err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%s: Validate = %v, want an error containing %q", tt.desc, err, tt.want)
		}
	}

	// A tenant's scheduled lists follow its list rules too.
	tenanted := &Policy{
		Tenants: []Tenant{{ID: "smiths"}},
		Profiles: []Profile{{ID: "a", Tenant: "smiths", Schedules: []Schedule{
			{Name: "x", Start: "09:00", End: "10:00", Lists: []string{"/etc/shadow"}},
		}}},
	}
	if err := tenanted.Validate(); err == nil || !strings.Contains(err.Error(), "preset lists") {
		t.Errorf("tenant schedule with a file list: %v", err)
	}
}

func TestParseClock(t *testing.T) {
	for in, want := range map[string]int{"00:00": 0, "07:30": 450, "23:59": 1439} {
		if got, err := ParseClock(in); err != nil || got != want {
			t.Errorf("ParseClock(%q) = %d, %v; want %d", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "7:30", "07:3", "24:00", "12:60", "noon", "07:30:00"} {
		if _, err := ParseClock(bad); err == nil {
			t.Errorf("ParseClock(%q) succeeded", bad)
		}
	}
}
