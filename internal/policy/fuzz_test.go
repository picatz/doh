package policy

import (
	"bytes"
	"testing"
)

// FuzzUnmarshal decodes policy files and API bodies: it must never panic,
// and a policy it accepts must survive a round trip unchanged, and still
// be valid.
func FuzzUnmarshal(f *testing.F) {
	def, err := Marshal(Defaults())
	if err != nil {
		f.Fatal(err)
	}
	f.Add(def)
	f.Add([]byte(`{"version":1,"profiles":[{"id":"default","security":{"rebinding":true,"homograph":true},"safe_search":true}]}`))
	f.Add([]byte(`{"profiles":[{"id":"kids","clients":["192.168.1.0/24","::ffff:10.0.0.1"],"devices":[{"name":"tv","addrs":["fd00::1"]}],"security":{"rebinding":true,"homograph":false},"deny":["*.games.example"],"block_tlds":["zip"],"services":["tiktok"],"time_zone":"America/New_York","schedules":[{"name":"Bedtime","days":["mon"],"start":"21:00","end":"07:00","block_all":true,"allow":["school.example"]}],"rewrites":[{"name":"nas.lan","addrs":["192.168.1.2"]}],"safe_search":false}]}`))
	f.Add([]byte(`{"profiles":[{"id":"a","security":{},"safe_search":false},{"id":"a","security":{},"safe_search":false}]}`))
	f.Add([]byte(`{"profiles":[], "x": 1}`))
	f.Add([]byte(`{"profiles":[{"id":"a","id":"b"}]}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		p, err := Unmarshal(b)
		if err != nil {
			return
		}
		out, err := Marshal(p)
		if err != nil {
			t.Fatalf("an accepted policy doesn't marshal: %v", err)
		}
		p2, err := Unmarshal(out)
		if err != nil {
			t.Fatalf("a marshaled policy doesn't unmarshal: %v\n%s", err, out)
		}
		out2, err := Marshal(p2)
		if err != nil || !bytes.Equal(out, out2) {
			t.Fatalf("round trip changed the policy:\n%s\n%s", out, out2)
		}
	})
}

// FuzzNormalizeDomain checks that normalized domains are normalized: a
// second pass changes nothing.
func FuzzNormalizeDomain(f *testing.F) {
	for _, s := range []string{"Example.COM.", "*.example.com", "*.*.x", "1.2.3.4", "::1", "a..b", "_dmarc.example", " x "} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		d, ok := NormalizeDomain(s)
		if !ok {
			return
		}
		if again, ok := NormalizeDomain(d); !ok || again != d {
			t.Fatalf("NormalizeDomain(%q) = %q, but NormalizeDomain(%q) = %q, %v", s, d, d, again, ok)
		}
	})
}

// FuzzParsePrefix checks that parsed prefixes are masked, unmapped, and
// parse back to themselves.
func FuzzParsePrefix(f *testing.F) {
	for _, s := range []string{"192.168.1.7/24", "::ffff:10.0.0.1/104", "::ffff:10.0.0.1", "fe80::1%eth0", "fd00::/8", "1.2.3.4/33", "x"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		p, err := ParsePrefix(s)
		if err != nil {
			return
		}
		if p != p.Masked() || p.Addr().Is4In6() || p.Addr().Zone() != "" {
			t.Fatalf("ParsePrefix(%q) = %v, not masked and unmapped", s, p)
		}
		if again, err := ParsePrefix(p.String()); err != nil || again != p {
			t.Fatalf("ParsePrefix(%q) = %v, %v", p.String(), again, err)
		}
	})
}

// FuzzParseClock checks schedule times: accepted ones are minutes of a
// day.
func FuzzParseClock(f *testing.F) {
	for _, s := range []string{"21:00", "07:30", "24:00", "7:30", "00:00", "23:59", "1:2:3"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if m, err := ParseClock(s); err == nil && (m < 0 || m >= 24*60) {
			t.Fatalf("ParseClock(%q) = %d", s, m)
		}
	})
}
