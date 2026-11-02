package hostnames

import (
	"strings"
	"testing"
	"time"

	"github.com/picatz/doh/internal/policy"
)

// FuzzParseLeases parses dnsmasq and Kea lease files, which devices on
// the network fill with names they choose: it must never panic, and
// every address it returns is unmapped.
func FuzzParseLeases(f *testing.F) {
	f.Add("1800000000 aa:bb:cc:dd:ee:ff 192.168.1.20 living-room-tv 01:aa\n0 aa:bb 192.168.1.21 * *\nduid 00:01\n")
	f.Add("address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,hostname,state\n192.168.1.30,aa,,3600,1800000000,1,0,0,phone.lan,0\n::ffff:10.0.0.1,,,,0,,,,x,1\n")
	f.Add("address,\n\"unterminated")
	f.Add("x y ::ffff:192.0.2.1 name\n")
	now := time.Unix(1_700_000_000, 0)
	f.Fuzz(func(t *testing.T, content string) {
		names, err := ParseLeases(strings.NewReader(content), now)
		if err != nil {
			return
		}
		for addr := range names {
			if addr.Is4In6() || !addr.IsValid() {
				t.Fatalf("address %v isn't unmapped", addr)
			}
		}
	})
}

// FuzzNormalize turns hostnames devices choose into device names: the
// result must be empty or a valid device name, and normalizing it again
// must change nothing.
func FuzzNormalize(f *testing.F) {
	for _, s := range []string{"Living Room TV.lan", "  --a--b--  ", "iPhone (2)", "ÄÖÜ-ß", strings.Repeat("x", 100), "", ".", "a_b"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, hostname string) {
		name := Normalize(hostname)
		if name == "" {
			return
		}
		if !policy.ValidID(name) {
			t.Fatalf("Normalize(%q) = %q, not a valid device name", hostname, name)
		}
		if again := Normalize(name); again != name {
			t.Fatalf("Normalize(%q) = %q, then %q", hostname, name, again)
		}
		for _, c := range []byte(name) {
			if !('a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '-') {
				t.Fatalf("Normalize(%q) = %q, with %q", hostname, name, c)
			}
		}
		if name[0] == '-' || name[len(name)-1] == '-' {
			t.Fatalf("Normalize(%q) = %q, with a hyphen at an end", hostname, name)
		}
	})
}

// FuzzParseRoutes parses /proc/net/route: it must never panic, and a
// gateway it finds is a specified IPv4 address.
func FuzzParseRoutes(f *testing.F) {
	f.Add("Iface\tDestination\tGateway\tFlags\neth0\t00000000\t0101A8C0\t0003\n")
	f.Add("Iface\tDestination\tGateway\neth0\t00000000\t00000000\neth1\t00000000\tzz\n")
	f.Fuzz(func(t *testing.T, table string) {
		gw, ok := parseRoutes(strings.NewReader(table))
		if ok && (!gw.Is4() || gw.IsUnspecified()) {
			t.Fatalf("gateway %v", gw)
		}
	})
}
