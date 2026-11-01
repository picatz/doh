package hostnames

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/miekg/dns"
)

// fake is a source that knows some names, counting lookups.
type fake struct {
	mu    sync.Mutex
	names map[netip.Addr]string
	err   error
	calls atomic.Int32
}

func (f *fake) Lookup(_ context.Context, addr netip.Addr) (string, error) {
	f.calls.Add(1)
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.names[addr], f.err
}

func (f *fake) set(addr netip.Addr, name string) {
	f.mu.Lock()
	f.names[addr] = name
	f.mu.Unlock()
}

var (
	tv    = netip.MustParseAddr("192.168.1.50")
	phone = netip.MustParseAddr("192.168.1.51")
)

func TestDirectory(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		src := &fake{names: map[netip.Addr]string{tv: "Living Room TV.lan"}}
		d := New([]Source{src})
		defer d.Close()

		// The first ask never waits: it starts a lookup.
		if name := d.Name(tv); name != "" {
			t.Fatalf("first Name = %q, want nothing yet", name)
		}
		synctest.Wait()
		if name := d.Name(tv); name != "living-room-tv" {
			t.Fatalf("Name = %q, want the normalized hostname", name)
		}

		// Repeated asks while it's known don't look it up again.
		for range 10 {
			d.Name(tv)
		}
		synctest.Wait()
		if n := src.calls.Load(); n != 1 {
			t.Errorf("%d lookups, want 1", n)
		}

		// Once stale, the old name is still given while it's refreshed.
		src.set(tv, "bedroom-tv")
		time.Sleep(DefaultTTL)
		if name := d.Name(tv); name != "living-room-tv" {
			t.Errorf("stale Name = %q, want the old name until refreshed", name)
		}
		synctest.Wait()
		if name := d.Name(tv); name != "bedroom-tv" {
			t.Errorf("refreshed Name = %q", name)
		}
	})
}

func TestDirectory_UnknownAndFailedLookupsWait(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		src := &fake{names: map[netip.Addr]string{}, err: errors.New("router unreachable")}
		d := New([]Source{src})
		defer d.Close()

		d.Name(phone)
		synctest.Wait()
		d.Name(phone)
		synctest.Wait()
		if n := src.calls.Load(); n != 1 {
			t.Errorf("failed lookups retried %d times before the negative TTL", n-1)
		}

		time.Sleep(DefaultNegativeTTL)
		src.err = nil
		src.set(phone, "pixel")
		d.Name(phone)
		synctest.Wait()
		if name := d.Name(phone); name != "pixel" {
			t.Errorf("Name after the negative TTL = %q", name)
		}
	})
}

func TestDirectory_SourcesInOrder(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		first := &fake{names: map[netip.Addr]string{}}
		second := &fake{names: map[netip.Addr]string{tv: "tv"}}
		d := New([]Source{first, second})
		defer d.Close()

		d.Name(tv)
		synctest.Wait()
		if name := d.Name(tv); name != "tv" || first.calls.Load() != 1 {
			t.Errorf("Name = %q after %d first-source lookups, want the second source's name", name, first.calls.Load())
		}
	})
}

func TestDirectory_OnlyLocalAddresses(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		src := &fake{names: map[netip.Addr]string{}}
		d := New([]Source{src})
		defer d.Close()

		for _, a := range []string{"8.8.8.8", "2001:db8::1", "127.0.0.1", "100.64.0.1"} {
			d.Name(netip.MustParseAddr(a))
		}
		d.Name(netip.Addr{})
		synctest.Wait()
		if n := src.calls.Load(); n != 0 {
			t.Errorf("looked up %d non-local addresses", n)
		}

		for _, a := range []string{"10.0.0.1", "fd00::1", "fe80::1", "::ffff:192.168.1.9"} {
			d.Name(netip.MustParseAddr(a))
		}
		synctest.Wait()
		if n := src.calls.Load(); n != 4 {
			t.Errorf("looked up %d local addresses, want 4", n)
		}
	})
}

func TestDirectory_Bounded(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		src := &fake{names: map[netip.Addr]string{}}
		d := New([]Source{src}, WithMaxEntries(10))
		defer d.Close()

		// A flood of new addresses: some queue, the rest are skipped, and
		// memory stays bounded.
		for i := range 1000 {
			d.Name(netip.AddrFrom4([4]byte{10, 0, byte(i >> 8), byte(i)}))
			if i%50 == 0 {
				synctest.Wait()
			}
		}
		synctest.Wait()
		if n := d.Len(); n > 10 {
			t.Errorf("remembered %d addresses, want at most 10", n)
		}
	})
}

func TestNormalize(t *testing.T) {
	for in, want := range map[string]string{
		"Living Room TV.lan":           "living-room-tv",
		"iPhone":                       "iphone",
		"KENTS-MBP.home.arpa":          "kents-mbp",
		"--weird__name--":              "weird-name",
		"android-1a2b3c":               "android-1a2b3c",
		"Kent’s iPad":                  "kent-s-ipad",
		"":                             "",
		"---":                          "",
		"🙂":                            "",
		strings.Repeat("a", 100):       strings.Repeat("a", 63),
		strings.Repeat("a", 62) + "-b": strings.Repeat("a", 62),
	} {
		if got := Normalize(in); got != want {
			t.Errorf("Normalize(%q) = %q, want %q", in, got, want)
		}
	}
}

// resolver answers PTR queries from a map.
type resolver map[string]string

func (r resolver) Exchange(_ context.Context, q *dns.Msg) (*dns.Msg, error) {
	resp := new(dns.Msg).SetReply(q)
	if name, ok := r[q.Question[0].Name]; ok {
		resp.Answer = append(resp.Answer, &dns.PTR{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypePTR, Class: dns.ClassINET}, Ptr: name})
	} else {
		resp.Rcode = dns.RcodeNameError
	}
	return resp, nil
}

func TestPTR(t *testing.T) {
	p := PTR{Resolver: resolver{
		"50.1.168.192.in-addr.arpa.": "living-room-tv.lan.",
		"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.d.f.ip6.arpa.": "nas.lan.",
	}}

	for addr, want := range map[string]string{
		"192.168.1.50":        "living-room-tv.lan",
		"::ffff:192.168.1.50": "living-room-tv.lan",
		"fd00::1":             "nas.lan",
		"192.168.1.99":        "",
	} {
		if got, err := p.Lookup(t.Context(), netip.MustParseAddr(addr)); err != nil || got != want {
			t.Errorf("Lookup(%s) = %q, %v; want %q", addr, got, err, want)
		}
	}
}

func TestParseLeases_Dnsmasq(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	names, err := ParseLeases(strings.NewReader(`1800003600 aa:bb:cc:dd:ee:01 192.168.1.50 living-room-tv 01:aa:bb:cc:dd:ee:01
1799999999 aa:bb:cc:dd:ee:02 192.168.1.51 expired *
1800003600 aa:bb:cc:dd:ee:03 192.168.1.52 * *
0 aa:bb:cc:dd:ee:04 192.168.1.53 printer *
duid 00:01:00:01:aa:bb:cc:dd:ee:ff:00:11
1800003600 1234 fd00::50 nas 00:01:00:01:22:33
garbage
`), now)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"192.168.1.50": "living-room-tv", "192.168.1.53": "printer", "fd00::50": "nas"}
	if len(names) != len(want) {
		t.Errorf("names = %v, want %v", names, want)
	}
	for a, n := range want {
		if names[netip.MustParseAddr(a)] != n {
			t.Errorf("%s = %q, want %q", a, names[netip.MustParseAddr(a)], n)
		}
	}
}

func TestParseLeases_Kea(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	names, err := ParseLeases(strings.NewReader(`address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,hostname,state,user_context
192.168.1.50,aa:bb:cc:dd:ee:01,,3600,1800003600,1,0,0,living-room-tv,0,
192.168.1.51,aa:bb:cc:dd:ee:02,,3600,1799999999,1,0,0,expired,0,
192.168.1.52,aa:bb:cc:dd:ee:03,,3600,1800003600,1,0,0,,0,
192.168.1.53,aa:bb:cc:dd:ee:04,,3600,1800003600,1,0,0,phone,0,
192.168.1.53,aa:bb:cc:dd:ee:04,,3600,1800003600,1,0,0,phone,2,
192.168.1.54,"broken
`), now)
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 1 || names[tv] != "living-room-tv" {
		t.Errorf("names = %v, want only the living room TV (expired, nameless, and reclaimed leases dropped)", names)
	}
}

func TestLeases_RereadsWhenChanged(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dnsmasq.leases")
	write := func(content string, mod time.Time) {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(path, mod, mod); err != nil {
			t.Fatal(err)
		}
	}
	future := time.Now().Add(time.Hour).Unix()
	write(strconv.FormatInt(future, 10)+" aa:bb 192.168.1.50 tv *\n", time.Now().Add(-time.Hour))

	l := &Leases{Path: path}
	if name, err := l.Lookup(t.Context(), tv); err != nil || name != "tv" {
		t.Fatalf("Lookup = %q, %v", name, err)
	}

	write(strconv.FormatInt(future, 10)+" aa:bb 192.168.1.50 renamed-tv *\n", time.Now())
	l.checked = time.Time{} // skip the recheck interval
	if name, _ := l.Lookup(t.Context(), tv); name != "renamed-tv" {
		t.Errorf("after the file changed: %q", name)
	}

	if _, err := (&Leases{Path: filepath.Join(t.TempDir(), "missing")}).Lookup(t.Context(), tv); err == nil {
		t.Error("a missing lease file wasn't an error")
	}
}

func TestParseRoutes(t *testing.T) {
	table := `Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	Mask		MTU	Window	IRTT
eth0	000200C0	00000000	0001	0	0	0	00FFFFFF	0	0	0
eth0	00000000	0101A8C0	0003	0	0	0	00000000	0	0	0
`
	gw, ok := parseRoutes(strings.NewReader(table))
	if !ok || gw != netip.MustParseAddr("192.168.1.1") {
		t.Errorf("parseRoutes = %v, %v; want 192.168.1.1", gw, ok)
	}
	if _, ok := parseRoutes(strings.NewReader("Iface\tDestination\tGateway\neth0\t000200C0\t00000000\n")); ok {
		t.Error("found a gateway in a table without a default route")
	}
}
