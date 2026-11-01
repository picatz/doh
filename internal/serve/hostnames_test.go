package serve

import (
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/picatz/doh/internal/policy"
	"github.com/picatz/doh/internal/querylog"
)

// eventually waits for cond, which background work makes true.
func eventually(t *testing.T, cond func() bool) bool {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if cond() {
			return true
		}
	}
	return false
}

func TestServer_LearnsDeviceNames(t *testing.T) {
	router, _ := startZone(t, map[string]string{
		"50.1.168.192.in-addr.arpa. PTR": "50.1.168.192.in-addr.arpa. 60 IN PTR Living-Room-TV.lan.",
		"9.0.0.10.in-addr.arpa. PTR":     "9.0.0.10.in-addr.arpa. 60 IN PTR kids-tablet.lan.",
	})
	up, _ := startZone(t, nil)

	for _, tt := range []struct {
		desc      string
		configure func(*Config)
		client    string
		want      string
	}{
		{"through a forward zone", func(c *Config) { c.Forward = map[string][]string{"168.192.in-addr.arpa": {router}} }, "192.168.1.50", "living-room-tv"},
		{"from a configured resolver", func(c *Config) { c.DeviceNames.Resolvers = []string{router} }, "10.0.0.9", "kids-tablet"},
	} {
		t.Run(tt.desc, func(t *testing.T) {
			s, _ := newPolicyServer(t, up, &policy.Policy{Profiles: []policy.Profile{{ID: "default"}}}, tt.configure)
			client := netip.MustParseAddr(tt.client)

			ask := func() {
				s.answerDNS(t.Context(), "udp", client, new(dns.Msg).SetQuestion("example.com.", dns.TypeA))
			}
			ask()
			if !eventually(t, func() bool { return s.hostnames.Name(client) != "" }) {
				t.Fatal("the device's name was never learned")
			}
			ask()

			page := s.qlog.Query(querylog.Filter{Client: tt.client, Limit: 1})
			if len(page.Entries) != 1 || page.Entries[0].Hostname != tt.want || page.Entries[0].Device != "" {
				t.Errorf("logged %+v, want hostname %q", page.Entries, tt.want)
			}
			if stats := s.qlog.Stats(querylog.Filter{}, 5); len(stats.TopClients) == 0 || stats.TopClients[0].Name != tt.want {
				t.Errorf("top clients = %+v, want %q", stats.TopClients, tt.want)
			}
		})
	}
}

func TestServer_DeviceNamesAreLabelsOnly(t *testing.T) {
	// A device calls itself "kids-tablet", the name of a configured
	// device in a stricter profile. Its claim changes nothing but the
	// label in the log.
	router, _ := startZone(t, map[string]string{
		"66.1.168.192.in-addr.arpa. PTR": "66.1.168.192.in-addr.arpa. 60 IN PTR kids-tablet.lan.",
	})
	up, _ := startZone(t, nil)
	s, _ := newPolicyServer(t, up, &policy.Policy{Profiles: []policy.Profile{
		{ID: "default"},
		{ID: "kids", Deny: []string{"games.example"}, Devices: []policy.Device{{Name: "kids-tablet", Addrs: []string{"192.168.1.20"}}}},
	}}, func(c *Config) { c.DeviceNames.Resolvers = []string{router} })

	impostor := netip.MustParseAddr("192.168.1.66")
	ask := func() *dns.Msg {
		return s.answerDNS(t.Context(), "udp", impostor, new(dns.Msg).SetQuestion("games.example.", dns.TypeA))
	}
	ask()
	if !eventually(t, func() bool { return s.hostnames.Name(impostor) != "" }) {
		t.Fatal("name never learned")
	}

	if resp := ask(); resp.Rcode != dns.RcodeSuccess {
		t.Errorf("the claimed name changed the answer: %s", dns.RcodeToString[resp.Rcode])
	}
	page := s.qlog.Query(querylog.Filter{Client: "192.168.1.66", Limit: 1})
	if e := page.Entries[0]; e.Profile != "default" || e.Device != "" || e.Hostname != "kids-tablet" {
		t.Errorf("logged %+v, want the default profile, labelled with the claimed hostname only", e)
	}
}

func TestServer_DeviceNamesDisabled(t *testing.T) {
	up, _ := startZone(t, nil)
	s, _ := newPolicyServer(t, up, nil, func(c *Config) { c.DeviceNames.Disabled = true })
	if s.hostnames != nil || s.hostnames.Name(netip.MustParseAddr("192.168.1.5")) != "" {
		t.Error("device names learned while disabled")
	}
}
