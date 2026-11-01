package serve

import (
	"context"
	"crypto/tls"
	"net"
	"testing"

	"github.com/miekg/dns"
	"github.com/picatz/doh/internal/doq"
	"github.com/picatz/doh/internal/querylog"
)

// startDoQ serves DoQ for s on a loopback port, returning its address.
func startDoQ(t *testing.T, s *Server) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.ServeDoQ(ctx, pc) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	})
	return pc.LocalAddr().String()
}

func TestServer_DoQSelectsProfileByServerName(t *testing.T) {
	s := newDoTServer(t, hostnamePolicy())
	addr := startDoQ(t, s)

	for _, tt := range []struct {
		serverName string
		rcode      int
	}{
		{"kids." + testHostname, dns.RcodeNameError},
		{"tablet--kids." + testHostname, dns.RcodeNameError},
		{testHostname, dns.RcodeSuccess},
		{"nobody." + testHostname, dns.RcodeRefused},
	} {
		t.Run(tt.serverName, func(t *testing.T) {
			c := &doq.Client{Addr: addr, TLSConfig: &tls.Config{ServerName: tt.serverName, InsecureSkipVerify: true}}
			defer c.Close()

			resp, err := c.Exchange(t.Context(), new(dns.Msg).SetQuestion("games.example.", dns.TypeA))
			if err != nil {
				t.Fatal(err)
			}
			if resp.Rcode != tt.rcode {
				t.Errorf("games.example: %s, want %s", dns.RcodeToString[resp.Rcode], dns.RcodeToString[tt.rcode])
			}
		})
	}

	page := s.qlog.Query(querylog.Filter{Device: "tablet"})
	if len(page.Entries) != 1 || page.Entries[0].Transport != "doq" || page.Entries[0].Profile != "kids" {
		t.Errorf("logged %+v, want a doq query from kids/tablet", page.Entries)
	}
}

func TestConfig_ValidateDoQ(t *testing.T) {
	for _, c := range []Config{
		{Plaintext: true, DoQListen: ":853"}, // needs a certificate
		{DNSListen: ":53", DoQListen: "853"},
	} {
		if err := c.Validate(); err == nil {
			t.Errorf("Validate(%+v) succeeded", c)
		}
	}
}
