package cli

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// startDoctorResolver starts a UDP resolver answering CHAOS id.server with
// identity (or REFUSED if empty), and the Firefox canary with canaryRcode.
func startDoctorResolver(t *testing.T, identity string, canaryRcode int) string {
	t.Helper()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		resp := new(dns.Msg).SetReply(req)
		q := req.Question[0]
		switch {
		case q.Qclass == dns.ClassCHAOS && q.Name == "id.server." && identity != "":
			resp.Answer = append(resp.Answer, &dns.TXT{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTXT, Class: dns.ClassCHAOS},
				Txt: []string{identity},
			})
		case q.Qclass == dns.ClassCHAOS:
			resp.Rcode = dns.RcodeRefused
		case q.Name == firefoxCanary:
			resp.Rcode = canaryRcode
		}
		_ = w.WriteMsg(resp)
	})}
	ready := make(chan struct{})
	srv.NotifyStartedFunc = func() { close(ready) }
	go func() { _ = srv.ActivateAndServe() }()
	<-ready
	t.Cleanup(func() { _ = srv.Shutdown() })
	return pc.LocalAddr().String()
}

func writeResolvConf(t *testing.T, lines ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "resolv.conf")
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func testDoctorEnv(resolvConf string) doctorEnv {
	return doctorEnv{resolvConf: resolvConf, goos: "linux", exchange: udpExchange(2 * time.Second)}
}

// findCheck returns the first check whose title contains s.
func findCheck(t *testing.T, checks []doctorCheck, s string) doctorCheck {
	t.Helper()
	for _, c := range checks {
		if strings.Contains(c.Title, s) {
			return c
		}
	}
	t.Fatalf("no check titled %q in %+v", s, checks)
	return doctorCheck{}
}

func TestParseResolvConf(t *testing.T) {
	got, err := parseResolvConf(strings.NewReader("# comment\nsearch lan\nnameserver 192.168.1.1\nnameserver   fe80::1%eth0\noptions edns0\nnameserver\n"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(got, ",") != "192.168.1.1,fe80::1%eth0" {
		t.Errorf("servers = %q", got)
	}
	if resolverAddr("fe80::1%eth0") != "[fe80::1%eth0]:53" || resolverAddr("127.0.0.1:5353") != "127.0.0.1:5353" {
		t.Error("resolverAddr")
	}
}

func TestDoctor_IdentifiesDoh(t *testing.T) {
	addr := startDoctorResolver(t, "doh profile=kids device=tablet client=192.168.1.20", dns.RcodeNameError)
	env := testDoctorEnv(writeResolvConf(t, "nameserver "+addr))

	checks := runDoctor(context.Background(), env)

	id := findCheck(t, checks, "answered by doh")
	if id.Status != doctorOK || id.Identity["profile"] != "kids" || id.Identity["device"] != "tablet" {
		t.Errorf("identity check = %+v", id)
	}
	if !strings.Contains(id.Title, "profile=kids, device=tablet") {
		t.Errorf("title = %q", id.Title)
	}
	if c := findCheck(t, checks, "Firefox will use"); c.Status != doctorOK {
		t.Errorf("canary = %+v", c)
	}
}

func TestDoctor_NotDoh(t *testing.T) {
	addr := startDoctorResolver(t, "", dns.RcodeSuccess)
	env := testDoctorEnv(writeResolvConf(t, "nameserver "+addr))

	checks := runDoctor(context.Background(), env)

	if c := findCheck(t, checks, "is not a doh server"); c.Status != doctorWarn || !strings.Contains(c.Title, "REFUSED") {
		t.Errorf("check = %+v", c)
	}
	if c := findCheck(t, checks, "Firefox may enable"); c.Status != doctorWarn {
		t.Errorf("canary = %+v", c)
	}
}

func TestDoctor_DirectServerAndUnreachable(t *testing.T) {
	addr := startDoctorResolver(t, "doh", dns.RcodeNameError)

	// A resolver nobody answers on: a UDP socket we close at once.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dead := pc.LocalAddr().String()
	pc.Close()

	env := testDoctorEnv(writeResolvConf(t, "nameserver "+dead))
	env.server = addr
	env.exchange = udpExchange(300 * time.Millisecond)

	checks := runDoctor(context.Background(), env)

	if c := findCheck(t, checks, addr+" is answered by doh"); c.Status != doctorOK {
		t.Errorf("direct = %+v", c)
	}
	if c := findCheck(t, checks, dead+" didn't answer"); c.Status != doctorFail {
		t.Errorf("dead = %+v", c)
	}
}

func TestDoctor_DetectsTailscaleAndResolved(t *testing.T) {
	// Answer every exchange with REFUSED, so no network is needed.
	refused := func(_ context.Context, m *dns.Msg, _ string) (*dns.Msg, error) {
		return new(dns.Msg).SetRcode(m, dns.RcodeRefused), nil
	}

	env := testDoctorEnv(writeResolvConf(t, "nameserver 100.100.100.100", "nameserver 127.0.0.53"))
	env.exchange = refused
	checks := runDoctor(context.Background(), env)

	ts := findCheck(t, checks, "Tailscale MagicDNS")
	if ts.Status != doctorWarn || !strings.Contains(ts.Advice, "tailscale set --accept-dns=false") || !strings.Contains(ts.Advice, "Override local DNS") {
		t.Errorf("tailscale = %+v", ts)
	}
	if c := findCheck(t, checks, "systemd-resolved"); !strings.Contains(c.Advice, "resolvectl status") {
		t.Errorf("resolved = %+v", c)
	}

	env.goos = "darwin"
	checks = runDoctor(context.Background(), env)
	if c := findCheck(t, checks, "macOS"); !strings.Contains(c.Advice, "scutil --dns") {
		t.Errorf("darwin = %+v", c)
	}
}

func TestDoctor_ResolvConfProblemsAndAdmin(t *testing.T) {
	env := testDoctorEnv(filepath.Join(t.TempDir(), "missing"))
	env.adminAddr = "127.0.0.1:9090"
	var gotURL string
	env.health = func(_ context.Context, url string) error { gotURL = url; return errors.New("connection refused") }

	checks := runDoctor(context.Background(), env)
	if c := findCheck(t, checks, "can't read"); c.Status != doctorWarn {
		t.Errorf("missing = %+v", c)
	}
	if c := findCheck(t, checks, "admin API not reachable"); c.Status != doctorWarn {
		t.Errorf("admin = %+v", c)
	}
	if gotURL != "http://127.0.0.1:9090/healthz" {
		t.Errorf("health URL = %q", gotURL)
	}

	env = testDoctorEnv(writeResolvConf(t, "search lan"))
	env.adminAddr = "http://127.0.0.1:9090/"
	env.health = func(context.Context, string) error { return nil }
	checks = runDoctor(context.Background(), env)
	findCheck(t, checks, "no nameservers")
	if c := findCheck(t, checks, "admin API reachable"); c.Status != doctorOK {
		t.Errorf("admin = %+v", c)
	}
}

func TestPrintDoctor(t *testing.T) {
	var b strings.Builder
	err := printDoctor(&b, []doctorCheck{
		{Status: doctorOK, Title: "fine"},
		{Status: doctorWarn, Title: "hmm", Advice: "do this"},
		{Status: doctorFail, Title: "broken"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if want := "✓ fine\n! hmm\n  do this\n✗ broken\n"; b.String() != want {
		t.Errorf("output = %q, want %q", b.String(), want)
	}
}
