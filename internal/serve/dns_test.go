package serve

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// startLargeResolver starts a TCP DNS server answering A queries with n
// records, so responses exceed 512 bytes for large n.
func startLargeResolver(t *testing.T, n int) string {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	server := &dns.Server{Listener: ln, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		resp := new(dns.Msg).SetReply(req)
		for i := range n {
			resp.Answer = append(resp.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   net.IPv4(192, 0, 2, byte(i)),
			})
		}
		_ = w.WriteMsg(resp)
	})}

	ready := make(chan struct{})
	server.NotifyStartedFunc = func() { close(ready) }
	go func() { _ = server.ActivateAndServe() }()
	<-ready
	t.Cleanup(func() { _ = server.Shutdown() })

	return "tcp://" + ln.Addr().String()
}

// startDNS serves plain DNS for s on local UDP and TCP ports until the test
// ends, returning their addresses.
func startDNS(t *testing.T, s *Server) (udpAddr, tcpAddr string) {
	t.Helper()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.ServeDNS(ctx, pc, ln) }()

	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("serve dns: %v", err)
		}
	})

	// Wait until the TCP listener answers, since ServeDNS starts serving
	// asynchronously.
	for range 100 {
		if conn, err := net.Dial("tcp", ln.Addr().String()); err == nil {
			conn.Close()
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	return pc.LocalAddr().String(), ln.Addr().String()
}

func exchange(t *testing.T, network, addr string, req *dns.Msg) *dns.Msg {
	t.Helper()

	client := &dns.Client{Net: network, Timeout: 5 * time.Second, UDPSize: 65535}

	resp, _, err := client.Exchange(req, addr)
	if err != nil {
		t.Fatal(err)
	}

	if resp.Id != req.Id {
		t.Errorf("got response ID %d, want %d", resp.Id, req.Id)
	}

	return resp
}

func TestServeDNS(t *testing.T) {
	s, err := New(Config{Plaintext: true, Upstreams: []string{startResolver(t)}}, testLogger(t))
	if err != nil {
		t.Fatal(err)
	}

	udpAddr, tcpAddr := startDNS(t, s)

	for network, addr := range map[string]string{"udp": udpAddr, "tcp": tcpAddr} {
		t.Run(network, func(t *testing.T) {
			resp := exchange(t, network, addr, new(dns.Msg).SetQuestion("example.com.", dns.TypeA))

			if len(resp.Answer) != 1 || resp.Answer[0].(*dns.A).A.String() != "192.0.2.1" {
				t.Errorf("got answers %v, want 192.0.2.1", resp.Answer)
			}
		})
	}
}

func TestServeDNS_UDPTruncation(t *testing.T) {
	const records = 60 // about 1 KiB of answers

	s, err := New(Config{Plaintext: true, Upstreams: []string{startLargeResolver(t, records)}}, testLogger(t))
	if err != nil {
		t.Fatal(err)
	}

	udpAddr, tcpAddr := startDNS(t, s)

	tests := []struct {
		name      string
		network   string
		addr      string
		edns      uint16
		truncated bool
		maxSize   int
	}{
		{name: "udp without edns", network: "udp", addr: udpAddr, truncated: true, maxSize: dns.MinMsgSize},
		{name: "udp with small edns buffer", network: "udp", addr: udpAddr, edns: 600, truncated: true, maxSize: 600},
		{name: "udp with large edns buffer", network: "udp", addr: udpAddr, edns: 4096, maxSize: 4096},
		{name: "tcp", network: "tcp", addr: tcpAddr, maxSize: dns.MaxMsgSize},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req := new(dns.Msg).SetQuestion("example.com.", dns.TypeA)
			if test.edns != 0 {
				req.SetEdns0(test.edns, false)
			}

			resp := exchange(t, test.network, test.addr, req)

			if resp.Truncated != test.truncated {
				t.Errorf("got TC=%t, want %t", resp.Truncated, test.truncated)
			}

			// Measure the wire size, which uses name compression.
			resp.Compress = true
			if size := resp.Len(); size > test.maxSize {
				t.Errorf("got %d byte response, want at most %d", size, test.maxSize)
			}

			if !test.truncated && len(resp.Answer) != records {
				t.Errorf("got %d answers, want %d", len(resp.Answer), records)
			}
		})
	}
}

func TestServeDNS_UpstreamFailureIsServfail(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dead := "tcp://" + ln.Addr().String()
	ln.Close()

	s, err := New(Config{Plaintext: true, Upstreams: []string{dead}, Timeout: Duration(time.Second)}, testLogger(t))
	if err != nil {
		t.Fatal(err)
	}

	udpAddr, _ := startDNS(t, s)

	resp := exchange(t, "udp", udpAddr, new(dns.Msg).SetQuestion("example.com.", dns.TypeA))
	if resp.Rcode != dns.RcodeServerFailure {
		t.Errorf("got rcode %s, want SERVFAIL", dns.RcodeToString[resp.Rcode])
	}
}

func TestServer_AnswerDNS_RejectsMalformedQueries(t *testing.T) {
	s, err := New(Config{Plaintext: true, Upstreams: []string{startResolver(t)}}, testLogger(t))
	if err != nil {
		t.Fatal(err)
	}

	query := func(modify func(*dns.Msg)) *dns.Msg {
		m := new(dns.Msg).SetQuestion("example.com.", dns.TypeA)
		modify(m)
		return m
	}

	tests := []struct {
		name string
		req  *dns.Msg
		want int
	}{
		{name: "standard query", req: query(func(*dns.Msg) {}), want: dns.RcodeSuccess},
		{name: "response", req: query(func(m *dns.Msg) { m.Response = true }), want: dns.RcodeFormatError},
		{name: "no question", req: query(func(m *dns.Msg) { m.Question = nil }), want: dns.RcodeFormatError},
		{name: "two questions", req: query(func(m *dns.Msg) { m.Question = append(m.Question, m.Question[0]) }), want: dns.RcodeFormatError},
		{name: "notify opcode", req: query(func(m *dns.Msg) { m.Opcode = dns.OpcodeNotify }), want: dns.RcodeNotImplemented},
		{name: "update opcode", req: query(func(m *dns.Msg) { m.Opcode = dns.OpcodeUpdate }), want: dns.RcodeNotImplemented},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resp := s.answerDNS(t.Context(), test.req)

			if resp.Rcode != test.want {
				t.Errorf("got rcode %s, want %s", dns.RcodeToString[resp.Rcode], dns.RcodeToString[test.want])
			}

			if resp.Id != test.req.Id {
				t.Errorf("got ID %d, want %d", resp.Id, test.req.Id)
			}
		})
	}
}

func TestConfig_ValidateDNSListen(t *testing.T) {
	for addr, ok := range map[string]bool{":53": true, "127.0.0.1:5353": true, "[::1]:53": true, "53": false, "localhost": false} {
		t.Run(addr, func(t *testing.T) {
			err := Config{Plaintext: true, DNSListen: addr}.Validate()
			if (err == nil) != ok {
				t.Errorf("got error %v, want valid=%t", err, ok)
			}
		})
	}
}

func TestServer_ListenAndServeWithDNS(t *testing.T) {
	// Pick free ports, accepting a small race with other processes.
	freePort := func() string {
		t.Helper()

		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()

		pc, err := net.ListenPacket("udp", ln.Addr().String())
		if err != nil {
			t.Skipf("can't bind UDP alongside TCP: %v", err)
		}
		pc.Close()

		return ln.Addr().String()
	}

	httpAddr, dnsAddr := freePort(), freePort()

	s, err := New(Config{
		Plaintext: true,
		Listen:    httpAddr,
		DNSListen: dnsAddr,
		Upstreams: []string{startResolver(t)},
	}, testLogger(t))
	if err != nil {
		t.Fatal(err)
	}

	listenAndQuery(t, s, dnsAddr)

	t.Run("dns only", func(t *testing.T) {
		dnsAddr := freePort()

		s, err := New(Config{DNSListen: dnsAddr, Upstreams: []string{startResolver(t)}}, testLogger(t))
		if err != nil {
			t.Fatal(err)
		}

		listenAndQuery(t, s, dnsAddr)
	})
}

// listenAndQuery runs s.ListenAndServe, queries its DNS listener over TCP
// and UDP, then shuts it down.
func listenAndQuery(t *testing.T, s *Server, dnsAddr string) {
	t.Helper()

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- s.ListenAndServe(ctx) }()

	var (
		resp *dns.Msg
		err  error
	)
	for range 100 {
		resp, _, err = (&dns.Client{Net: "tcp", Timeout: time.Second}).Exchange(new(dns.Msg).SetQuestion("example.com.", dns.TypeA), dnsAddr)
		if err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}

	if len(resp.Answer) != 1 {
		t.Errorf("got %d answers over TCP, want 1", len(resp.Answer))
	}

	if resp := exchange(t, "udp", dnsAddr, new(dns.Msg).SetQuestion("example.com.", dns.TypeA)); len(resp.Answer) != 1 {
		t.Errorf("got %d answers over UDP, want 1", len(resp.Answer))
	}

	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("listen and serve: %v", err)
		}
	case <-time.After(shutdownTimeout + time.Second):
		t.Fatal("server did not shut down")
	}
}

func TestConfig_DNSOnly(t *testing.T) {
	tests := []struct {
		name    string
		config  Config
		wantErr string
	}{
		{name: "dns only", config: Config{DNSListen: ":53"}},
		{name: "dns only with explicit listen", config: Config{DNSListen: ":53", Listen: ":443"}, wantErr: "only plain DNS is served"},
		{name: "nothing to serve", config: Config{}, wantErr: "dns_listen"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.config.Validate()

			switch {
			case test.wantErr == "" && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case test.wantErr != "" && (err == nil || !strings.Contains(err.Error(), test.wantErr)):
				t.Fatalf("got error %v, want %q", err, test.wantErr)
			}
		})
	}

	t.Run("serve refuses DoH without TLS", func(t *testing.T) {
		s, err := New(Config{DNSListen: ":53", Upstreams: []string{startResolver(t)}}, testLogger(t))
		if err != nil {
			t.Fatal(err)
		}

		if s.tlsConfig != nil {
			t.Error("configured TLS for a DNS-only server")
		}

		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}

		if err := s.Serve(t.Context(), ln); err == nil {
			t.Fatal("expected Serve to refuse unencrypted DoH")
		}
	})
}

func TestListenError(t *testing.T) {
	opErr := func(errno syscall.Errno) error {
		return &net.OpError{Op: "listen", Net: "udp", Err: os.NewSyscallError("bind", errno)}
	}

	tests := []struct {
		err  error
		want string
	}{
		{err: opErr(syscall.EACCES), want: "cap_net_bind_service"},
		{err: opErr(syscall.EADDRINUSE), want: "systemd-resolved"},
		{err: errors.New("other"), want: "serve: other"},
	}

	for _, test := range tests {
		t.Run(test.want, func(t *testing.T) {
			err := listenError("serve", ":53", test.err)

			if !strings.Contains(err.Error(), test.want) {
				t.Errorf("got %q, want mention of %q", err, test.want)
			}

			if !errors.Is(err, test.err) {
				t.Errorf("got %v, want it to wrap %v", err, test.err)
			}
		})
	}
}

func TestLANAddrs(t *testing.T) {
	udp := func(s string) net.Addr { return net.UDPAddrFromAddrPort(netip.MustParseAddrPort(s)) }

	if got := lanAddrs(udp("192.168.1.10:53")); !slices.Equal(got, []netip.Addr{netip.MustParseAddr("192.168.1.10")}) {
		t.Errorf("got %v for a specific private address, want it alone", got)
	}

	if got := lanAddrs(udp("8.8.8.8:53")); got != nil {
		t.Errorf("got %v for a public address, want none", got)
	}

	for _, listen := range []string{"0.0.0.0:53", "[::]:53"} {
		for _, addr := range lanAddrs(udp(listen)) {
			if !addr.IsPrivate() {
				t.Errorf("%s: got non-private address %s", listen, addr)
			}
			if netip.MustParseAddrPort(listen).Addr().Is4() && !addr.Is4() {
				t.Errorf("%s: got IPv6 address %s for an IPv4 listener", listen, addr)
			}
		}
	}
}
