package upstream

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/miekg/dns"
	"github.com/picatz/doh/pkg/doh"
)

// answer replies to every A question with addr.
func answer(addr string) dns.HandlerFunc {
	return func(w dns.ResponseWriter, req *dns.Msg) {
		resp := new(dns.Msg).SetReply(req)
		resp.Answer = append(resp.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.ParseIP(addr),
		})
		_ = w.WriteMsg(resp)
	}
}

// startDNS starts a DNS server on network ("udp", "tcp" or "tcp-tls") and
// returns its address.
func startDNS(t *testing.T, network string, handler dns.Handler, tlsConfig *tls.Config) string {
	t.Helper()

	server := &dns.Server{Handler: handler}

	var addr string
	switch network {
	case "udp":
		conn, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		server.PacketConn, addr = conn, conn.LocalAddr().String()
	default:
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		if tlsConfig != nil {
			listener = tls.NewListener(listener, tlsConfig)
		}
		server.Listener, addr = listener, listener.Addr().String()
	}

	ready := make(chan struct{})
	server.NotifyStartedFunc = func() { close(ready) }
	go func() { _ = server.ActivateAndServe() }()
	<-ready
	t.Cleanup(func() { _ = server.Shutdown() })

	return addr
}

// selfSigned returns a server TLS config with a certificate for 127.0.0.1
// and a pool that trusts it.
func selfSigned(t *testing.T) (*tls.Config, *x509.CertPool) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "doh test"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}

	pool := x509.NewCertPool()
	pool.AddCert(cert)

	return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}, pool
}

func query(t *testing.T, e Exchanger) (*dns.Msg, error) {
	t.Helper()

	q := new(dns.Msg).SetQuestion("example.com.", dns.TypeA)
	q.Id = 4242

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	resp, err := e.Exchange(ctx, q)
	if err == nil && resp.Id != q.Id {
		t.Errorf("got response ID %d, want query ID %d", resp.Id, q.Id)
	}

	return resp, err
}

func wantAnswer(t *testing.T, resp *dns.Msg, err error, addr string) {
	t.Helper()

	if err != nil {
		t.Fatal(err)
	}

	if len(resp.Answer) != 1 || resp.Answer[0].(*dns.A).A.String() != addr {
		t.Fatalf("got answers %v, want %s", resp.Answer, addr)
	}
}

func TestParse(t *testing.T) {
	tests := []struct {
		url     string
		want    string
		wantErr string
	}{
		{url: "https://dns.google/dns-query", want: "https://dns.google/dns-query"},
		{url: "tls://1.1.1.1", want: "tls://1.1.1.1:853"},
		{url: "tls://dns.quad9.net:8853", want: "tls://dns.quad9.net:8853"},
		{url: "tcp://9.9.9.9", want: "tcp://9.9.9.9:53"},
		{url: "udp://9.9.9.9:5353", want: "udp://9.9.9.9:5353"},
		{url: "9.9.9.9", want: "udp://9.9.9.9:53"},
		{url: "[2620:fe::fe]", want: "udp://[2620:fe::fe]:53"},
		{url: "udp://[2620:fe::fe]:53", want: "udp://[2620:fe::fe]:53"},
		{url: "http://example.com/dns-query", wantErr: "unsupported scheme"},
		{url: "tls://", wantErr: "missing host"},
	}

	for _, test := range tests {
		t.Run(test.url, func(t *testing.T) {
			e, err := Parse(test.url, Options{})
			if test.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantErr) {
					t.Fatalf("got error %v, want %q", err, test.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}

			if got := e.(interface{ String() string }).String(); got != test.want {
				t.Errorf("got %s, want %s", got, test.want)
			}
		})
	}
}

func TestExchange_UDP(t *testing.T) {
	addr := startDNS(t, "udp", answer("192.0.2.1"), nil)

	e, err := Parse("udp://"+addr, Options{})
	if err != nil {
		t.Fatal(err)
	}

	resp, err := query(t, e)
	wantAnswer(t, resp, err, "192.0.2.1")
}

func TestExchange_UDPTruncatedFallsBackToTCP(t *testing.T) {
	// Serve UDP and TCP on the same port: UDP always truncates.
	tcpListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := tcpListener.Addr().(*net.TCPAddr).Port

	udpConn, err := net.ListenPacket("udp", tcpListener.Addr().String())
	if err != nil {
		tcpListener.Close()
		t.Skipf("can't bind UDP on TCP port %d: %v", port, err)
	}

	var tcpQueries atomic.Int32
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		if w.LocalAddr().Network() == "udp" {
			resp := new(dns.Msg).SetReply(req)
			resp.Truncated = true
			_ = w.WriteMsg(resp)
			return
		}
		tcpQueries.Add(1)
		answer("192.0.2.2")(w, req)
	})

	for _, server := range []*dns.Server{{Listener: tcpListener, Handler: handler}, {PacketConn: udpConn, Handler: handler}} {
		ready := make(chan struct{})
		server.NotifyStartedFunc = func() { close(ready) }
		go func() { _ = server.ActivateAndServe() }()
		<-ready
		t.Cleanup(func() { _ = server.Shutdown() })
	}

	e, err := Parse("udp://"+tcpListener.Addr().String(), Options{})
	if err != nil {
		t.Fatal(err)
	}

	resp, err := query(t, e)
	wantAnswer(t, resp, err, "192.0.2.2")

	if tcpQueries.Load() != 1 {
		t.Errorf("got %d TCP queries, want 1", tcpQueries.Load())
	}
}

func TestExchange_TCP(t *testing.T) {
	addr := startDNS(t, "tcp", answer("192.0.2.3"), nil)

	e, err := Parse("tcp://"+addr, Options{})
	if err != nil {
		t.Fatal(err)
	}

	resp, err := query(t, e)
	wantAnswer(t, resp, err, "192.0.2.3")
}

func TestExchange_TLS(t *testing.T) {
	serverConfig, pool := selfSigned(t)
	addr := startDNS(t, "tcp-tls", answer("192.0.2.4"), serverConfig)

	t.Run("trusted", func(t *testing.T) {
		e, err := Parse("tls://"+addr, Options{TLSConfig: &tls.Config{RootCAs: pool}})
		if err != nil {
			t.Fatal(err)
		}

		resp, err := query(t, e)
		wantAnswer(t, resp, err, "192.0.2.4")
	})

	t.Run("untrusted", func(t *testing.T) {
		e, err := Parse("tls://"+addr, Options{})
		if err != nil {
			t.Fatal(err)
		}

		if _, err := query(t, e); err == nil {
			t.Fatal("expected certificate verification error")
		}
	})
}

func TestExchange_DoH(t *testing.T) {
	var gotID atomic.Int32
	gotID.Store(-1)

	mux := doh.NewServerMux(func(w http.ResponseWriter, r *http.Request, req *dns.Msg) (*dns.Msg, error) {
		gotID.Store(int32(req.Id))

		resp := new(dns.Msg).SetReply(req)
		resp.Answer = append(resp.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.ParseIP("192.0.2.5"),
		})
		return resp, nil
	})

	server := httptest.NewTLSServer(mux)
	t.Cleanup(server.Close)

	e, err := Parse(server.URL+doh.DefaultPath, Options{HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}

	resp, err := query(t, e)
	wantAnswer(t, resp, err, "192.0.2.5")

	if gotID.Load() != 0 {
		t.Errorf("upstream saw query ID %d, want 0 (RFC 8484, Section 4.1)", gotID.Load())
	}
}

type exchangerFunc func(context.Context, *dns.Msg) (*dns.Msg, error)

func (f exchangerFunc) Exchange(ctx context.Context, q *dns.Msg) (*dns.Msg, error) { return f(ctx, q) }

func TestFailover(t *testing.T) {
	failing := exchangerFunc(func(context.Context, *dns.Msg) (*dns.Msg, error) {
		return nil, errors.New("unreachable")
	})

	ok := exchangerFunc(func(_ context.Context, q *dns.Msg) (*dns.Msg, error) {
		return new(dns.Msg).SetRcode(q, dns.RcodeNameError), nil
	})

	t.Run("first success wins", func(t *testing.T) {
		var calls atomic.Int32
		counting := exchangerFunc(func(ctx context.Context, q *dns.Msg) (*dns.Msg, error) {
			calls.Add(1)
			return ok(ctx, q)
		})

		resp, err := Failover{failing, ok, counting}.Exchange(t.Context(), new(dns.Msg).SetQuestion("example.com.", dns.TypeA))
		if err != nil {
			t.Fatal(err)
		}

		// A DNS error response is still an answer, not a failure.
		if resp.Rcode != dns.RcodeNameError {
			t.Errorf("got rcode %s, want NXDOMAIN", dns.RcodeToString[resp.Rcode])
		}

		if calls.Load() != 0 {
			t.Errorf("later upstream called %d times, want 0", calls.Load())
		}
	})

	t.Run("all fail", func(t *testing.T) {
		_, err := Failover{failing, failing}.Exchange(t.Context(), new(dns.Msg).SetQuestion("example.com.", dns.TypeA))
		if !errors.Is(err, ErrAllFailed) {
			t.Fatalf("got error %v, want %v", err, ErrAllFailed)
		}

		if got := strings.Count(err.Error(), "unreachable"); got != 2 {
			t.Errorf("got %d upstream errors in %q, want 2", got, err)
		}
	})

	t.Run("stops when context is done", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())

		var calls atomic.Int32
		cancelling := exchangerFunc(func(context.Context, *dns.Msg) (*dns.Msg, error) {
			calls.Add(1)
			cancel()
			return nil, context.Canceled
		})

		_, err := Failover{cancelling, cancelling}.Exchange(ctx, new(dns.Msg).SetQuestion("example.com.", dns.TypeA))
		if !errors.Is(err, context.Canceled) {
			t.Errorf("got error %v, want %v", err, context.Canceled)
		}

		if calls.Load() != 1 {
			t.Errorf("got %d calls, want 1", calls.Load())
		}
	})
}

func TestFailover_SharesDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var firstBudget time.Duration

		// The first upstream never answers, like a blackholed resolver.
		blackholed := exchangerFunc(func(ctx context.Context, q *dns.Msg) (*dns.Msg, error) {
			deadline, _ := ctx.Deadline()
			firstBudget = time.Until(deadline)
			<-ctx.Done()
			return nil, ctx.Err()
		})

		ok := exchangerFunc(func(_ context.Context, q *dns.Msg) (*dns.Msg, error) {
			return new(dns.Msg).SetReply(q), nil
		})

		ctx, cancel := context.WithTimeout(t.Context(), 6*time.Second)
		defer cancel()

		start := time.Now()
		if _, err := (Failover{blackholed, ok, ok}).Exchange(ctx, new(dns.Msg).SetQuestion("example.com.", dns.TypeA)); err != nil {
			t.Fatalf("failover didn't reach a working upstream: %v", err)
		}

		if firstBudget != 2*time.Second {
			t.Errorf("first of 3 upstreams got %s, want a third of 6s", firstBudget)
		}

		if elapsed := time.Since(start); elapsed != 2*time.Second {
			t.Errorf("answered after %s, want 2s", elapsed)
		}
	})
}

func TestValidate(t *testing.T) {
	query := new(dns.Msg).SetQuestion("Example.com.", dns.TypeA)

	reply := func(modify func(*dns.Msg)) *dns.Msg {
		resp := new(dns.Msg).SetReply(query)
		modify(resp)
		return resp
	}

	tests := []struct {
		name    string
		resp    *dns.Msg
		wantErr bool
	}{
		{name: "reply", resp: reply(func(*dns.Msg) {})},
		{name: "case-insensitive name", resp: reply(func(m *dns.Msg) { m.Question[0].Name = "EXAMPLE.COM." })},
		{name: "no question section", resp: reply(func(m *dns.Msg) { m.Question = nil; m.Rcode = dns.RcodeFormatError })},
		{name: "successful response without question", resp: reply(func(m *dns.Msg) { m.Question = nil }), wantErr: true},
		{name: "not a response", resp: reply(func(m *dns.Msg) { m.Response = false }), wantErr: true},
		{name: "different name", resp: reply(func(m *dns.Msg) { m.Question[0].Name = "example.net." }), wantErr: true},
		{name: "different type", resp: reply(func(m *dns.Msg) { m.Question[0].Qtype = dns.TypeAAAA }), wantErr: true},
		{name: "extra question", resp: reply(func(m *dns.Msg) { m.Question = append(m.Question, m.Question[0]) }), wantErr: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := validate(query, test.resp); (err != nil) != test.wantErr {
				t.Errorf("got error %v, want error %t", err, test.wantErr)
			}
		})
	}
}

func TestExchange_DoHRejectsMismatchedResponse(t *testing.T) {
	mux := doh.NewServerMux(func(w http.ResponseWriter, r *http.Request, req *dns.Msg) (*dns.Msg, error) {
		return new(dns.Msg).SetQuestion("other.example.", dns.TypeA).SetReply(new(dns.Msg).SetQuestion("other.example.", dns.TypeA)), nil
	})

	server := httptest.NewTLSServer(mux)
	t.Cleanup(server.Close)

	e, err := Parse(server.URL+doh.DefaultPath, Options{HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := query(t, e); err == nil || !strings.Contains(err.Error(), "doesn't match") {
		t.Errorf("got error %v, want a question mismatch", err)
	}
}

func TestCheckRedirect(t *testing.T) {
	plain := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(plain.Close)

	redirecting := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, plain.URL+"/dns-query", http.StatusFound)
	}))
	t.Cleanup(redirecting.Close)

	client := redirecting.Client()
	client.CheckRedirect = CheckRedirect

	_, err := client.Get(redirecting.URL)
	if err == nil || !strings.Contains(err.Error(), "refusing redirect") {
		t.Errorf("got error %v, want an HTTPS to HTTP redirect refused", err)
	}

	e, err := Parse("https://dns.example/dns-query", Options{})
	if err != nil {
		t.Fatal(err)
	}

	if e.(*dohUpstream).client.CheckRedirect == nil {
		t.Error("default DoH client follows redirects to plain HTTP")
	}
}

func TestParse_RedactsCredentials(t *testing.T) {
	e, err := Parse("https://user:hunter2@dns.example/dns-query", Options{})
	if err != nil {
		t.Fatal(err)
	}

	if s := e.(fmt.Stringer).String(); strings.Contains(s, "hunter2") {
		t.Errorf("String() = %q exposes the password", s)
	}
}
