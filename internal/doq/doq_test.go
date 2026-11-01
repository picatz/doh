package doq

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/quic"
)

// testTLS returns a server certificate for "dns.example.test" and a pool
// that trusts it.
func testTLS(t *testing.T) (*tls.Config, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "dns.example.test"},
		DNSNames:     []string{"dns.example.test", "*.dns.example.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}, pool
}

// recorder answers A queries with 192.0.2.1, recording requests.
type recorder struct {
	mu       sync.Mutex
	requests []Request
}

func (r *recorder) handle(ctx context.Context, req Request) *dns.Msg {
	r.mu.Lock()
	r.requests = append(r.requests, req)
	r.mu.Unlock()

	resp := new(dns.Msg).SetReply(req.Query)
	rr, _ := dns.NewRR(req.Query.Question[0].Name + " 60 IN A 192.0.2.1")
	resp.Answer = append(resp.Answer, rr)
	return resp
}

// startServer serves DoQ on loopback, returning its address and a client
// that trusts it.
func startServer(t *testing.T, s *Server) (string, *Client) {
	t.Helper()
	serverTLS, pool := testTLS(t)
	if s.TLSConfig == nil {
		s.TLSConfig = serverTLS
	}

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx, pc) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("Serve: %v", err)
		}
	})

	addr := pc.LocalAddr().String()
	c := &Client{Addr: addr, TLSConfig: &tls.Config{RootCAs: pool, ServerName: "kids.dns.example.test"}}
	t.Cleanup(func() { c.Close() })
	return addr, c
}

func query(name string) *dns.Msg {
	m := new(dns.Msg).SetQuestion(dns.Fqdn(name), dns.TypeA)
	m.Id = 4242
	return m
}

func TestExchange(t *testing.T) {
	var r recorder
	_, c := startServer(t, &Server{Handler: r.handle})

	resp, err := c.Exchange(t.Context(), query("example.com"))
	if err != nil {
		t.Fatal(err)
	}
	if resp.Id != 4242 || len(resp.Answer) != 1 || !resp.Response {
		t.Errorf("response = %v, want an answer with the query's ID", resp)
	}

	r.mu.Lock()
	req := r.requests[0]
	r.mu.Unlock()
	if req.Query.Id != 0 {
		t.Errorf("server saw ID %d, want 0 on the wire", req.Query.Id)
	}
	if req.ServerName != "kids.dns.example.test" {
		t.Errorf("server name %q, want the one the client asked for", req.ServerName)
	}
	if !req.RemoteAddr.Addr().IsLoopback() {
		t.Errorf("remote address %v", req.RemoteAddr)
	}
}

func TestExchange_ConcurrentQueriesShareAConnection(t *testing.T) {
	var r recorder
	_, c := startServer(t, &Server{Handler: r.handle})

	var wg sync.WaitGroup
	errs := make(chan error, 50)
	for i := range 50 {
		wg.Go(func() {
			q := query(fmt.Sprintf("q%d.example.com", i))
			q.Id = uint16(i + 1)
			resp, err := c.Exchange(t.Context(), q)
			switch {
			case err != nil:
				errs <- err
			case resp.Id != q.Id || resp.Question[0].Name != q.Question[0].Name:
				errs <- fmt.Errorf("query %d got response %v", i, resp.Question)
			}
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}

	addrs := map[netip.AddrPort]bool{}
	r.mu.Lock()
	for _, req := range r.requests {
		addrs[req.RemoteAddr] = true
	}
	r.mu.Unlock()
	if len(addrs) != 1 {
		t.Errorf("queries came from %d client addresses, want one reused connection", len(addrs))
	}
}

func TestExchange_Padding(t *testing.T) {
	var seen atomic.Int32
	_, c := startServer(t, &Server{Handler: func(ctx context.Context, req Request) *dns.Msg {
		if b, _ := req.Query.Pack(); len(b)%queryBlock == 0 {
			seen.Add(1)
		}
		return new(dns.Msg).SetReply(req.Query)
	}})

	q := query("example.com")
	q.SetEdns0(1232, false)
	resp, err := c.Exchange(t.Context(), q)
	if err != nil {
		t.Fatal(err)
	}
	if seen.Load() != 1 {
		t.Error("EDNS query wasn't padded to a 128-byte block")
	}
	if b, _ := resp.Pack(); len(b)%responseBlock != 0 {
		t.Errorf("padded query's response is %d bytes, want a multiple of %d", len(b), responseBlock)
	}
	if len(q.IsEdns0().Option) != 0 {
		t.Error("Exchange modified the caller's query")
	}
}

func TestExchange_ReconnectsAfterServerClosesConnection(t *testing.T) {
	var r recorder
	_, c := startServer(t, &Server{Handler: r.handle})

	if _, err := c.Exchange(t.Context(), query("a.example.com")); err != nil {
		t.Fatal(err)
	}
	// The connection dies, as when a server restarts or times it out.
	c.mu.Lock()
	c.conn.Abort(nil)
	c.mu.Unlock()

	if _, err := c.Exchange(t.Context(), query("b.example.com")); err != nil {
		t.Errorf("after the connection closed: %v, want a new connection", err)
	}
}

func TestExchange_Errors(t *testing.T) {
	serverTLS, _ := testTLS(t)
	_, untrusting := startServer(t, &Server{Handler: (&recorder{}).handle, TLSConfig: serverTLS})
	untrusting.TLSConfig = &tls.Config{} // system roots don't trust the test certificate
	if _, err := untrusting.Exchange(t.Context(), query("example.com")); err == nil {
		t.Error("connected to a server with an untrusted certificate")
	}

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, c := startServer(t, &Server{Handler: (&recorder{}).handle})
	if _, err := c.Exchange(ctx, query("example.com")); !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled exchange = %v", err)
	}
}

// rawConn dials the server with a bare QUIC connection, to send what a
// well-behaved client wouldn't.
func rawConn(t *testing.T, addr string, alpn string) *quic.Conn {
	t.Helper()
	endpoint, err := quic.Listen("udp", "127.0.0.1:0", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { endpoint.Close(context.Background()) })
	config := &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13, NextProtos: []string{alpn}, ServerName: "dns.example.test"}
	conn, err := endpoint.Dial(t.Context(), "udp", addr, &quic.Config{TLSConfig: config})
	if err != nil {
		t.Fatal(err)
	}
	return conn
}

// send writes raw bytes on a new stream, then reads the response, if any.
func send(t *testing.T, conn *quic.Conn, data []byte) (*dns.Msg, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	stream, err := conn.NewStream(ctx)
	if err != nil {
		return nil, err
	}
	stream.SetReadContext(ctx)
	stream.SetWriteContext(ctx)
	if _, err := stream.Write(data); err != nil {
		return nil, err
	}
	if err := stream.CloseWrite(); err != nil {
		return nil, err
	}
	return readMessage(stream)
}

func framed(t *testing.T, m *dns.Msg) []byte {
	t.Helper()
	b, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return append(binary.BigEndian.AppendUint16(nil, uint16(len(b))), b...)
}

func TestServer_ProtocolErrors(t *testing.T) {
	keepalive := query("example.com")
	keepalive.Id = 0
	keepalive.SetEdns0(1232, false)
	keepalive.IsEdns0().Option = append(keepalive.IsEdns0().Option, &dns.EDNS0_TCP_KEEPALIVE{Code: dns.EDNS0TCPKEEPALIVE})

	nonzero := query("example.com")

	zero := query("example.com")
	zero.Id = 0
	response := new(dns.Msg).SetReply(zero)

	for _, tt := range []struct {
		desc string
		data []byte
	}{
		{"nonzero ID", framed(t, nonzero)},
		{"edns-tcp-keepalive", framed(t, keepalive)},
		{"two messages on one stream", append(framed(t, zero), framed(t, zero)...)},
		{"a response as a query", framed(t, response)},
		{"truncated message", framed(t, zero)[:10]},
		{"empty message", []byte{0, 0}},
		{"garbage", append([]byte{0, 5}, "hello"...)},
	} {
		t.Run(tt.desc, func(t *testing.T) {
			var r recorder
			addr, _ := startServer(t, &Server{Handler: r.handle})
			conn := rawConn(t, addr, ALPN)

			if resp, err := send(t, conn, tt.data); err == nil {
				t.Fatalf("answered %v, want a protocol error", resp)
			}
			r.mu.Lock()
			n := len(r.requests)
			r.mu.Unlock()
			if n != 0 {
				t.Error("the handler saw an invalid query")
			}

			// The connection is closed with DOQ_PROTOCOL_ERROR, except for
			// a truncated message, where only the stream fails.
			if tt.desc == "truncated message" {
				return
			}
			var closeErr *quic.ConnectionCloseError
			if err := conn.Wait(t.Context()); !errors.As(err, &closeErr) || closeErr.Code != CodeProtocolError {
				t.Errorf("connection closed with %v, want DOQ_PROTOCOL_ERROR", err)
			}
		})
	}
}

func TestServer_RejectsOtherProtocols(t *testing.T) {
	addr, _ := startServer(t, &Server{Handler: (&recorder{}).handle})

	endpoint, err := quic.Listen("udp", "127.0.0.1:0", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer endpoint.Close(context.Background())
	config := &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13, NextProtos: []string{"h3"}}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if conn, err := endpoint.Dial(ctx, "udp", addr, &quic.Config{TLSConfig: config}); err == nil {
		if _, err := send(t, conn, framed(t, query("example.com"))); err == nil {
			t.Error("an h3 client was answered")
		}
	}
}

func TestServer_NilResponseIsServfail(t *testing.T) {
	_, c := startServer(t, &Server{Handler: func(context.Context, Request) *dns.Msg { return nil }})
	resp, err := c.Exchange(t.Context(), query("example.com"))
	if err != nil || resp.Rcode != dns.RcodeServerFailure {
		t.Errorf("Exchange = %v, %v; want SERVFAIL", resp, err)
	}
}

func TestServer_StopsOnCancel(t *testing.T) {
	serverTLS, _ := testTLS(t)
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- (&Server{TLSConfig: serverTLS, Handler: (&recorder{}).handle}).Serve(ctx, pc) }()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Serve = %v, want nil after cancellation", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Serve didn't return after cancellation")
	}
}

func TestPad(t *testing.T) {
	for _, block := range []int{queryBlock, responseBlock} {
		for _, name := range []string{"a.example", "a-much-longer-name.with.many.labels.example.com"} {
			m := new(dns.Msg).SetQuestion(dns.Fqdn(name), dns.TypeAAAA)
			m.SetEdns0(1232, false)
			pad(m, block)
			pad(m, block) // padding again replaces the old padding
			if b, _ := m.Pack(); len(b)%block != 0 {
				t.Errorf("padded %s to %d bytes, want a multiple of %d", name, len(b), block)
			}
		}
	}

	plain := query("example.com")
	pad(plain, queryBlock)
	if plain.IsEdns0() != nil {
		t.Error("pad added EDNS to a query without it")
	}
}
