package upstream

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/picatz/doh/internal/doq"
)

func TestParse_QUIC(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "doq.test"}, DNSNames: []string{"doq.test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(cert)

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = (&doq.Server{
			TLSConfig: &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}},
			Handler: func(ctx context.Context, r doq.Request) *dns.Msg {
				resp := new(dns.Msg).SetReply(r.Query)
				rr, _ := dns.NewRR(r.Query.Question[0].Name + " 60 IN A 192.0.2.53")
				resp.Answer = append(resp.Answer, rr)
				return resp
			},
		}).Serve(ctx, pc)
	}()
	t.Cleanup(func() { cancel(); <-done })

	_, port, _ := net.SplitHostPort(pc.LocalAddr().String())
	e, err := Parse("quic://127.0.0.1:"+port, Options{TLSConfig: &tls.Config{RootCAs: pool, ServerName: "doq.test"}})
	if err != nil {
		t.Fatal(err)
	}
	if got := e.(interface{ String() string }).String(); got != "quic://127.0.0.1:"+port {
		t.Errorf("String() = %q", got)
	}

	for i := range 3 { // the connection is reused
		q := new(dns.Msg).SetQuestion("example.com.", dns.TypeA)
		q.Id = uint16(100 + i)
		resp, err := e.Exchange(t.Context(), q)
		if err != nil {
			t.Fatal(err)
		}
		if resp.Id != q.Id || len(resp.Answer) != 1 || !strings.HasSuffix(resp.Answer[0].String(), "192.0.2.53") {
			t.Errorf("response = %v", resp)
		}
	}
}

func TestParse_QUICDefaultsAndLimits(t *testing.T) {
	e, err := Parse("quic://dns.example", Options{})
	if err != nil {
		t.Fatal(err)
	}
	if got := e.(*quicUpstream).client.Addr; got != "dns.example:853" {
		t.Errorf("addr = %q, want the default DoQ port", got)
	}
	if _, err := Parse("quic://dns.example", Options{Dialer: &net.Dialer{}}); err == nil {
		t.Error("accepted a custom dialer, which QUIC upstreams can't use")
	}
}

// TestParse_QUICLive checks interoperability with a public DoQ resolver.
// Like the other live tests, it only runs with DOH_LIVE_TESTS=1, since
// CI runners can't reliably reach public resolvers over UDP.
func TestParse_QUICLive(t *testing.T) {
	if os.Getenv("DOH_LIVE_TESTS") == "" {
		t.Skip("skipping live network test; set DOH_LIVE_TESTS=1 to enable")
	}

	e, err := Parse("quic://dns.adguard-dns.com", Options{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	resp, err := e.Exchange(ctx, new(dns.Msg).SetQuestion("example.com.", dns.TypeA))
	if err != nil {
		t.Fatal(err)
	}
	if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) == 0 {
		t.Errorf("response = %v", resp)
	}
}
