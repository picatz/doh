package alerts

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeSMTP is a tiny SMTP server for tests: enough of RFC 5321, STARTTLS
// (RFC 3207), and AUTH PLAIN (RFC 4954) to receive what doh sends, and to
// misbehave on request.
type fakeSMTP struct {
	t    *testing.T
	ln   net.Listener
	cert tls.Certificate
	pool *x509.CertPool

	// Configuration, set before use.
	startTLS    bool   // offer STARTTLS
	implicitTLS bool   // speak TLS from the start, as on port 465
	user, pass  string // if set, AUTH PLAIN is offered and required
	rcptReply   string // if set, the reply to RCPT TO, such as "450 try later"

	mu       sync.Mutex
	messages []fakeMessage
	sawAuth  []string // the decoded AUTH PLAIN responses, as sent
	sawPlain []string // commands received before TLS, if any
}

// fakeMessage is a message the server took.
type fakeMessage struct {
	from, to string
	data     string
	tls      bool
}

// newFakeSMTP starts a fake SMTP server with a certificate for names.
func newFakeSMTP(t *testing.T, names ...string) *fakeSMTP {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: names[0]},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:         true, BasicConstraintsValid: true,
	}
	for _, n := range names {
		if ip := net.ParseIP(n); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, n)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(leaf)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &fakeSMTP{t: t, ln: ln, cert: tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pool: pool, startTLS: true}
	t.Cleanup(func() { ln.Close() })
	go s.serve()
	return s
}

// addr is the server's address.
func (s *fakeSMTP) addr() string { return s.ln.Addr().String() }

// dial connects to the server, whatever address is asked for, as a
// [MailConfig.Dial].
func (s *fakeSMTP) dial(ctx context.Context, network, _ string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, network, s.addr())
}

// config returns a MailConfig for the server, at host, trusting its
// certificate.
func (s *fakeSMTP) config(rawURL string) MailConfig {
	s.mu.Lock()
	defer s.mu.Unlock()
	return MailConfig{URL: rawURL, Password: Secret(s.pass), From: "doh <alerts@dns.example.com>", TLS: &tls.Config{RootCAs: s.pool}, Dial: s.dial}
}

func (s *fakeSMTP) serve() {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.handle(c)
	}
}

// taken returns the messages taken so far.
func (s *fakeSMTP) taken() []fakeMessage {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]fakeMessage(nil), s.messages...)
}

// waitMessages waits for n messages.
func (s *fakeSMTP) waitMessages(n int) []fakeMessage {
	s.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if m := s.taken(); len(m) >= n {
			return m
		}
		time.Sleep(5 * time.Millisecond)
	}
	s.t.Fatalf("got %d messages, want %d", len(s.taken()), n)
	return nil
}

func (s *fakeSMTP) handle(conn net.Conn) {
	defer func() { conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	s.mu.Lock()
	startTLS, implicitTLS, user, pass, rcptReply := s.startTLS, s.implicitTLS, s.user, s.pass, s.rcptReply
	s.mu.Unlock()
	secure := false
	if implicitTLS {
		tc := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{s.cert}})
		if tc.Handshake() != nil {
			return
		}
		conn, secure = tc, true
	}
	r, w := bufio.NewReader(conn), bufio.NewWriter(conn)
	reply := func(lines ...string) {
		for _, l := range lines {
			w.WriteString(l + "\r\n")
		}
		w.Flush()
	}
	reply("220 fake.example ESMTP")
	authed := user == ""
	var msg fakeMessage
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		verb := strings.ToUpper(strings.SplitN(line, " ", 2)[0])
		if !secure {
			s.mu.Lock()
			s.sawPlain = append(s.sawPlain, verb)
			s.mu.Unlock()
		}
		switch verb {
		case "EHLO", "HELO":
			ext := []string{"250-fake.example", "250-8BITMIME"}
			if startTLS && !secure {
				ext = append(ext, "250-STARTTLS")
			}
			if user != "" {
				ext = append(ext, "250-AUTH PLAIN")
			}
			ext = append(ext, "250 SIZE 1000000")
			reply(ext...)
		case "STARTTLS":
			if !startTLS || secure {
				reply("502 no")
				continue
			}
			reply("220 go ahead")
			tc := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{s.cert}})
			if tc.Handshake() != nil {
				return
			}
			conn, secure = tc, true
			r, w = bufio.NewReader(conn), bufio.NewWriter(conn)
		case "AUTH":
			f := strings.Fields(line)
			if len(f) != 3 || strings.ToUpper(f[1]) != "PLAIN" {
				reply("504 PLAIN only")
				continue
			}
			b, _ := base64.StdEncoding.DecodeString(f[2])
			s.mu.Lock()
			s.sawAuth = append(s.sawAuth, string(b))
			s.mu.Unlock()
			if string(b) == "\x00"+user+"\x00"+pass {
				authed = true
				reply("235 ok")
			} else {
				reply("535 authentication failed")
			}
		case "MAIL":
			if !authed {
				reply("530 sign in first")
				continue
			}
			msg = fakeMessage{from: strings.Trim(strings.TrimPrefix(line[len("MAIL FROM:"):], " "), "<>"), tls: secure}
			if i := strings.Index(msg.from, ">"); i >= 0 {
				msg.from = msg.from[:i]
			}
			reply("250 ok")
		case "RCPT":
			if rcptReply != "" {
				reply(rcptReply)
				continue
			}
			msg.to = strings.Trim(strings.TrimSpace(line[len("RCPT TO:"):]), "<>")
			reply("250 ok")
		case "DATA":
			reply("354 go on")
			var data strings.Builder
			for {
				l, err := r.ReadString('\n')
				if err != nil {
					return
				}
				if l == ".\r\n" {
					break
				}
				data.WriteString(strings.TrimPrefix(l, "."))
			}
			msg.data = data.String()
			s.mu.Lock()
			s.messages = append(s.messages, msg)
			s.mu.Unlock()
			reply("250 queued")
		case "RSET", "NOOP":
			reply("250 ok")
		case "QUIT":
			reply("221 bye")
			return
		default:
			reply("500 what")
		}
	}
}
