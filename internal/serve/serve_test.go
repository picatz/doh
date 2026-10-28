package serve

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/picatz/doh/pkg/doh"
)

// testLogger discards logs unless the test fails.
func testLogger(t *testing.T) *slog.Logger {
	t.Helper()
	return slog.New(slog.NewTextHandler(t.Output(), &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// startResolver starts a UDP DNS server answering A queries with 192.0.2.1.
func startResolver(t *testing.T) string {
	t.Helper()

	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	server := &dns.Server{PacketConn: conn, UDPSize: dns.MaxMsgSize, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		resp := new(dns.Msg).SetReply(req)
		resp.Answer = append(resp.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.ParseIP("192.0.2.1"),
		})
		_ = w.WriteMsg(resp)
	})}

	ready := make(chan struct{})
	server.NotifyStartedFunc = func() { close(ready) }
	go func() { _ = server.ActivateAndServe() }()
	<-ready
	t.Cleanup(func() { _ = server.Shutdown() })

	return conn.LocalAddr().String()
}

// writeCert writes a self-signed certificate for 127.0.0.1 with the given
// common name, returning the cert and key paths.
func writeCert(t *testing.T, dir, commonName string) (string, string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: commonName},
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

	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}

	certFile, keyFile := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")

	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}

	return certFile, keyFile
}

// start serves s on a local port until the test ends, returning its address.
func start(t *testing.T, s *Server) string {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx, ln) }()

	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("serve: %v", err)
		}
	})

	return ln.Addr().String()
}

func TestConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  Config
		wantErr string
	}{
		{name: "plaintext", config: Config{Plaintext: true}},
		{name: "cert files", config: Config{TLS: TLSConfig{CertFile: "c", KeyFile: "k"}}},
		{name: "acme", config: Config{TLS: TLSConfig{ACME: ACMEConfig{Domains: []string{"doh.example"}, CacheDir: "/tmp/acme"}}}},
		{name: "no TLS", config: Config{}, wantErr: "no TLS certificate configured"},
		{name: "cert without key", config: Config{TLS: TLSConfig{CertFile: "c"}}, wantErr: "must be set together"},
		{name: "files and acme", config: Config{TLS: TLSConfig{CertFile: "c", KeyFile: "k", ACME: ACMEConfig{Domains: []string{"d"}}}}, wantErr: "not both"},
		{name: "plaintext and TLS", config: Config{Plaintext: true, TLS: TLSConfig{CertFile: "c", KeyFile: "k"}}, wantErr: "can't be combined"},
		{name: "acme http without domain", config: Config{Plaintext: true, TLS: TLSConfig{ACME: ACMEConfig{HTTPListen: ":80"}}}, wantErr: "requires an ACME domain"},
		{name: "relative path", config: Config{Plaintext: true, Path: "dns-query"}, wantErr: "must start with /"},
		{name: "negative timeout", config: Config{Plaintext: true, Timeout: -1}, wantErr: "must not be negative"},
		{name: "bad upstream", config: Config{Plaintext: true, Upstreams: []string{"ftp://x"}}, wantErr: "unsupported scheme"},
		{name: "bad log level", config: Config{Plaintext: true, Log: LogConfig{Level: "loud"}}, wantErr: "invalid level"},
		{name: "bad log format", config: Config{Plaintext: true, Log: LogConfig{Format: "xml"}}, wantErr: "invalid format"},
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
}

func TestConfig_Defaults(t *testing.T) {
	c := Config{}.withDefaults()
	if c.Listen != DefaultListen || c.Path != doh.DefaultPath || time.Duration(c.Timeout) != DefaultTimeout || !slices.Equal(c.Upstreams, DefaultUpstreams) {
		t.Errorf("got %+v, want defaults", c)
	}

	if got := (Config{Plaintext: true}).withDefaults().Listen; got != DefaultPlaintextListen {
		t.Errorf("got plaintext listen %q, want %q", got, DefaultPlaintextListen)
	}
}

func TestConfig_LoadFile(t *testing.T) {
	dir := t.TempDir()

	write := func(name, content string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}

	t.Run("valid", func(t *testing.T) {
		c := Config{Listen: ":1"}
		err := c.LoadFile(write("valid.json", `{
			"upstreams": ["9.9.9.9"],
			"timeout": "1m30s",
			"tls": {"acme": {"domains": ["doh.example"], "email": "a@doh.example"}},
			"log": {"level": "debug", "format": "json"}
		}`))
		if err != nil {
			t.Fatal(err)
		}

		if c.Listen != ":1" {
			t.Errorf("got listen %q, want unset fields preserved", c.Listen)
		}
		if time.Duration(c.Timeout) != 90*time.Second {
			t.Errorf("got timeout %s, want 1m30s", time.Duration(c.Timeout))
		}
		if c.TLS.ACME.Email != "a@doh.example" || c.Log.Format != "json" {
			t.Errorf("got %+v, want nested fields", c)
		}
	})

	for name, content := range map[string]string{
		"unknown field":    `{"listne": ":1"}`,
		"numeric duration": `{"timeout": 5}`,
		"bad duration":     `{"timeout": "soon"}`,
		"malformed":        `{`,
	} {
		t.Run(name, func(t *testing.T) {
			var c Config
			if err := c.LoadFile(write(name+".json", content)); err == nil {
				t.Fatal("expected error")
			}
		})
	}

	t.Run("round trip", func(t *testing.T) {
		want := Config{Listen: ":1", Timeout: Duration(3 * time.Second), Plaintext: true}

		b, err := json.Marshal(want)
		if err != nil {
			t.Fatal(err)
		}

		var got Config
		if err := got.LoadFile(write("roundtrip.json", string(b))); err != nil {
			t.Fatal(err)
		}

		if got.Listen != want.Listen || got.Timeout != want.Timeout || got.Plaintext != want.Plaintext {
			t.Errorf("got %+v, want %+v (JSON %s)", got, want, b)
		}
	})
}

func query(t *testing.T, client *http.Client, serverURL string) *dns.Msg {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	resp, err := doh.Query(ctx, client, serverURL, new(dns.Msg).SetQuestion("example.com.", dns.TypeA))
	if err != nil {
		t.Fatal(err)
	}

	return resp
}

func TestServer_Plaintext(t *testing.T) {
	s, err := New(Config{Plaintext: true, Upstreams: []string{startResolver(t)}}, testLogger(t))
	if err != nil {
		t.Fatal(err)
	}

	addr := start(t, s)
	client := &http.Client{Transport: &http.Transport{}}

	resp := query(t, client, "http://"+addr+doh.DefaultPath)
	if len(resp.Answer) != 1 || resp.Answer[0].(*dns.A).A.String() != "192.0.2.1" {
		t.Errorf("got answers %v, want 192.0.2.1", resp.Answer)
	}

	health, err := client.Get("http://" + addr + HealthPath)
	if err != nil {
		t.Fatal(err)
	}
	defer health.Body.Close()

	if body, _ := io.ReadAll(health.Body); health.StatusCode != http.StatusOK || string(body) != "ok\n" {
		t.Errorf("got health %d %q, want 200 \"ok\\n\"", health.StatusCode, body)
	}
}

func TestServer_UpstreamFailureIsServfail(t *testing.T) {
	// Reserve a TCP port, then close it so the upstream refuses connections.
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

	resp := query(t, &http.Client{Transport: &http.Transport{}}, "http://"+start(t, s)+doh.DefaultPath)
	if resp.Rcode != dns.RcodeServerFailure {
		t.Errorf("got rcode %s, want SERVFAIL", dns.RcodeToString[resp.Rcode])
	}
}

func TestServer_TLSCertificateFiles(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := writeCert(t, dir, "first")

	s, err := New(Config{
		Upstreams: []string{startResolver(t)},
		TLS:       TLSConfig{CertFile: certFile, KeyFile: keyFile},
	}, testLogger(t))
	if err != nil {
		t.Fatal(err)
	}

	addr := start(t, s)

	// Inspect the served certificate without verifying it, since the test
	// swaps it out.
	servedName := func() string {
		t.Helper()

		conn, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true})
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()

		state := conn.ConnectionState()
		if state.Version < tls.VersionTLS12 {
			t.Errorf("negotiated TLS version %x, want at least 1.2", state.Version)
		}

		return state.PeerCertificates[0].Subject.CommonName
	}

	if got := servedName(); got != "first" {
		t.Fatalf("got certificate %q, want first", got)
	}

	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		ForceAttemptHTTP2: true,
	}}

	if resp := query(t, client, "https://"+addr+doh.DefaultPath); len(resp.Answer) != 1 {
		t.Errorf("got %d answers over TLS, want 1", len(resp.Answer))
	}

	health, err := client.Get("https://" + addr + HealthPath)
	if err != nil {
		t.Fatal(err)
	}
	health.Body.Close()

	if health.ProtoMajor != 2 {
		t.Errorf("got %s, want HTTP/2 over TLS", health.Proto)
	}

	t.Run("reload", func(t *testing.T) {
		writeCert(t, dir, "second")

		// Make the change visible regardless of filesystem time resolution,
		// and skip the reload throttle.
		future := time.Now().Add(time.Minute)
		for _, name := range []string{certFile, keyFile} {
			if err := os.Chtimes(name, future, future); err != nil {
				t.Fatal(err)
			}
		}

		reloader := s.reloader
		reloader.mu.Lock()
		reloader.checked = time.Time{}
		reloader.mu.Unlock()

		if got := servedName(); got != "second" {
			t.Errorf("got certificate %q after reload, want second", got)
		}
	})

	t.Run("invalid replacement keeps serving", func(t *testing.T) {
		if err := os.WriteFile(certFile, []byte("not a certificate"), 0o600); err != nil {
			t.Fatal(err)
		}

		future := time.Now().Add(2 * time.Minute)
		if err := os.Chtimes(certFile, future, future); err != nil {
			t.Fatal(err)
		}

		reloader := s.reloader
		reloader.mu.Lock()
		reloader.checked = time.Time{}
		reloader.mu.Unlock()

		if got := servedName(); got != "second" {
			t.Errorf("got certificate %q, want previous certificate second", got)
		}
	})
}

func TestServer_MissingCertificate(t *testing.T) {
	_, err := New(Config{TLS: TLSConfig{CertFile: "missing.pem", KeyFile: "missing.key"}}, testLogger(t))
	if err == nil {
		t.Fatal("expected error for missing certificate files")
	}
}

func TestServer_ACME(t *testing.T) {
	s, err := New(Config{TLS: TLSConfig{ACME: ACMEConfig{
		Domains:      []string{"doh.example"},
		CacheDir:     t.TempDir(),
		DirectoryURL: unreachableURL(t),
	}}}, testLogger(t))
	if err != nil {
		t.Fatal(err)
	}

	if !slices.Contains(s.tlsConfig.NextProtos, "acme-tls/1") {
		t.Errorf("got NextProtos %v, want acme-tls/1 for TLS-ALPN-01", s.tlsConfig.NextProtos)
	}

	// Names outside the configured domains are refused without contacting
	// the certificate authority.
	if _, err := s.tlsConfig.GetCertificate(&tls.ClientHelloInfo{ServerName: "other.example"}); err == nil {
		t.Error("expected certificate request for an unconfigured name to fail")
	}
}

func TestServer_ShutdownWaitsForInFlightRequests(t *testing.T) {
	s, err := New(Config{Plaintext: true, Upstreams: []string{startResolver(t)}}, testLogger(t))
	if err != nil {
		t.Fatal(err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx, ln) }()

	query(t, &http.Client{Transport: &http.Transport{}}, "http://"+ln.Addr().String()+doh.DefaultPath)

	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("serve returned %v, want nil after graceful shutdown", err)
		}
	case <-time.After(shutdownTimeout + time.Second):
		t.Fatal("server did not shut down")
	}

	if _, err := net.DialTimeout("tcp", ln.Addr().String(), time.Second); err == nil {
		t.Error("listener still accepting connections after shutdown")
	}
}

func TestConfig_LoadFileRejectsTrailingData(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"plaintext": true} {"listne": ":80"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	var c Config
	if err := c.LoadFile(path); err == nil || !strings.Contains(err.Error(), "unexpected data") {
		t.Errorf("got error %v, want trailing data rejected", err)
	}
}

func TestConfig_ValidatePath(t *testing.T) {
	for path, ok := range map[string]bool{
		"/dns-query":    true,
		"/resolve":      true,
		"dns-query":     false,
		HealthPath:      false,
		"/dns/{x}":      false,
		"/dns/{":        false,
		"/dns query":    false,
		"/dns/../query": false,
		"/dns//query":   false,
		"/dns-query/":   false,
		"/%68ealthz":    false,
		"/":             true,
	} {
		t.Run(path, func(t *testing.T) {
			config := Config{Plaintext: true, Path: path, Upstreams: []string{"192.0.2.1"}}

			if err := config.Validate(); (err == nil) != ok {
				t.Fatalf("got error %v, want valid=%t", err, ok)
			}

			// New must return an error rather than panic registering the
			// endpoint on the mux.
			if _, err := New(config, testLogger(t)); (err == nil) != ok {
				t.Errorf("New: got error %v, want valid=%t", err, ok)
			}
		})
	}
}

// unreachableURL returns a URL that refuses connections, so ACME tests
// never contact a real certificate authority.
func unreachableURL(t *testing.T) string {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln.Close()

	return "https://" + ln.Addr().String() + "/directory"
}

// writeACMECache stores a self-signed certificate for name in an autocert
// cache directory, as autocert would after issuing it.
func writeACMECache(t *testing.T, dir, name string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: name},
		DNSNames:     []string{name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}

	data := append(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)

	if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestServer_ACMEEnforcesDomainsOnCachedCertificates guards that autocert
// applies the host policy before its cache, so a certificate cached for a
// domain since removed from the configuration isn't served.
func TestServer_ACMEEnforcesDomainsOnCachedCertificates(t *testing.T) {
	cacheDir := t.TempDir()
	writeACMECache(t, cacheDir, "doh.example")
	writeACMECache(t, cacheDir, "removed.example")

	s, err := New(Config{TLS: TLSConfig{ACME: ACMEConfig{
		Domains:      []string{"doh.example"},
		CacheDir:     cacheDir,
		DirectoryURL: unreachableURL(t),
	}}}, testLogger(t))
	if err != nil {
		t.Fatal(err)
	}

	// Advertise ECDSA support, so autocert looks up the ECDSA certificate.
	hello := func(name string) *tls.ClientHelloInfo {
		return &tls.ClientHelloInfo{
			ServerName:       name,
			SignatureSchemes: []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256},
			SupportedCurves:  []tls.CurveID{tls.CurveP256},
			CipherSuites:     []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		}
	}

	if _, err := s.tlsConfig.GetCertificate(hello("DOH.example")); err != nil {
		t.Errorf("configured domain: %v", err)
	}

	if _, err := s.tlsConfig.GetCertificate(hello("removed.example")); err == nil {
		t.Error("served a cached certificate for a domain no longer configured")
	}
}

func TestCertReloader_DetectsEitherFileChanging(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := writeCert(t, dir, "first")

	// Give the key a newer timestamp than the certificate.
	base := time.Now().Add(time.Hour)
	setTimes := func(cert, key time.Time) {
		t.Helper()
		for name, mtime := range map[string]time.Time{certFile: cert, keyFile: key} {
			if err := os.Chtimes(name, mtime, mtime); err != nil {
				t.Fatal(err)
			}
		}
	}
	setTimes(base, base.Add(time.Minute))

	r, err := newCertReloader(certFile, keyFile, testLogger(t))
	if err != nil {
		t.Fatal(err)
	}

	// Rotate both files, with timestamps that are no newer than the key's
	// previous one, and one moving backwards.
	writeCert(t, dir, "second")
	setTimes(base.Add(30*time.Second), base.Add(time.Minute-time.Second))

	r.checked = time.Time{}
	cert, err := r.GetCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}

	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}

	if leaf.Subject.CommonName != "second" {
		t.Errorf("got certificate %q, want the rotated certificate", leaf.Subject.CommonName)
	}
}
