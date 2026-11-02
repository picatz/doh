package serve

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/picatz/doh/internal/api"
	"github.com/picatz/doh/internal/cms/cmstest"
)

// signingPKI returns a PKI whose leaf, for testHostname, has a new key of
// the given kind, valid from notBefore to notAfter, and the paths of its
// chain (leaf and intermediate) and key.
func signingPKI(t *testing.T, kind string, notBefore, notAfter time.Time) (*cmstest.PKI, string, string) {
	t.Helper()
	var key crypto.Signer
	switch kind {
	case "rsa":
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		key = k
	case "ed25519":
		_, k, _ := ed25519.GenerateKey(rand.Reader)
		key = k
	default:
		key, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}
	pki := cmstest.NewPKI(t, key, testHostname, notBefore, notAfter)
	dir := t.TempDir()
	return pki, cmstest.WritePEM(t, dir, "chain.pem", pki.Chain()...), cmstest.WriteKey(t, dir, "key.pem", key)
}

// newSigningServer returns a plaintext server with a hostname, so it
// offers configuration profiles, configured by configure, logging to log.
func newSigningServer(t *testing.T, log *syncBuffer, configure func(*Config)) (*Server, error) {
	t.Helper()
	up, _ := startZone(t, nil)
	dataDir := t.TempDir()
	writePolicy(t, dataDir, hostnamePolicy())
	config := Config{
		Plaintext: true,
		Hostname:  testHostname,
		Upstreams: []string{up},
		DataDir:   dataDir,
		Blocklist: BlocklistConfig{CacheDir: t.TempDir()},
		RDAP:      RDAPConfig{BootstrapURL: "http://127.0.0.1:1/unreachable"},
	}
	if configure != nil {
		configure(&config)
	}
	logger := testLogger(t)
	if log != nil {
		logger = slog.New(slog.NewTextHandler(log, nil))
	}
	s, err := New(config, logger)
	if err == nil {
		t.Cleanup(func() { s.Close() })
	}
	return s, err
}

// appleSetup returns the Apple platform of a profile's setup, and an API
// client for the server.
func appleSetup(t *testing.T, s *Server) (api.Platform, apiClient) {
	t.Helper()
	c := apiClient{t, startAdmin(t, s), token(t, s.config.DataDir, ReaderTokenFile)}
	resp, body := c.do(http.MethodGet, "/api/v1/profiles/kids/setup?device=tablet", "")
	var setup api.Setup
	if err := json.Unmarshal(body, &setup); resp.StatusCode != http.StatusOK || err != nil {
		t.Fatalf("setup = %d %s", resp.StatusCode, body)
	}
	for _, p := range setup.Platforms {
		if p.ID == "apple" {
			if p.Signing == nil {
				t.Fatalf("apple platform has no signing status: %s", body)
			}
			return p, c
		}
	}
	t.Fatalf("no apple platform: %s", body)
	return api.Platform{}, c
}

// TestProfileSigning_VerifiesWithOpenSSL signs with --profile-signing-cert
// files, for each kind of key, and checks the downloaded profile with
// OpenSSL: it verifies against the root, and its content is exactly the
// profile served unsigned.
func TestProfileSigning_VerifiesWithOpenSSL(t *testing.T) {
	cmstest.OpenSSL(t)
	for _, kind := range []string{"ecdsa", "rsa"} {
		t.Run(kind, func(t *testing.T) {
			pki, certFile, keyFile := signingPKI(t, kind, time.Now().Add(-time.Hour), time.Now().Add(90*24*time.Hour))
			s, err := newSigningServer(t, nil, func(c *Config) {
				c.TLS.ProfileSigning = ProfileSigningConfig{CertFile: certFile, KeyFile: keyFile}
			})
			if err != nil {
				t.Fatal(err)
			}
			s.profileSigner.roots = x509.NewCertPool()
			s.profileSigner.roots.AddCert(pki.Root)

			apple, c := appleSetup(t, s)
			if st := apple.Signing; !st.Signed || !st.Trusted || st.Signer != testHostname || st.Expires == nil || !st.Expires.Equal(pki.Leaf.NotAfter) || st.Note != "" {
				t.Errorf("signing = %+v, want signed and trusted by %s", st, testHostname)
			}

			resp, signed := c.do(http.MethodGet, apple.Download, "")
			if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != api.MobileConfigType {
				t.Fatalf("mobileconfig = %d %q", resp.StatusCode, resp.Header.Get("Content-Type"))
			}
			got, err := cmstest.VerifyWithOpenSSL(t, signed, pki.Root)
			if err != nil {
				t.Fatal(err)
			}

			s.profileSigner = nil
			_, unsigned := c.do(http.MethodGet, apple.Download, "")
			if !bytes.HasPrefix(unsigned, []byte("<?xml")) {
				t.Fatalf("unsigned profile = %q", unsigned)
			}
			if !bytes.Equal(got, unsigned) {
				t.Errorf("openssl verified\n%s\nwant exactly\n%s", got, unsigned)
			}

			// A byte changed anywhere in the profile fails verification.
			i := bytes.Index(signed, []byte("dnsSettings"))
			tampered := bytes.Clone(signed)
			tampered[i] ^= 0x20
			if _, err := cmstest.VerifyWithOpenSSL(t, tampered, pki.Root); err == nil {
				t.Error("openssl verified a tampered profile")
			}
		})
	}
}

// TestProfileSigning_TLSCertificate signs with the TLS certificate files
// when no profile signing files are set, and prefers those that are.
func TestProfileSigning_TLSCertificate(t *testing.T) {
	tlsPKI, tlsCert, tlsKey := signingPKI(t, "ecdsa", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	s, err := newSigningServer(t, nil, func(c *Config) {
		c.Plaintext = false
		c.TLS = TLSConfig{CertFile: tlsCert, KeyFile: tlsKey}
	})
	if err != nil {
		t.Fatal(err)
	}
	apple, c := appleSetup(t, s)
	if !apple.Signing.Signed || apple.Signing.Trusted || apple.Signing.Note != noteUntrusted {
		t.Errorf("signing = %+v, want signed but untrusted (a private root)", apple.Signing)
	}
	if !strings.Contains(strings.Join(apple.Steps, " "), noteUntrusted) {
		t.Errorf("steps %q don't say the profile shows as unverified", apple.Steps)
	}
	_, body := c.do(http.MethodGet, apple.Download, "")
	m, err := cmstest.Decode(body)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Verify(); err != nil || !m.Certificates[0].Equal(tlsPKI.Leaf) || len(m.Certificates) != 2 {
		t.Errorf("signed by %v (%d certificates, %v), want the TLS certificate and its intermediate", m.Certificates[0].Subject, len(m.Certificates), err)
	}

	// Profile signing files take precedence.
	signPKI, signCert, signKey := signingPKI(t, "rsa", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	s, err = newSigningServer(t, nil, func(c *Config) {
		c.Plaintext = false
		c.TLS = TLSConfig{CertFile: tlsCert, KeyFile: tlsKey, ProfileSigning: ProfileSigningConfig{CertFile: signCert, KeyFile: signKey}}
	})
	if err != nil {
		t.Fatal(err)
	}
	_, c = appleSetup(t, s)
	_, body = c.do(http.MethodGet, "/api/v1/profiles/kids/apple.mobileconfig", "")
	if m, err := cmstest.Decode(body); err != nil || !m.Certificates[0].Equal(signPKI.Leaf) {
		t.Errorf("signed with %v, want the profile signing certificate", err)
	}
}

// TestProfileSigning_ACME signs with the ACME certificate for the
// hostname, here from autocert's cache.
func TestProfileSigning_ACME(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pki := cmstest.NewPKI(t, key, testHostname, time.Now().Add(-time.Hour), time.Now().Add(90*24*time.Hour))

	// autocert caches a certificate as its key, then its chain, under the
	// domain's name.
	cacheDir := t.TempDir()
	keyDER, _ := x509.MarshalECPrivateKey(key)
	var cached bytes.Buffer
	_ = pem.Encode(&cached, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	for _, c := range pki.Chain() {
		_ = pem.Encode(&cached, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
	}
	if err := os.WriteFile(filepath.Join(cacheDir, testHostname), cached.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}

	s, err := newSigningServer(t, nil, func(c *Config) {
		c.Plaintext = false
		c.TLS.ACME = ACMEConfig{Domains: []string{testHostname}, CacheDir: cacheDir, DirectoryURL: "http://127.0.0.1:1/unreachable"}
	})
	if err != nil {
		t.Fatal(err)
	}
	s.profileSigner.roots = x509.NewCertPool()
	s.profileSigner.roots.AddCert(pki.Root)

	apple, c := appleSetup(t, s)
	if !apple.Signing.Signed || !apple.Signing.Trusted {
		t.Errorf("signing = %+v, want signed with the ACME certificate", apple.Signing)
	}
	_, body := c.do(http.MethodGet, apple.Download, "")
	m, err := cmstest.Decode(body)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Verify(); err != nil || !m.Certificates[0].Equal(pki.Leaf) {
		t.Errorf("signed by %v, %v; want the ACME certificate", m.Certificates[0].Subject, err)
	}
}

// TestProfileSigning_Unsigned keeps serving unsigned profiles when the
// server has no certificate, and says so.
func TestProfileSigning_Unsigned(t *testing.T) {
	s, err := newSigningServer(t, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	apple, c := appleSetup(t, s)
	if st := apple.Signing; st.Signed || st.Trusted || st.Note != noteUnsigned || st.Expires != nil {
		t.Errorf("signing = %+v, want unsigned, with a note", st)
	}
	if !strings.Contains(strings.Join(apple.Steps, " "), "Unverified") {
		t.Errorf("steps %q don't say the profile shows as unverified", apple.Steps)
	}
	resp, body := c.do(http.MethodGet, apple.Download, "")
	if resp.Header.Get("Content-Type") != api.MobileConfigType || !bytes.HasPrefix(body, []byte("<?xml")) || !bytes.Contains(body, []byte("com.apple.dnsSettings.managed")) {
		t.Errorf("unsigned profile = %q %s", resp.Header.Get("Content-Type"), body)
	}

	// The JSON says signed: false explicitly.
	_, raw := c.do(http.MethodGet, "/api/v1/profiles/kids/setup", "")
	if !bytes.Contains(raw, []byte(`"signing":{"signed":false`)) {
		t.Errorf("setup JSON lacks signed: false: %s", raw)
	}
}

// TestProfileSigning_StartupErrors refuses to start with a profile signing
// certificate that can't sign.
func TestProfileSigning_StartupErrors(t *testing.T) {
	now := time.Now()
	_, certA, keyA := signingPKI(t, "ecdsa", now.Add(-time.Hour), now.Add(time.Hour))
	_, _, keyB := signingPKI(t, "ecdsa", now.Add(-time.Hour), now.Add(time.Hour))
	_, certEd, keyEd := signingPKI(t, "ed25519", now.Add(-time.Hour), now.Add(time.Hour))

	for _, tt := range []struct {
		name       string
		cert, key  string
		wantErrors []string
	}{
		{"another key", certA, keyB, []string{"profile signing certificate", "private key does not match public key"}},
		{"Ed25519", certEd, keyEd, []string{"profile signing certificate", "ECDSA or RSA"}},
		{"no key", certA, "", []string{"profile_signing cert_file and key_file must be set together"}},
		{"no certificate", "", keyA, []string{"profile_signing cert_file and key_file must be set together"}},
		{"missing files", filepath.Join(t.TempDir(), "nope.pem"), keyA, []string{"profile signing certificate", "no such file"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := newSigningServer(t, nil, func(c *Config) {
				c.TLS.ProfileSigning = ProfileSigningConfig{CertFile: tt.cert, KeyFile: tt.key}
			})
			if err == nil {
				t.Fatal("started")
			}
			for _, want := range tt.wantErrors {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q lacks %q", err, want)
				}
			}
		})
	}
}

// TestProfileSigning_Expired starts with an expired certificate, warning
// that devices show what it signs as unverified, and still signs.
func TestProfileSigning_Expired(t *testing.T) {
	_, certFile, keyFile := signingPKI(t, "ecdsa", time.Now().Add(-100*24*time.Hour), time.Now().Add(-10*24*time.Hour))
	var log syncBuffer
	s, err := newSigningServer(t, &log, func(c *Config) {
		c.TLS.ProfileSigning = ProfileSigningConfig{CertFile: certFile, KeyFile: keyFile}
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(log.String(), "level=WARN") || !strings.Contains(log.String(), "isn't valid now") {
		t.Errorf("no warning about the expired certificate:\n%s", log.String())
	}
	st := s.profileSigner.status()
	if !st.Signed || st.Trusted || !strings.Contains(st.Note, "expired") {
		t.Errorf("signing = %+v, want signed, untrusted, and a note that it expired", st)
	}
	if _, ok := s.profileSigner.sign([]byte("x")); !ok {
		t.Error("didn't sign with an expired certificate")
	}
	// Warned once per certificate, not per profile.
	if n := strings.Count(log.String(), "isn't valid now"); n != 1 {
		t.Errorf("warned %d times, want once", n)
	}
}
