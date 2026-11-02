package cms

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/picatz/doh/internal/cms/cmstest"
)

const profile = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>PayloadType</key>
	<string>Configuration</string>
</dict>
</plist>
`

// keys are the kinds of signer keys TLS certificates have.
func keys(t *testing.T) map[string]crypto.Signer {
	t.Helper()
	p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	rsa2048, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return map[string]crypto.Signer{"P-256": p256, "P-384": p384, "RSA-2048": rsa2048}
}

func newPKI(t *testing.T, key crypto.Signer) *cmstest.PKI {
	now := time.Now()
	return cmstest.NewPKI(t, key, "dns.example.com", now.Add(-time.Hour), now.Add(90*24*time.Hour))
}

func TestSign_Decodes(t *testing.T) {
	when := time.Date(2026, 11, 2, 12, 30, 15, 999, time.FixedZone("x", 3600))
	for name, key := range keys(t) {
		t.Run(name, func(t *testing.T) {
			pki := newPKI(t, key)
			der, err := Sign([]byte(profile), Signer{Chain: pki.Chain(), Key: key}, when)
			if err != nil {
				t.Fatal(err)
			}
			m, err := cmstest.Decode(der)
			if err != nil {
				t.Fatal(err)
			}
			if err := m.Verify(); err != nil {
				t.Fatal(err)
			}
			if string(m.Content) != profile {
				t.Errorf("content = %q", m.Content)
			}
			if len(m.Certificates) != 2 || !m.Certificates[0].Equal(pki.Leaf) || !m.Certificates[1].Equal(pki.Intermediate) {
				t.Errorf("certificates = %d, want the leaf then the intermediate", len(m.Certificates))
			}
			if !m.SigningTime.Equal(when.Truncate(time.Second)) {
				t.Errorf("signing time = %v, want %v", m.SigningTime, when)
			}
			if sum := sha256.Sum256([]byte(profile)); !bytes.Equal(m.Digest, sum[:]) {
				t.Error("digest isn't the content's SHA-256")
			}
		})
	}
}

func TestSign_VerifiesWithOpenSSL(t *testing.T) {
	cmstest.OpenSSL(t)
	for name, key := range keys(t) {
		t.Run(name, func(t *testing.T) {
			pki := newPKI(t, key)
			der, err := Sign([]byte(profile), Signer{Chain: pki.Chain(), Key: key}, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			got, err := cmstest.VerifyWithOpenSSL(t, der, pki.Root)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != profile {
				t.Errorf("openssl verified content %q, want the profile exactly", got)
			}

			// Trusting another root, the same message doesn't verify.
			other := newPKI(t, key)
			if _, err := cmstest.VerifyWithOpenSSL(t, der, other.Root); err == nil {
				t.Error("verified against an unrelated root")
			}
		})
	}
}

// TestSign_TamperedFailsOpenSSL changes one byte of the signed content in
// the message: OpenSSL, and the decoder here, must both refuse it.
func TestSign_TamperedFailsOpenSSL(t *testing.T) {
	cmstest.OpenSSL(t)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pki := newPKI(t, key)
	der, err := Sign([]byte(profile), Signer{Chain: pki.Chain(), Key: key}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	i := bytes.Index(der, []byte("Configuration"))
	if i < 0 {
		t.Fatal("content not found in the message")
	}
	tampered := bytes.Clone(der)
	tampered[i] = 'c'
	if _, err := cmstest.VerifyWithOpenSSL(t, tampered, pki.Root); err == nil {
		t.Error("openssl verified tampered content")
	} else {
		t.Logf("openssl, as expected: %v", err)
	}
	m, err := cmstest.Decode(tampered)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Verify(); err == nil {
		t.Error("decoder verified tampered content")
	}
}

// TestSign_Mutations breaks each step of signing in turn, checking that
// OpenSSL catches each, so the tests above would notice a broken signer.
func TestSign_Mutations(t *testing.T) {
	cmstest.OpenSSL(t)
	flip := func(b []byte) []byte {
		b = bytes.Clone(b)
		b[len(b)-1] ^= 1
		return b
	}
	for name, key := range keys(t) {
		pki := newPKI(t, key)
		for _, step := range []string{"digest", "signed attributes", "content"} {
			t.Run(name+"/"+step, func(t *testing.T) {
				der, err := sign([]byte(profile), Signer{Chain: pki.Chain(), Key: key}, time.Now(), func(s string, b []byte) []byte {
					if s == step {
						return flip(b)
					}
					return b
				})
				if err != nil {
					t.Fatal(err)
				}
				if _, err := cmstest.VerifyWithOpenSSL(t, der, pki.Root); err == nil {
					t.Errorf("openssl verified a message whose %s was broken", step)
				}
			})
		}
	}
}

func TestSign_Errors(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	_, edKey, _ := ed25519.GenerateKey(rand.Reader)
	pki := newPKI(t, key)
	edPKI := cmstest.NewPKI(t, edKey, "dns.example.com", time.Now(), time.Now().Add(time.Hour))

	for _, tt := range []struct {
		name    string
		content []byte
		signer  Signer
		want    error
	}{
		{"no chain", nil, Signer{Key: key}, ErrNoCertificate},
		{"nil leaf", nil, Signer{Chain: []*x509.Certificate{nil}, Key: key}, ErrNoCertificate},
		{"no key", nil, Signer{Chain: pki.Chain()}, ErrKeyMismatch},
		{"another ECDSA key", nil, Signer{Chain: pki.Chain(), Key: other}, ErrKeyMismatch},
		{"an RSA key for an ECDSA certificate", nil, Signer{Chain: pki.Chain(), Key: rsaKey}, ErrKeyMismatch},
		{"Ed25519", nil, Signer{Chain: edPKI.Chain(), Key: edKey}, ErrUnsupportedKey},
		{"too large", make([]byte, MaxContentSize+1), Signer{Chain: pki.Chain(), Key: key}, ErrContentTooLarge},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Sign(tt.content, tt.signer, time.Now()); !errors.Is(err, tt.want) {
				t.Errorf("Sign = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestSign_SigningTimes(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pki := newPKI(t, key)
	for _, tt := range []struct {
		when time.Time
		tag  byte // UTCTime, or GeneralizedTime
	}{
		{time.Date(1950, 1, 1, 0, 0, 0, 0, time.UTC), 0x17},
		{time.Date(2049, 12, 31, 23, 59, 59, 0, time.UTC), 0x17},
		{time.Date(2050, 1, 1, 0, 0, 0, 0, time.UTC), 0x18},
		{time.Date(1949, 12, 31, 23, 59, 59, 0, time.UTC), 0x18},
	} {
		der, err := Sign([]byte("x"), Signer{Chain: pki.Chain(), Key: key}, tt.when)
		if err != nil {
			t.Fatal(err)
		}
		m, err := cmstest.Decode(der)
		if err != nil {
			t.Fatal(err)
		}
		if !m.SigningTime.Equal(tt.when) {
			t.Errorf("signing time %v, want %v", m.SigningTime, tt.when)
		}
		enc, _ := encodeTime(tt.when)
		if enc[0] != tt.tag {
			t.Errorf("%v encoded with tag %#x, want %#x", tt.when, enc[0], tt.tag)
		}
	}
}

func TestTLV_Lengths(t *testing.T) {
	for _, n := range []int{0, 1, 127, 128, 255, 256, 65535, 65536, 1 << 20} {
		b := tlv(tagOctetString, make([]byte, n))
		var header int
		switch {
		case n < 128:
			header = 2
		case n < 256:
			header = 3
		case n < 65536:
			header = 4
		default:
			header = 5
		}
		if len(b) != header+n {
			t.Errorf("tlv of %d bytes is %d bytes, want %d", n, len(b), header+n)
		}
	}
}

func FuzzSign(f *testing.F) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pki := cmstest.NewPKI(f, key, "dns.example.com", time.Now(), time.Now().Add(time.Hour))
	for _, s := range []string{"", profile, strings.Repeat("a", 128), strings.Repeat("\x00", 70000)} {
		f.Add([]byte(s), int64(0))
	}
	f.Fuzz(func(t *testing.T, content []byte, unix int64) {
		// Signing times in the years 1 to 9999, which ASN.1 can encode.
		when := time.Unix(unix%253402300799, 0).UTC()
		if when.Year() < 1 {
			when = time.Unix(0, 0)
		}
		der, err := Sign(content, Signer{Chain: pki.Chain(), Key: key}, when)
		if err != nil {
			t.Fatal(err)
		}
		m, err := cmstest.Decode(der)
		if err != nil {
			t.Fatal(err)
		}
		if err := m.Verify(); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(m.Content, content) || !m.SigningTime.Equal(when) {
			t.Fatalf("round trip changed content or time: %v != %v", m.SigningTime, when)
		}
	})
}
