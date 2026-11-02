// Package cmstest helps test CMS signatures: it makes certificate
// authorities and signers, decodes SignedData with a decoder written apart
// from the encoder, and verifies messages with OpenSSL when it's
// installed. It's for tests only.
package cmstest

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

// PKI is a root certificate authority, an intermediate it issued, and a
// leaf certificate the intermediate issued, as a TLS server certificate
// from a public authority such as Let's Encrypt is.
type PKI struct {
	Root, Intermediate, Leaf *x509.Certificate

	// LeafKey is the leaf certificate's private key.
	LeafKey crypto.Signer
}

// Chain returns the leaf and intermediate certificates, in that order.
func (p *PKI) Chain() []*x509.Certificate { return []*x509.Certificate{p.Leaf, p.Intermediate} }

// NewPKI returns a new PKI whose leaf has key, valid from notBefore to
// notAfter, for the given DNS name, with the key usages of a TLS server
// certificate (digital signature, server authentication).
func NewPKI(t testing.TB, key crypto.Signer, name string, notBefore, notAfter time.Time) *PKI {
	t.Helper()

	rootKey := newECDSAKey(t)
	root := issue(t, &x509.Certificate{
		Subject:               pkix.Name{CommonName: "cmstest root"},
		NotBefore:             notBefore.Add(-24 * time.Hour),
		NotAfter:              notAfter.Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}, nil, rootKey, rootKey)

	intermediateKey := newECDSAKey(t)
	intermediate := issue(t, &x509.Certificate{
		Subject:               pkix.Name{CommonName: "cmstest intermediate"},
		NotBefore:             notBefore.Add(-time.Hour),
		NotAfter:              notAfter.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign,
	}, root, rootKey, intermediateKey)

	leaf := issue(t, &x509.Certificate{
		Subject:     pkix.Name{CommonName: name},
		DNSNames:    []string{name},
		NotBefore:   notBefore,
		NotAfter:    notAfter,
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}, intermediate, intermediateKey, key)

	return &PKI{Root: root, Intermediate: intermediate, Leaf: leaf, LeafKey: key}
}

func newECDSAKey(t testing.TB) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// issue signs template with parentKey, as parent (or self-signed if nil),
// for key's public key.
func issue(t testing.TB, template, parent *x509.Certificate, parentKey, key crypto.Signer) *x509.Certificate {
	t.Helper()
	sn, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		t.Fatal(err)
	}
	template.SerialNumber = sn.Add(sn, big.NewInt(1))
	if parent == nil {
		parent = template
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, key.Public(), parentKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// WritePEM writes certs to a PEM file in dir, returning its path.
func WritePEM(t testing.TB, dir, name string, certs ...*x509.Certificate) string {
	t.Helper()
	var b bytes.Buffer
	for _, c := range certs {
		_ = pem.Encode(&b, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, b.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// WriteKey writes key to a PKCS #8 PEM file in dir, returning its path.
func WriteKey(t testing.TB, dir, name string, key crypto.Signer) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// OpenSSL returns the path of the openssl command, skipping the test if
// it isn't installed.
func OpenSSL(t testing.TB) string {
	t.Helper()
	path, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl isn't installed, so CMS signatures can't be checked against an independent implementation (apt install openssl)")
	}
	return path
}

// VerifyWithOpenSSL verifies the DER-encoded CMS message msg with
// "openssl cms -verify", trusting only root, returning the content it
// verified or OpenSSL's error output.
//
// It passes -purpose any, since TLS server certificates carry only the
// server authentication extended key usage, not S/MIME's, and Apple
// devices accept them for signing configuration profiles.
func VerifyWithOpenSSL(t testing.TB, msg []byte, root *x509.Certificate) ([]byte, error) {
	t.Helper()
	openssl := OpenSSL(t)
	dir := t.TempDir()
	in := filepath.Join(dir, "message.der")
	if err := os.WriteFile(in, msg, 0o600); err != nil {
		t.Fatal(err)
	}
	ca := WritePEM(t, dir, "root.pem", root)
	out := filepath.Join(dir, "content")

	cmd := exec.Command(openssl, "cms", "-verify", "-binary", "-inform", "DER", "-in", in,
		"-CAfile", ca, "-purpose", "any", "-out", out)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("openssl cms -verify: %w: %s", err, bytes.TrimSpace(stderr.Bytes()))
	}
	content, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	return content, nil
}

// Message is a decoded SignedData with one signer.
type Message struct {
	Content      []byte
	Certificates []*x509.Certificate

	// DigestAlgorithm and SignatureAlgorithm are the signer's.
	DigestAlgorithm, SignatureAlgorithm asn1.ObjectIdentifier

	// SignatureNullParams reports whether the signature algorithm has
	// NULL parameters, rather than none.
	SignatureNullParams bool

	// Issuer and Serial name the signer's certificate.
	Issuer []byte
	Serial *big.Int

	// ContentType, Digest, and SigningTime are the signed attributes.
	ContentType asn1.ObjectIdentifier
	Digest      []byte
	SigningTime time.Time

	// SignedAttributes is the DER encoding the signature covers, and
	// Signature the signature.
	SignedAttributes, Signature []byte
}

// Object identifiers, written out apart from the encoder's.
var (
	OIDData          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	OIDSignedData    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	OIDSHA256        = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	OIDRSAEncryption = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	OIDECDSAWithSHA2 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}

	oidContentType   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidMessageDigest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	oidSigningTime   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}
)

type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,tag:0"`
}

type signedData struct {
	Version          int
	DigestAlgorithms []pkix.AlgorithmIdentifier `asn1:"set"`
	EncapContentInfo encapsulatedContentInfo
	Certificates     asn1.RawValue `asn1:"optional,tag:0"`
	SignerInfos      []signerInfo  `asn1:"set"`
}

type encapsulatedContentInfo struct {
	EContentType asn1.ObjectIdentifier
	EContent     []byte `asn1:"explicit,tag:0"`
}

type signerInfo struct {
	Version            int
	SID                issuerAndSerialNumber
	DigestAlgorithm    pkix.AlgorithmIdentifier
	SignedAttrs        asn1.RawValue `asn1:"tag:0"`
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          []byte
}

type issuerAndSerialNumber struct {
	Issuer asn1.RawValue
	Serial *big.Int
}

type attribute struct {
	Type   asn1.ObjectIdentifier
	Values []asn1.RawValue `asn1:"set"`
}

// Decode decodes a DER-encoded ContentInfo holding a SignedData with
// attached data content and exactly one signer, checking its structure
// strictly: versions, algorithms, the attributes required, and that the
// signed attributes are DER (sorted).
func Decode(der []byte) (*Message, error) {
	var ci contentInfo
	if rest, err := asn1.Unmarshal(der, &ci); err != nil || len(rest) > 0 {
		return nil, fmt.Errorf("ContentInfo: %v (%d trailing bytes)", err, len(rest))
	}
	if !ci.ContentType.Equal(OIDSignedData) {
		return nil, fmt.Errorf("content type %v, want signedData", ci.ContentType)
	}
	var sd signedData
	if rest, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil || len(rest) > 0 {
		return nil, fmt.Errorf("SignedData: %v (%d trailing bytes)", err, len(rest))
	}
	if sd.Version != 1 {
		return nil, fmt.Errorf("SignedData version %d, want 1", sd.Version)
	}
	if len(sd.DigestAlgorithms) != 1 || !sd.DigestAlgorithms[0].Algorithm.Equal(OIDSHA256) {
		return nil, fmt.Errorf("digest algorithms %v, want SHA-256 alone", sd.DigestAlgorithms)
	}
	if !sd.EncapContentInfo.EContentType.Equal(OIDData) {
		return nil, fmt.Errorf("encapsulated content type %v, want data", sd.EncapContentInfo.EContentType)
	}
	if len(sd.SignerInfos) != 1 {
		return nil, fmt.Errorf("%d signers, want 1", len(sd.SignerInfos))
	}

	m := &Message{Content: sd.EncapContentInfo.EContent}
	if sd.Certificates.Class != asn1.ClassContextSpecific || !sd.Certificates.IsCompound {
		return nil, errors.New("no certificates")
	}
	certs, err := x509.ParseCertificates(sd.Certificates.Bytes)
	if err != nil {
		return nil, fmt.Errorf("certificates: %w", err)
	}
	m.Certificates = certs

	si := sd.SignerInfos[0]
	if si.Version != 1 {
		return nil, fmt.Errorf("SignerInfo version %d, want 1", si.Version)
	}
	m.Issuer, m.Serial = si.SID.Issuer.FullBytes, si.SID.Serial
	m.DigestAlgorithm = si.DigestAlgorithm.Algorithm
	m.SignatureAlgorithm = si.SignatureAlgorithm.Algorithm
	m.SignatureNullParams = bytes.Equal(si.SignatureAlgorithm.Parameters.FullBytes, asn1.NullBytes)
	m.Signature = si.Signature

	// The signature covers the attributes with a SET OF tag.
	m.SignedAttributes = append([]byte{0x31}, si.SignedAttrs.FullBytes[1:]...)
	var attrs []attribute
	if rest, err := asn1.UnmarshalWithParams(m.SignedAttributes, &attrs, "set"); err != nil || len(rest) > 0 {
		return nil, fmt.Errorf("signed attributes: %v", err)
	}
	var encoded [][]byte
	seen := map[string]bool{}
	for _, a := range attrs {
		if len(a.Values) != 1 {
			return nil, fmt.Errorf("attribute %v has %d values", a.Type, len(a.Values))
		}
		if seen[a.Type.String()] {
			return nil, fmt.Errorf("attribute %v repeated", a.Type)
		}
		seen[a.Type.String()] = true
		b, _ := asn1.Marshal(a)
		encoded = append(encoded, b)
		v := a.Values[0].FullBytes
		switch {
		case a.Type.Equal(oidContentType):
			if _, err := asn1.Unmarshal(v, &m.ContentType); err != nil {
				return nil, fmt.Errorf("content type attribute: %w", err)
			}
		case a.Type.Equal(oidMessageDigest):
			if _, err := asn1.Unmarshal(v, &m.Digest); err != nil {
				return nil, fmt.Errorf("message digest attribute: %w", err)
			}
		case a.Type.Equal(oidSigningTime):
			if _, err := asn1.Unmarshal(v, &m.SigningTime); err != nil {
				return nil, fmt.Errorf("signing time attribute: %w", err)
			}
		}
	}
	if !slices.IsSortedFunc(encoded, bytes.Compare) {
		return nil, errors.New("signed attributes aren't in DER order")
	}
	if m.ContentType == nil || m.Digest == nil || m.SigningTime.IsZero() {
		return nil, errors.New("missing a content type, message digest, or signing time attribute")
	}
	return m, nil
}

// Verify checks m's digest and signature against its first certificate,
// which must be the signer's, independently of OpenSSL.
func (m *Message) Verify() error {
	if len(m.Certificates) == 0 {
		return errors.New("no certificates")
	}
	leaf := m.Certificates[0]
	if !bytes.Equal(leaf.RawIssuer, m.Issuer) || leaf.SerialNumber.Cmp(m.Serial) != 0 {
		return errors.New("the first certificate isn't the signer's")
	}
	if !m.DigestAlgorithm.Equal(OIDSHA256) {
		return fmt.Errorf("digest algorithm %v", m.DigestAlgorithm)
	}
	if !m.ContentType.Equal(OIDData) {
		return fmt.Errorf("content type attribute %v", m.ContentType)
	}
	if sum := sha256.Sum256(m.Content); !bytes.Equal(sum[:], m.Digest) {
		return errors.New("message digest doesn't match the content")
	}
	signed := sha256.Sum256(m.SignedAttributes)
	switch pub := leaf.PublicKey.(type) {
	case *ecdsa.PublicKey:
		if !m.SignatureAlgorithm.Equal(OIDECDSAWithSHA2) {
			return fmt.Errorf("signature algorithm %v for an ECDSA key", m.SignatureAlgorithm)
		}
		if !ecdsa.VerifyASN1(pub, signed[:], m.Signature) {
			return errors.New("bad ECDSA signature")
		}
	case *rsa.PublicKey:
		if !m.SignatureAlgorithm.Equal(OIDRSAEncryption) || !m.SignatureNullParams {
			return fmt.Errorf("signature algorithm %v for an RSA key", m.SignatureAlgorithm)
		}
		if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, signed[:], m.Signature); err != nil {
			return fmt.Errorf("bad RSA signature: %w", err)
		}
	default:
		return fmt.Errorf("unexpected key type %T", pub)
	}
	return nil
}
