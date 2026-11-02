// Package cms signs content as a Cryptographic Message Syntax SignedData
// message ([RFC 5652]), the minimal profile Apple devices accept for
// signed configuration profiles: one signer, attached content, SHA-256,
// and signed attributes (content type, message digest, and signing time).
//
// Signers are ECDSA (P-256, P-384, or P-521) or RSA (PKCS #1 v1.5) keys.
// The signer's certificate, and any intermediates given with it, are
// included so verifiers can build a chain to a root they trust.
//
// The package only encodes; it doesn't verify. Its tests verify its
// output with OpenSSL, an independent implementation, when it's
// installed.
//
// [RFC 5652]: https://www.rfc-editor.org/rfc/rfc5652.html
package cms

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"slices"
	"time"
)

// MaxContentSize is the largest content [Sign] accepts, 16 MiB, far more
// than any configuration profile.
const MaxContentSize = 16 << 20

// Object identifiers, from RFC 5652, RFC 5754, RFC 5758, and RFC 8017.
var (
	oidData          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidSignedData    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidContentType   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidMessageDigest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	oidSigningTime   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}
	oidSHA256        = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidRSAEncryption = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidECDSAWithSHA2 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
)

// Errors returned by [Sign].
var (
	// ErrNoCertificate means no signer certificate was given.
	ErrNoCertificate = errors.New("cms: no signer certificate")

	// ErrKeyMismatch means the key isn't the signer certificate's.
	ErrKeyMismatch = errors.New("cms: private key doesn't match the signer certificate")

	// ErrUnsupportedKey means the key is neither ECDSA nor RSA.
	ErrUnsupportedKey = errors.New("cms: unsupported key type: want ECDSA or RSA")

	// ErrContentTooLarge means the content exceeds [MaxContentSize].
	ErrContentTooLarge = errors.New("cms: content too large")
)

// Signer is what [Sign] signs with.
type Signer struct {
	// Chain is the signer's certificate first, then any intermediates,
	// in order. A root may be included but needn't be.
	Chain []*x509.Certificate

	// Key is the private key of Chain[0]: an *ecdsa.PrivateKey,
	// *rsa.PrivateKey, or another [crypto.Signer] with one of their
	// public keys, such as a key in hardware.
	Key crypto.Signer

	// Rand is the source of randomness for signing. It defaults to
	// [crypto/rand.Reader].
	Rand io.Reader
}

// Sign returns content signed by s, as the DER encoding of a CMS
// ContentInfo holding a SignedData with the content attached, signed at
// signingTime.
func Sign(content []byte, s Signer, signingTime time.Time) ([]byte, error) {
	return sign(content, s, signingTime, nil)
}

// mutation lets tests break one step of signing, to check that the tests
// would catch it. It's nil outside tests.
type mutation func(step string, b []byte) []byte

func sign(content []byte, s Signer, signingTime time.Time, mutate mutation) ([]byte, error) {
	if mutate == nil {
		mutate = func(_ string, b []byte) []byte { return b }
	}
	if len(content) > MaxContentSize {
		return nil, ErrContentTooLarge
	}
	if len(s.Chain) == 0 || s.Chain[0] == nil {
		return nil, ErrNoCertificate
	}
	if s.Key == nil {
		return nil, ErrKeyMismatch
	}
	leaf := s.Chain[0]

	signatureAlgorithm, opts, err := algorithmFor(s.Key.Public(), leaf.PublicKey)
	if err != nil {
		return nil, err
	}

	digest := sha256.Sum256(content)
	attrs, err := signedAttributes(mutate("digest", digest[:]), signingTime)
	if err != nil {
		return nil, err
	}

	// The signature covers the DER encoding of the attributes as a SET OF
	// (RFC 5652, Section 5.4), though they're sent with an implicit [0] tag.
	signed := sha256.Sum256(mutate("signed attributes", tlv(tagSet, attrs)))
	signature, err := s.Key.Sign(randOr(s.Rand), signed[:], opts)
	if err != nil {
		return nil, fmt.Errorf("cms: signing: %w", err)
	}

	issuerAndSerial, err := issuerAndSerialNumber(leaf)
	if err != nil {
		return nil, err
	}

	signerInfo := tlv(tagSequence,
		mustMarshal(1), // version: the signer is named by issuer and serial number
		issuerAndSerial,
		algorithmIdentifier(oidSHA256, false),
		tlv(tagContext0Constructed, attrs),
		signatureAlgorithm,
		tlv(tagOctetString, signature),
	)

	var certs [][]byte
	for _, c := range s.Chain {
		if c == nil {
			return nil, ErrNoCertificate
		}
		certs = append(certs, c.Raw)
	}

	signedData := tlv(tagSequence,
		mustMarshal(1), // version: no attribute certificates, data content
		tlv(tagSet, algorithmIdentifier(oidSHA256, false)),
		tlv(tagSequence, // EncapsulatedContentInfo
			mustMarshal(oidData),
			tlv(tagContext0Constructed, tlv(tagOctetString, mutate("content", content))),
		),
		tlv(tagContext0Constructed, certs...), // certificates [0] IMPLICIT CertificateSet
		tlv(tagSet, signerInfo),
	)

	return tlv(tagSequence, mustMarshal(oidSignedData), tlv(tagContext0Constructed, signedData)), nil
}

// algorithmFor returns the signature algorithm identifier and signing
// options for key, checking that it's the certificate's.
func algorithmFor(key, certKey crypto.PublicKey) ([]byte, crypto.SignerOpts, error) {
	switch k := key.(type) {
	case *ecdsa.PublicKey:
		if !k.Equal(certKey) {
			return nil, nil, ErrKeyMismatch
		}
		// ECDSA with SHA-256 has no parameters (RFC 5758, Section 3.2).
		return algorithmIdentifier(oidECDSAWithSHA2, false), crypto.SHA256, nil
	case *rsa.PublicKey:
		if !k.Equal(certKey) {
			return nil, nil, ErrKeyMismatch
		}
		// rsaEncryption with NULL parameters, as RFC 3370, Section 3.2
		// recommends and OpenSSL writes.
		return algorithmIdentifier(oidRSAEncryption, true), crypto.SHA256, nil
	default:
		return nil, nil, ErrUnsupportedKey
	}
}

// signedAttributes returns the encoded attributes, without the SET OF
// header, in the order DER requires: sorted by their encodings.
func signedAttributes(digest []byte, signingTime time.Time) ([]byte, error) {
	when, err := encodeTime(signingTime)
	if err != nil {
		return nil, err
	}
	attrs := [][]byte{
		attribute(oidContentType, mustMarshal(oidData)),
		attribute(oidMessageDigest, tlv(tagOctetString, digest)),
		attribute(oidSigningTime, when),
	}
	slices.SortFunc(attrs, bytes.Compare)
	return bytes.Join(attrs, nil), nil
}

// attribute encodes an Attribute with one value.
func attribute(oid asn1.ObjectIdentifier, value []byte) []byte {
	return tlv(tagSequence, mustMarshal(oid), tlv(tagSet, value))
}

// encodeTime encodes t as UTCTime from 1950 through 2049, and as
// GeneralizedTime otherwise (RFC 5652, Section 11.3).
func encodeTime(t time.Time) ([]byte, error) {
	t = t.UTC().Truncate(time.Second)
	if y := t.Year(); y >= 1950 && y < 2050 {
		return asn1.Marshal(t) // encoding/asn1 writes UTCTime in this range
	}
	b, err := asn1.MarshalWithParams(t, "generalized")
	if err != nil {
		return nil, fmt.Errorf("cms: signing time: %w", err)
	}
	return b, nil
}

// issuerAndSerialNumber identifies cert by its issuer's encoded name and
// its serial number.
func issuerAndSerialNumber(cert *x509.Certificate) ([]byte, error) {
	if len(cert.RawIssuer) == 0 || cert.SerialNumber == nil {
		return nil, errors.New("cms: signer certificate lacks an issuer or serial number")
	}
	serial, err := asn1.Marshal(cert.SerialNumber)
	if err != nil {
		return nil, fmt.Errorf("cms: serial number: %w", err)
	}
	return tlv(tagSequence, cert.RawIssuer, serial), nil
}

// algorithmIdentifier encodes an AlgorithmIdentifier, with NULL
// parameters if null, else none.
func algorithmIdentifier(oid asn1.ObjectIdentifier, null bool) []byte {
	if null {
		return tlv(tagSequence, mustMarshal(oid), asn1.NullBytes)
	}
	return tlv(tagSequence, mustMarshal(oid))
}

// mustMarshal encodes values that always encode: integers and object
// identifiers from this package.
func mustMarshal(v any) []byte {
	b, err := asn1.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

func randOr(r io.Reader) io.Reader {
	if r == nil {
		return rand.Reader
	}
	return r
}

// DER identifier octets.
const (
	tagOctetString         = 0x04
	tagSequence            = 0x30
	tagSet                 = 0x31
	tagContext0Constructed = 0xa0
)

// tlv encodes a DER element with the given identifier octet whose
// contents are the concatenation of contents.
func tlv(tag byte, contents ...[]byte) []byte {
	n := 0
	for _, c := range contents {
		n += len(c)
	}
	b := make([]byte, 0, 1+5+n)
	b = append(b, tag)
	switch {
	case n < 0x80:
		b = append(b, byte(n))
	default:
		var l []byte
		for v := n; v > 0; v >>= 8 {
			l = append([]byte{byte(v)}, l...)
		}
		b = append(b, 0x80|byte(len(l)))
		b = append(b, l...)
	}
	for _, c := range contents {
		b = append(b, c...)
	}
	return b
}
