package cose

import (
	"crypto"
	_ "crypto/sha256" // registers crypto.SHA256 for Hash().New
	_ "crypto/sha512" // registers crypto.SHA384 and crypto.SHA512
	"fmt"
	"strconv"
)

// Algorithm is a signature algorithm identifier from the [IANA COSE
// Algorithms registry], as carried in a COSE_Key's alg parameter, a COSE
// header, CTAP's pubKeyCredParams and WebAuthn's
// [COSEAlgorithmIdentifier].
//
// Any int64 is a valid identifier; [Algorithm.Available] reports whether
// this package implements it. Text encodes an implemented identifier by its
// registry name, and JSON encodes every identifier as a number, as WebAuthn
// does.
//
// [IANA COSE Algorithms registry]: https://www.iana.org/assignments/cose/cose.xhtml#algorithms
// [COSEAlgorithmIdentifier]: https://www.w3.org/TR/webauthn-3/#sctn-alg-identifier
type Algorithm int64

// Algorithms this package implements, by registry value. Every one has a
// [Descriptor].
const (
	// AlgorithmES256 is ECDSA with SHA-256, paired here with P-256.
	AlgorithmES256 Algorithm = -7
	// AlgorithmEdDSA is EdDSA, implemented here with Ed25519 only.
	AlgorithmEdDSA Algorithm = -8
	// AlgorithmESP256 is ECDSA with P-256 and SHA-256, fully specified.
	AlgorithmESP256 Algorithm = -9
	// AlgorithmEd25519 is EdDSA with Ed25519, fully specified.
	AlgorithmEd25519 Algorithm = -19
	// AlgorithmES384 is ECDSA with SHA-384, paired here with P-384.
	AlgorithmES384 Algorithm = -35
	// AlgorithmES512 is ECDSA with SHA-512, paired here with P-521.
	AlgorithmES512 Algorithm = -36
	// AlgorithmPS256 is RSASSA-PSS with SHA-256, MGF1 with SHA-256 and a
	// 32-byte salt.
	AlgorithmPS256 Algorithm = -37
	// AlgorithmESP384 is ECDSA with P-384 and SHA-384, fully specified.
	AlgorithmESP384 Algorithm = -51
	// AlgorithmESP512 is ECDSA with P-521 and SHA-512, fully specified.
	AlgorithmESP512 Algorithm = -52
	// AlgorithmRS256 is RSASSA-PKCS1-v1_5 with SHA-256.
	AlgorithmRS256 Algorithm = -257
	// AlgorithmRS384 is RSASSA-PKCS1-v1_5 with SHA-384.
	AlgorithmRS384 Algorithm = -258
	// AlgorithmRS512 is RSASSA-PKCS1-v1_5 with SHA-512.
	AlgorithmRS512 Algorithm = -259
)

// KeyType is a COSE key type from the [IANA COSE Key Types registry].
//
// [IANA COSE Key Types registry]: https://www.iana.org/assignments/cose/cose.xhtml#key-type
type KeyType int64

// Key types of the algorithms this package implements.
const (
	// KeyTypeOKP is an octet key pair (RFC 9053 §7.2), such as Ed25519.
	KeyTypeOKP KeyType = 1
	// KeyTypeEC2 is an elliptic-curve key with x and y coordinates
	// (RFC 9053 §7.1.1).
	KeyTypeEC2 KeyType = 2
	// KeyTypeRSA is an RSA key (RFC 8230 §4).
	KeyTypeRSA KeyType = 3
)

// String returns the registry name, or KeyType(N) for another value.
func (k KeyType) String() string {
	switch k {
	case KeyTypeOKP:
		return "OKP"
	case KeyTypeEC2:
		return "EC2"
	case KeyTypeRSA:
		return "RSA"
	}
	return "KeyType(" + strconv.FormatInt(int64(k), 10) + ")"
}

// Curve is a COSE elliptic curve from the [IANA COSE Elliptic Curves
// registry].
//
// [IANA COSE Elliptic Curves registry]: https://www.iana.org/assignments/cose/cose.xhtml#elliptic-curves
type Curve int64

// Curves of the algorithms this package implements.
const (
	// CurveP256 is NIST P-256, an EC2 curve.
	CurveP256 Curve = 1
	// CurveP384 is NIST P-384, an EC2 curve.
	CurveP384 Curve = 2
	// CurveP521 is NIST P-521, an EC2 curve.
	CurveP521 Curve = 3
	// CurveEd25519 is Ed25519 for EdDSA, an OKP curve.
	CurveEd25519 Curve = 6
)

// String returns the registry name, or Curve(N) for another value.
func (c Curve) String() string {
	switch c {
	case CurveP256:
		return "P-256"
	case CurveP384:
		return "P-384"
	case CurveP521:
		return "P-521"
	case CurveEd25519:
		return "Ed25519"
	}
	return "Curve(" + strconv.FormatInt(int64(c), 10) + ")"
}

// implemented reports whether this package implements c for some algorithm.
func (c Curve) implemented() bool {
	return c == CurveP256 || c == CurveP384 || c == CurveP521 || c == CurveEd25519
}

// Descriptor is public metadata about an implemented [Algorithm]. It is
// pure data: obtaining one performs no cryptography or I/O.
type Descriptor struct {
	// Algorithm is the identifier described.
	Algorithm Algorithm
	// Name is the registry name, such as "ES256".
	Name string
	// Specification links to the section that defines the algorithm.
	Specification string
	// KeyType is the only key type the algorithm uses.
	KeyType KeyType
	// Curve is the only curve the algorithm uses here, or zero for RSA.
	Curve Curve
	// Hash is the hash the algorithm applies to the message, or zero for
	// EdDSA and Ed25519, which sign the message itself.
	Hash crypto.Hash
	// FullySpecified reports whether the identifier itself names one curve
	// and hash, as RFC 9864 defines. ES256, ES384, ES512 and EdDSA do not:
	// this package pins their curve, but another implementation may not.
	FullySpecified bool

	pss bool // RSASSA-PSS rather than RSASSA-PKCS1-v1_5
}

// Specification sections, linked from descriptors.
const (
	specECDSA      = "https://www.rfc-editor.org/rfc/rfc9053.html#section-2.1"
	specEdDSA      = "https://www.rfc-editor.org/rfc/rfc9053.html#section-2.2"
	specFullECDSA  = "https://www.rfc-editor.org/rfc/rfc9864.html#section-2.1"
	specFullEdDSA  = "https://www.rfc-editor.org/rfc/rfc9864.html#section-2.2"
	specRSAPSS     = "https://www.rfc-editor.org/rfc/rfc8230.html#section-2"
	specRSAPKCS1v5 = "https://www.rfc-editor.org/rfc/rfc8812.html#section-2"
)

// descriptors is the only table of implemented algorithms. Adding an
// algorithm means adding an entry here.
var descriptors = [...]Descriptor{
	{Algorithm: AlgorithmES256, Name: "ES256", Specification: specECDSA, KeyType: KeyTypeEC2, Curve: CurveP256, Hash: crypto.SHA256},
	{Algorithm: AlgorithmEdDSA, Name: "EdDSA", Specification: specEdDSA, KeyType: KeyTypeOKP, Curve: CurveEd25519},
	{Algorithm: AlgorithmESP256, Name: "ESP256", Specification: specFullECDSA, KeyType: KeyTypeEC2, Curve: CurveP256, Hash: crypto.SHA256, FullySpecified: true},
	{Algorithm: AlgorithmEd25519, Name: "Ed25519", Specification: specFullEdDSA, KeyType: KeyTypeOKP, Curve: CurveEd25519, FullySpecified: true},
	{Algorithm: AlgorithmES384, Name: "ES384", Specification: specECDSA, KeyType: KeyTypeEC2, Curve: CurveP384, Hash: crypto.SHA384},
	{Algorithm: AlgorithmES512, Name: "ES512", Specification: specECDSA, KeyType: KeyTypeEC2, Curve: CurveP521, Hash: crypto.SHA512},
	{Algorithm: AlgorithmPS256, Name: "PS256", Specification: specRSAPSS, KeyType: KeyTypeRSA, Hash: crypto.SHA256, FullySpecified: true, pss: true},
	{Algorithm: AlgorithmESP384, Name: "ESP384", Specification: specFullECDSA, KeyType: KeyTypeEC2, Curve: CurveP384, Hash: crypto.SHA384, FullySpecified: true},
	{Algorithm: AlgorithmESP512, Name: "ESP512", Specification: specFullECDSA, KeyType: KeyTypeEC2, Curve: CurveP521, Hash: crypto.SHA512, FullySpecified: true},
	{Algorithm: AlgorithmRS256, Name: "RS256", Specification: specRSAPKCS1v5, KeyType: KeyTypeRSA, Hash: crypto.SHA256, FullySpecified: true},
	{Algorithm: AlgorithmRS384, Name: "RS384", Specification: specRSAPKCS1v5, KeyType: KeyTypeRSA, Hash: crypto.SHA384, FullySpecified: true},
	{Algorithm: AlgorithmRS512, Name: "RS512", Specification: specRSAPKCS1v5, KeyType: KeyTypeRSA, Hash: crypto.SHA512, FullySpecified: true},
}

// Descriptor returns the algorithm's metadata, or false for an identifier
// this package does not implement.
func (a Algorithm) Descriptor() (Descriptor, bool) {
	for _, d := range descriptors {
		if d.Algorithm == a {
			return d, true
		}
	}
	return Descriptor{}, false
}

// Available returns nil when this package can parse, encode and verify with
// a, and an error matching [ErrUnsupported] otherwise. It performs no
// cryptography.
func (a Algorithm) Available() error {
	if _, ok := a.Descriptor(); !ok {
		return fmt.Errorf("%w: %v", ErrUnsupported, a)
	}
	return nil
}

// String returns the registry name of an implemented algorithm, or
// Algorithm(N) for another identifier.
func (a Algorithm) String() string {
	if d, ok := a.Descriptor(); ok {
		return d.Name
	}
	return "Algorithm(" + strconv.FormatInt(int64(a), 10) + ")"
}

// Hash returns the hash the algorithm applies to the message. It is zero
// for EdDSA and Ed25519, which sign the message itself, and for an
// identifier this package does not implement; [Algorithm.Available] tells
// them apart. The result suits [crypto.SignMessage] as its options, so a
// signer for any implemented algorithm is called the same way.
func (a Algorithm) Hash() crypto.Hash {
	d, _ := a.Descriptor()
	return d.Hash
}

// MarshalText returns the registry name of an implemented algorithm, or
// the identifier in decimal for another, so that every identifier
// round-trips through [Algorithm.UnmarshalText].
func (a Algorithm) MarshalText() ([]byte, error) {
	if d, ok := a.Descriptor(); ok {
		return []byte(d.Name), nil
	}
	return strconv.AppendInt(nil, int64(a), 10), nil
}

// UnmarshalText accepts the exact registry name of an implemented
// algorithm, such as "ES256", or any identifier in canonical decimal, such
// as "-7". Anything else fails with [ErrFormat], and a leaves unchanged.
func (a *Algorithm) UnmarshalText(text []byte) error {
	for _, d := range descriptors {
		if string(text) == d.Name {
			*a = d.Algorithm
			return nil
		}
	}
	value, err := parseDecimal(text)
	if err != nil {
		return err
	}
	*a = Algorithm(value)
	return nil
}

// MarshalJSON encodes the identifier as a JSON number, as WebAuthn's
// pubKeyCredParams and COSE in JSON do.
func (a Algorithm) MarshalJSON() ([]byte, error) {
	return strconv.AppendInt(nil, int64(a), 10), nil
}

// UnmarshalJSON accepts a JSON integer. JSON null leaves a unchanged, as
// encoding/json does for other types. Anything else, including a name in a
// string, fails with [ErrFormat].
func (a *Algorithm) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		return nil
	}
	value, err := parseDecimal(data)
	if err != nil {
		return err
	}
	*a = Algorithm(value)
	return nil
}

// parseDecimal parses a canonical decimal int64: no sign other than a
// leading minus, no leading zeros and no other characters.
func parseDecimal(text []byte) (int64, error) {
	value, err := strconv.ParseInt(string(text), 10, 64)
	if err != nil || strconv.FormatInt(value, 10) != string(text) {
		if len(text) > 32 {
			text = append(text[:32:32], "..."...)
		}
		return 0, fmt.Errorf("%w: %q is not a COSE algorithm", ErrFormat, text)
	}
	return value, nil
}
