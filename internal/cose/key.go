package cose

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"fmt"
	"math/big"
	"slices"

	"github.com/picatz/cbor"
)

// MaxPublicKeySize bounds an encoded COSE_Key that [ParsePublicKey]
// accepts. An RSA key of the largest accepted size fits with room to spare.
const MaxPublicKeySize = 2048

// RSA modulus bounds. They exclude keys too small to trust and bound the
// work of verification; they are this package's policy, not a COSE rule.
const (
	minRSABits = 2048
	maxRSABits = 8192
)

// COSE_Key parameter labels (RFC 9052 §7.1, RFC 9053 §7, RFC 8230 §4).
const (
	labelKeyType   = 1
	labelKeyID     = 2
	labelAlgorithm = 3
	labelCurve     = -1 // EC2 and OKP crv; RSA n
	labelX         = -2 // EC2 and OKP x; RSA e
	labelY         = -3 // EC2 y; RSA d, the first private parameter
)

// keyLabels lists the parameters each key type may carry in a public
// COSE_Key. The common kid (RFC 9052 §7.1) is also accepted; every other
// label, including key_ops and all private parameters, is rejected.
var keyLabels = map[KeyType][]int64{
	KeyTypeEC2: {labelKeyType, labelAlgorithm, labelCurve, labelX, labelY},
	KeyTypeOKP: {labelKeyType, labelAlgorithm, labelCurve, labelX},
	KeyTypeRSA: {labelKeyType, labelAlgorithm, labelCurve, labelX},
}

// decoder rejects tags and any encoding but RFC 8949 core deterministic
// encoding, which for COSE_Key labels is also CTAP2 canonical CBOR.
func decoder() cbor.DecoderOptions {
	return cbor.DecoderOptions{
		MaxNestedLevels: 2, MaxMapPairs: 8,
		MaxStringBytes: MaxPublicKeySize, MaxBytes: MaxPublicKeySize, MaxEncodedBytes: MaxPublicKeySize,
		RejectTags: true, RequireDeterministic: true,
	}
}

// ParsePublicKey decodes a COSE_Key public key and returns it with the
// algorithm its alg parameter names. The key is an [*ecdsa.PublicKey],
// [ed25519.PublicKey] or [*rsa.PublicKey] that does not alias encoded.
//
// The encoding must be canonical CBOR ([RFC 8949 §4.2.1]) without tags, of
// at most [MaxPublicKeySize] bytes, and must hold exactly the public
// parameters its key type defines ([RFC 9053 §7.1.1], [RFC 9053 §7.2],
// [RFC 8230 §4]) plus, optionally, a byte-string kid, which is ignored. The
// alg parameter is required, and the key type and curve must be the ones
// that algorithm uses, as [Algorithm.Descriptor] reports:
//
//   - an EC2 key holds an uncompressed point on its curve;
//   - an OKP key holds a 32-byte Ed25519 x;
//   - an RSA key holds a minimal odd modulus of 2048 to 8192 bits and a
//     minimal odd exponent from 3 to 2^31-1.
//
// A key that names an algorithm or curve this package does not implement,
// such as Ed448, fails with [ErrUnsupported]. Any other key this package
// rejects fails with [ErrFormat].
//
// [RFC 8949 §4.2.1]: https://www.rfc-editor.org/rfc/rfc8949.html#section-4.2.1
// [RFC 9053 §7.1.1]: https://www.rfc-editor.org/rfc/rfc9053.html#section-7.1.1
// [RFC 9053 §7.2]: https://www.rfc-editor.org/rfc/rfc9053.html#section-7.2
// [RFC 8230 §4]: https://www.rfc-editor.org/rfc/rfc8230.html#section-4
func ParsePublicKey(encoded []byte) (crypto.PublicKey, Algorithm, error) {
	if len(encoded) == 0 || len(encoded) > MaxPublicKeySize || encoded[0]>>5 != 5 {
		return nil, 0, fmt.Errorf("%w: COSE_Key is not a CBOR map of at most %d bytes", ErrFormat, MaxPublicKeySize)
	}
	var fields map[int64]cbor.RawMessage
	if err := decoder().Unmarshal(encoded, &fields); err != nil {
		return nil, 0, fmt.Errorf("%w: COSE_Key is not canonical CBOR with integer labels: %v", ErrFormat, err)
	}
	kty, errKty := integer(fields, labelKeyType)
	alg, errAlg := integer(fields, labelAlgorithm)
	if errKty != nil || errAlg != nil {
		return nil, 0, fmt.Errorf("%w: COSE_Key needs an integer kty and alg", ErrFormat)
	}
	algorithm := Algorithm(alg)
	d, ok := algorithm.Descriptor()
	if !ok {
		return nil, 0, fmt.Errorf("%w: COSE_Key algorithm %v", ErrUnsupported, algorithm)
	}
	if KeyType(kty) != d.KeyType {
		return nil, 0, fmt.Errorf("%w: COSE_Key type %v does not match algorithm %v", ErrFormat, KeyType(kty), algorithm)
	}
	if err := checkLabels(fields, d.KeyType); err != nil {
		return nil, 0, err
	}
	var key crypto.PublicKey
	var err error
	switch d.KeyType {
	case KeyTypeEC2:
		key, err = parseEC2(fields, d)
	case KeyTypeOKP:
		key, err = parseOKP(fields, d)
	case KeyTypeRSA:
		key, err = parseRSA(fields)
	}
	if err != nil {
		return nil, 0, err
	}
	return key, algorithm, nil
}

// checkLabels rejects private and unknown parameters, and a kid that is
// not a byte string.
func checkLabels(fields map[int64]cbor.RawMessage, kty KeyType) error {
	allowed := keyLabels[kty]
	for label, raw := range fields {
		switch {
		case label == labelKeyID:
			if len(raw) == 0 || raw[0]>>5 != 2 {
				return fmt.Errorf("%w: COSE_Key kid is not a byte string", ErrFormat)
			}
		case contains(allowed, label):
		case private(kty, label):
			return fmt.Errorf("%w: COSE_Key holds private key parameter %d", ErrFormat, label)
		default:
			return fmt.Errorf("%w: COSE_Key has parameter %d, which a public %v key does not define", ErrFormat, label, kty)
		}
	}
	return nil
}

// private reports whether label is a private key parameter of kty: d for
// EC2 and OKP (RFC 9053 §7.1.1, §7.2), and d through t_i for RSA
// (RFC 8230 §4).
func private(kty KeyType, label int64) bool {
	if kty == KeyTypeRSA {
		return label <= -3 && label >= -12
	}
	return label == -4
}

func contains(labels []int64, label int64) bool {
	return slices.Contains(labels, label)
}

// integer decodes a required integer parameter.
func integer(fields map[int64]cbor.RawMessage, label int64) (int64, error) {
	raw, ok := fields[label]
	if !ok || len(raw) == 0 || raw[0]>>5 > 1 {
		return 0, ErrFormat
	}
	var value int64
	if err := decoder().Unmarshal(raw, &value); err != nil {
		return 0, ErrFormat
	}
	return value, nil
}

// byteString decodes a required byte-string parameter.
func byteString(fields map[int64]cbor.RawMessage, label int64) ([]byte, error) {
	raw, ok := fields[label]
	if !ok || len(raw) == 0 || raw[0]>>5 != 2 {
		return nil, ErrFormat
	}
	var value []byte
	if err := decoder().Unmarshal(raw, &value); err != nil {
		return nil, ErrFormat
	}
	return bytes.Clone(value), nil
}

// curveOf checks the crv parameter against the algorithm's curve.
func curveOf(fields map[int64]cbor.RawMessage, d Descriptor) error {
	crv, err := integer(fields, labelCurve)
	if err != nil {
		return fmt.Errorf("%w: %v key needs an integer crv", ErrFormat, d.KeyType)
	}
	switch curve := Curve(crv); {
	case curve == d.Curve:
		return nil
	case curve.implemented():
		return fmt.Errorf("%w: curve %v does not match algorithm %v", ErrFormat, curve, d.Algorithm)
	default:
		return fmt.Errorf("%w: %v key with curve %v", ErrUnsupported, d.KeyType, curve)
	}
}

// ellipticCurve returns the curve an EC2 algorithm uses.
func ellipticCurve(curve Curve) elliptic.Curve {
	switch curve {
	case CurveP256:
		return elliptic.P256()
	case CurveP384:
		return elliptic.P384()
	case CurveP521:
		return elliptic.P521()
	}
	return nil
}

func parseEC2(fields map[int64]cbor.RawMessage, d Descriptor) (crypto.PublicKey, error) {
	if err := curveOf(fields, d); err != nil {
		return nil, err
	}
	curve := ellipticCurve(d.Curve)
	size := (curve.Params().BitSize + 7) / 8
	x, errX := byteString(fields, labelX)
	// A boolean y is the compressed form, which CTAP and WebAuthn forbid.
	y, errY := byteString(fields, labelY)
	if errX != nil || errY != nil || len(x) != size || len(y) != size {
		return nil, fmt.Errorf("%w: EC2 key needs uncompressed %d-byte x and y", ErrFormat, size)
	}
	point := make([]byte, 0, 1+2*size)
	point = append(append(append(point, 4), x...), y...)
	key, err := ecdsa.ParseUncompressedPublicKey(curve, point)
	if err != nil {
		return nil, fmt.Errorf("%w: EC2 point is not on %v", ErrFormat, d.Curve)
	}
	return key, nil
}

func parseOKP(fields map[int64]cbor.RawMessage, d Descriptor) (crypto.PublicKey, error) {
	if err := curveOf(fields, d); err != nil {
		return nil, err
	}
	x, err := byteString(fields, labelX)
	if err != nil || len(x) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: Ed25519 key needs a %d-byte x", ErrFormat, ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(x), nil
}

func parseRSA(fields map[int64]cbor.RawMessage) (crypto.PublicKey, error) {
	n, errN := byteString(fields, labelCurve)
	e, errE := byteString(fields, labelX)
	if errN != nil || errE != nil {
		return nil, fmt.Errorf("%w: RSA key needs byte-string n and e", ErrFormat)
	}
	if len(n) == 0 || n[0] == 0 || len(e) == 0 || e[0] == 0 || len(e) > 4 {
		return nil, fmt.Errorf("%w: RSA n and e must be minimal big-endian integers", ErrFormat)
	}
	var exponent int64
	for _, b := range e {
		exponent = exponent<<8 | int64(b)
	}
	key := &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(exponent)}
	if err := checkRSA(key); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrFormat, err)
	}
	return key, nil
}

// checkRSA applies the RSA key bounds.
func checkRSA(key *rsa.PublicKey) error {
	if bits := key.N.BitLen(); bits < minRSABits || bits > maxRSABits || key.N.Bit(0) == 0 {
		return fmt.Errorf("RSA modulus must be odd and %d to %d bits", minRSABits, maxRSABits)
	}
	if key.E < 3 || key.E > 1<<31-1 || key.E%2 == 0 {
		return fmt.Errorf("RSA exponent must be odd and from 3 to 2^31-1")
	}
	return nil
}

// MarshalPublicKey encodes pub as a canonical COSE_Key for alg, which
// [ParsePublicKey] decodes to an equal key and the same algorithm. It
// writes exactly kty, alg and the key type's public parameters, without a
// kid.
//
// pub must be the key type alg uses: an [*ecdsa.PublicKey] on the
// algorithm's curve, an [ed25519.PublicKey], or an [*rsa.PublicKey] within
// the bounds [ParsePublicKey] accepts. Any other key fails with
// [ErrInvalidInput], and an algorithm this package does not implement with
// [ErrUnsupported].
func MarshalPublicKey(pub crypto.PublicKey, alg Algorithm) ([]byte, error) {
	d, ok := alg.Descriptor()
	if !ok {
		return nil, fmt.Errorf("%w: algorithm %v", ErrUnsupported, alg)
	}
	var fields map[int64]any
	switch d.KeyType {
	case KeyTypeEC2:
		key, ok := pub.(*ecdsa.PublicKey)
		if !ok || key == nil || key.Curve != ellipticCurve(d.Curve) || key.X == nil || key.Y == nil {
			return nil, fmt.Errorf("%w: %v needs a %v ECDSA public key", ErrInvalidInput, alg, d.Curve)
		}
		point, err := key.Bytes()
		if err != nil {
			return nil, fmt.Errorf("%w: ECDSA public key is not a point on %v", ErrInvalidInput, d.Curve)
		}
		size := (len(point) - 1) / 2
		fields = map[int64]any{labelKeyType: int64(d.KeyType), labelAlgorithm: int64(alg), labelCurve: int64(d.Curve),
			labelX: point[1 : 1+size], labelY: point[1+size:]}
	case KeyTypeOKP:
		key, ok := pub.(ed25519.PublicKey)
		if !ok || len(key) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("%w: %v needs a %d-byte Ed25519 public key", ErrInvalidInput, alg, ed25519.PublicKeySize)
		}
		fields = map[int64]any{labelKeyType: int64(d.KeyType), labelAlgorithm: int64(alg), labelCurve: int64(d.Curve),
			labelX: []byte(key)}
	case KeyTypeRSA:
		key, ok := pub.(*rsa.PublicKey)
		if !ok || key == nil || key.N == nil {
			return nil, fmt.Errorf("%w: %v needs an RSA public key", ErrInvalidInput, alg)
		}
		if err := checkRSA(key); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidInput, err)
		}
		fields = map[int64]any{labelKeyType: int64(d.KeyType), labelAlgorithm: int64(alg),
			labelCurve: key.N.Bytes(), labelX: big.NewInt(int64(key.E)).Bytes()}
	}
	encoded, err := cbor.CoreDeterministicEncoding().Marshal(fields)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidInput, err)
	}
	return encoded, nil
}
