package cose

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"fmt"
	"math/big"
)

// Verify checks that signature is pub's signature of message under alg, in
// the encoding COSE defines: ECDSA as the big-endian r and s, each padded
// to the curve's size and concatenated ([RFC 9053 §2.1]); EdDSA as RFC 8032
// defines it ([RFC 9053 §2.2]); and RSA as the PKCS #1 signature
// ([RFC 8230 §2], [RFC 8812 §2]). Use [VerifyASN1] for ECDSA signatures in
// ASN.1 DER.
//
// message is the data that was signed, such as a COSE Sig_structure, never
// its digest: Verify applies [Algorithm.Hash] itself. pub must be the key
// type and curve alg uses, as [ParsePublicKey] returns them; an RSA key must
// have a 2048- to 8192-bit modulus.
//
// Verify returns nil for a valid signature, an error matching
// [ErrUnsupported] for an algorithm this package does not implement, and
// one matching [ErrVerification] otherwise, including when pub does not
// suit alg.
//
// [RFC 9053 §2.1]: https://www.rfc-editor.org/rfc/rfc9053.html#section-2.1
// [RFC 9053 §2.2]: https://www.rfc-editor.org/rfc/rfc9053.html#section-2.2
// [RFC 8230 §2]: https://www.rfc-editor.org/rfc/rfc8230.html#section-2
// [RFC 8812 §2]: https://www.rfc-editor.org/rfc/rfc8812.html#section-2
func Verify(pub crypto.PublicKey, alg Algorithm, message, signature []byte) error {
	return verify(pub, alg, message, signature, false)
}

// VerifyASN1 is [Verify] for ECDSA signatures in ASN.1 DER, the encoding
// CTAP authenticators produce and WebAuthn specifies for assertions and
// packed attestation ([WebAuthn signature formats]). For EdDSA and RSA it
// is the same as Verify.
//
// [WebAuthn signature formats]: https://www.w3.org/TR/webauthn-3/#sctn-signature-attestation-types
func VerifyASN1(pub crypto.PublicKey, alg Algorithm, message, signature []byte) error {
	return verify(pub, alg, message, signature, true)
}

func verify(pub crypto.PublicKey, alg Algorithm, message, signature []byte, der bool) error {
	d, ok := alg.Descriptor()
	if !ok {
		return fmt.Errorf("%w: algorithm %v", ErrUnsupported, alg)
	}
	var digest []byte
	if d.Hash != 0 {
		h := d.Hash.New()
		h.Write(message)
		digest = h.Sum(nil)
	}
	valid := false
	switch d.KeyType {
	case KeyTypeEC2:
		key, ok := pub.(*ecdsa.PublicKey)
		if !ok || key == nil || key.Curve != ellipticCurve(d.Curve) || key.X == nil || key.Y == nil {
			break
		}
		if der {
			valid = ecdsa.VerifyASN1(key, digest, signature)
		} else if size := (key.Curve.Params().BitSize + 7) / 8; len(signature) == 2*size {
			r := new(big.Int).SetBytes(signature[:size])
			s := new(big.Int).SetBytes(signature[size:])
			valid = ecdsa.Verify(key, digest, r, s)
		}
	case KeyTypeOKP:
		key, ok := pub.(ed25519.PublicKey)
		valid = ok && len(key) == ed25519.PublicKeySize && ed25519.Verify(key, message, signature)
	case KeyTypeRSA:
		key, ok := pub.(*rsa.PublicKey)
		if !ok || key == nil || key.N == nil || checkRSA(key) != nil {
			break
		}
		if d.pss {
			valid = rsa.VerifyPSS(key, d.Hash, digest, signature, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: d.Hash}) == nil
		} else {
			valid = rsa.VerifyPKCS1v15(key, d.Hash, digest, signature) == nil
		}
	}
	if !valid {
		return fmt.Errorf("%w: %v", ErrVerification, alg)
	}
	return nil
}
