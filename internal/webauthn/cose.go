package webauthn

import (
	"crypto"
	"errors"
	"fmt"

	"github.com/picatz/doh/internal/cose"
)

// PublicKey is a parsed COSE credential public key. Key is an
// *ecdsa.PublicKey, ed25519.PublicKey or *rsa.PublicKey.
type PublicKey struct {
	Algorithm cose.Algorithm
	Key       crypto.PublicKey
}

// ParsePublicKey parses a COSE_Key credential public key with
// [cose.ParsePublicKey], which applies the WebAuthn Level 3 key rules and
// more: ES256 and ESP256 keys are uncompressed P-256 points, ES384 and
// ESP384 P-384, ES512 and ESP512 P-521, EdDSA and Ed25519 keys use the
// Ed25519 curve, and RSA keys have a 2048–8192-bit odd modulus and an odd
// exponent from 3 to 2^31-1. Points are checked to be on the curve. The
// encoding must be canonical CBOR, and keys that carry private or unknown
// parameters are rejected.
//
// A well-formed key with an algorithm or curve this package does not
// verify, such as Ed448, fails with [ErrUnsupported]; anything else invalid
// fails with [ErrMalformed]. Both errors also match the [cose] sentinel. The
// result does not alias encoded.
//
// https://www.w3.org/TR/webauthn-3/#sctn-encoded-credPubKey-examples
func ParsePublicKey(encoded []byte) (*PublicKey, error) {
	key, algorithm, err := cose.ParsePublicKey(encoded)
	switch {
	case errors.Is(err, cose.ErrUnsupported):
		return nil, fmt.Errorf("%w: %w", ErrUnsupported, err)
	case err != nil:
		return nil, fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	return &PublicKey{Algorithm: algorithm, Key: key}, nil
}

// Verify checks signature over message with the key and its algorithm.
// ECDSA signatures are ASN.1 DER, as WebAuthn specifies:
// https://www.w3.org/TR/webauthn-3/#sctn-signature-attestation-types
// It returns [ErrVerification] for a bad signature.
func (k *PublicKey) Verify(message, signature []byte) error {
	if k == nil || !verify(k.Algorithm, k.Key, message, signature) {
		return ErrVerification
	}
	return nil
}

// verify checks a WebAuthn signature with key under algorithm, requiring
// the key type and curve that the algorithm names.
func verify(algorithm cose.Algorithm, key crypto.PublicKey, message, signature []byte) bool {
	return cose.VerifyASN1(key, algorithm, message, signature) == nil
}
