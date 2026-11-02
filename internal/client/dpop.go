package client

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/picatz/jose/pkg/dpop"
	"github.com/picatz/jose/pkg/jwa"
)

// DPoP keys ([RFC 9449]) are kept as PEM: a PKCS #8 "PRIVATE KEY" block,
// as [MarshalDPoPKey] writes and openssl genpkey makes, or a SEC 1 "EC
// PRIVATE KEY" block, as older openssl commands make.
//
// [RFC 9449]: https://www.rfc-editor.org/rfc/rfc9449.html

// minRSABits is the smallest RSA key accepted for DPoP.
const minRSABits = 2048

// GenerateDPoPKey returns a new ECDSA P-256 key, for proofs signed with
// ES256.
func GenerateDPoPKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// NewDPoPSigner returns a signer of DPoP proofs with key, using the
// algorithm a doh server accepts for it: ES256 for ECDSA P-256, EdDSA for
// Ed25519, and RS256 for RSA of at least 2048 bits. Other keys are
// refused.
func NewDPoPSigner(key crypto.Signer) (*dpop.Signer, error) {
	var opts []dpop.SignerOption
	switch k := key.Public().(type) {
	case *ecdsa.PublicKey:
		if k.Curve != elliptic.P256() {
			return nil, fmt.Errorf("doh: a DPoP ECDSA key must use P-256, not %s", k.Curve.Params().Name)
		}
	case ed25519.PublicKey:
	case *rsa.PublicKey:
		if k.N.BitLen() < minRSABits {
			return nil, fmt.Errorf("doh: a DPoP RSA key must have at least %d bits", minRSABits)
		}
		opts = append(opts, dpop.WithAlgorithm(jwa.RS256))
	default:
		return nil, fmt.Errorf("doh: a DPoP key must be ECDSA P-256, Ed25519, or RSA, not %T", k)
	}
	return dpop.NewSigner(key, opts...)
}

// MarshalDPoPKey encodes key as a PEM "PRIVATE KEY" block (PKCS #8).
func MarshalDPoPKey(key crypto.Signer) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("doh: encoding the DPoP key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// ParseDPoPKey decodes a DPoP key from PEM, as [MarshalDPoPKey] encodes
// it, or a SEC 1 "EC PRIVATE KEY" block, and returns a signer of proofs
// with it, as [NewDPoPSigner] does. "EC PARAMETERS" blocks, which openssl
// ecparam writes before the key, are skipped; anything else besides one
// key is refused.
func ParseDPoPKey(b []byte) (*dpop.Signer, error) {
	var block *pem.Block
	for rest := b; len(bytes.TrimSpace(rest)) > 0; {
		var next *pem.Block
		if next, rest = pem.Decode(rest); next == nil {
			return nil, errors.New("doh: the DPoP key isn't PEM encoded")
		}
		switch {
		case next.Type == "EC PARAMETERS":
		case block != nil:
			return nil, errors.New("doh: the DPoP key file holds more than one key")
		default:
			block = next
		}
	}
	if block == nil {
		return nil, errors.New("doh: the DPoP key file holds no key")
	}

	var (
		key any
		err error
	)
	switch block.Type {
	case "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("doh: the DPoP key is a PEM %q block; want PRIVATE KEY or EC PRIVATE KEY", block.Type)
	}
	if err != nil {
		return nil, fmt.Errorf("doh: parsing the DPoP key: %w", err)
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("doh: a %T can't sign DPoP proofs", key)
	}
	return NewDPoPSigner(signer)
}
