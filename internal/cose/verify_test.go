package cose

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"testing"
)

// signatures returns signer's signature of message under algorithm in the
// COSE encoding and in the ASN.1 DER encoding, which differ only for ECDSA.
func signatures(t testing.TB, signer crypto.Signer, algorithm Algorithm, message []byte) (cose, der []byte) {
	t.Helper()
	d, _ := algorithm.Descriptor()
	var opts crypto.SignerOpts = d.Hash
	if d.pss {
		opts = &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: d.Hash}
	}
	signature, err := crypto.SignMessage(signer, rand.Reader, message, opts)
	if err != nil {
		t.Fatal(err)
	}
	key, ok := signer.(*ecdsa.PrivateKey)
	if !ok {
		return signature, signature
	}
	raw, err := rawECDSA(signature, (key.Curve.Params().BitSize+7)/8)
	if err != nil {
		t.Fatal(err)
	}
	return raw, signature
}

// rawECDSA converts an ASN.1 DER ECDSA signature to COSE's r||s.
func rawECDSA(der []byte, size int) ([]byte, error) {
	var parsed struct{ R, S *big.Int }
	if rest, err := asn1.Unmarshal(der, &parsed); err != nil || len(rest) != 0 {
		return nil, fmt.Errorf("malformed ECDSA signature: %v", err)
	}
	raw := make([]byte, 2*size)
	parsed.R.FillBytes(raw[:size])
	parsed.S.FillBytes(raw[size:])
	return raw, nil
}

func TestVerify(t *testing.T) {
	message := []byte("authenticator data || client data hash")
	for _, d := range descriptors {
		t.Run(d.Name, func(t *testing.T) {
			signer := signerFor(t, d.Algorithm)
			public := signer.Public()
			cose, der := signatures(t, signer, d.Algorithm, message)
			if err := Verify(public, d.Algorithm, message, cose); err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if err := VerifyASN1(public, d.Algorithm, message, der); err != nil {
				t.Fatalf("VerifyASN1: %v", err)
			}
			tampered := append([]byte(nil), message...)
			tampered[0] ^= 1
			reject := map[string]error{
				"tampered message":       Verify(public, d.Algorithm, tampered, cose),
				"tampered message (DER)": VerifyASN1(public, d.Algorithm, tampered, der),
				"empty signature":        Verify(public, d.Algorithm, message, nil),
				"truncated signature":    Verify(public, d.Algorithm, message, cose[:len(cose)-1]),
				"nil key":                Verify(nil, d.Algorithm, message, cose),
				"key of another type":    Verify("key", d.Algorithm, message, cose),
			}
			if d.KeyType == KeyTypeEC2 {
				reject["DER to Verify"] = Verify(public, d.Algorithm, message, der)
				reject["raw to VerifyASN1"] = VerifyASN1(public, d.Algorithm, message, cose)
			}
			for name, err := range reject {
				if !errors.Is(err, ErrVerification) {
					t.Errorf("%s: %v, want ErrVerification", name, err)
				}
			}
		})
	}
}

// TestVerifyRequiresKeyForAlgorithm checks that a valid signature verifies
// only under an algorithm that uses its key's type, curve and hash.
func TestVerifyRequiresKeyForAlgorithm(t *testing.T) {
	message := []byte("message")
	for _, signed := range descriptors {
		signer := signerFor(t, signed.Algorithm)
		cose, der := signatures(t, signer, signed.Algorithm, message)
		for _, other := range descriptors {
			same := other.KeyType == signed.KeyType && other.Curve == signed.Curve && other.Hash == signed.Hash && other.pss == signed.pss
			errCOSE := Verify(signer.Public(), other.Algorithm, message, cose)
			errDER := VerifyASN1(signer.Public(), other.Algorithm, message, der)
			if same != (errCOSE == nil) || same != (errDER == nil) {
				t.Errorf("signed with %v, verified as %v: %v, %v", signed.Name, other.Name, errCOSE, errDER)
			}
		}
	}
}

func TestVerifyRejectsUnimplementedAlgorithm(t *testing.T) {
	signer := testKeys()[CurveEd25519]
	signature := ed25519.Sign(signer.(ed25519.PrivateKey), nil)
	for _, algorithm := range []Algorithm{-53, -48, 0} {
		if err := Verify(signer.Public(), algorithm, nil, signature); !errors.Is(err, ErrUnsupported) {
			t.Errorf("Verify(%v) = %v, want ErrUnsupported", algorithm, err)
		}
	}
}

func TestVerifyRejectsRSAOutsideBounds(t *testing.T) {
	key := smallRSA()
	message := []byte("message")
	_, signature := signatures(t, key, AlgorithmRS256, message)
	if err := Verify(&key.PublicKey, AlgorithmRS256, message, signature); !errors.Is(err, ErrVerification) {
		t.Fatalf("1024-bit RSA: %v, want ErrVerification", err)
	}
}

// TestVerifyRFC8032 checks Ed25519 against RFC 8032 §7.1 TEST 1, through the
// encoded key.
func TestVerifyRFC8032(t *testing.T) {
	public, _ := hex.DecodeString("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
	signature, _ := hex.DecodeString("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
	encoded, err := MarshalPublicKey(ed25519.PublicKey(public), AlgorithmEd25519)
	if err != nil {
		t.Fatal(err)
	}
	key, algorithm, err := ParsePublicKey(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(key, algorithm, nil, signature); err != nil {
		t.Fatalf("RFC 8032 TEST 1: %v", err)
	}
	if err := Verify(key, algorithm, []byte{0}, signature); !errors.Is(err, ErrVerification) {
		t.Fatalf("other message: %v", err)
	}
}
