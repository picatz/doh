package webauthn

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"errors"
	"testing"

	"github.com/picatz/cbor"
	"github.com/picatz/doh/internal/cose"
)

func encodeCOSE(t *testing.T, fields map[int]any) []byte {
	t.Helper()
	data, err := cbor.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestParsePublicKey(t *testing.T) {
	p256 := fixedP256(t, "cose")
	point, _ := p256.PublicKey.Bytes()
	x, y := point[1:33], point[33:]
	edPublic := fixedEd25519("cose").Public().(ed25519.PublicKey)
	offCurve := append([]byte(nil), y...)
	offCurve[31] ^= 1

	good := map[string]map[int]any{
		"ES256":   {1: 2, 3: -7, -1: 1, -2: x, -3: y},
		"ESP256":  {1: 2, 3: -9, -1: 1, -2: x, -3: y},
		"EdDSA":   {1: 1, 3: -8, -1: 6, -2: []byte(edPublic)},
		"Ed25519": {1: 1, 3: -19, -1: 6, -2: []byte(edPublic)},
		"kid":     {1: 2, 3: -7, -1: 1, -2: x, -3: y, 2: []byte("key id")},
	}
	for name, fields := range good {
		key, err := ParsePublicKey(encodeCOSE(t, fields))
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if key.Algorithm.String() != name && name != "kid" {
			t.Errorf("%s: algorithm %v", name, key.Algorithm)
		}
	}

	malformed := map[string]map[int]any{
		"private-ec":         {1: 2, 3: -7, -1: 1, -2: x, -3: y, -4: []byte{1}},
		"private-okp":        {1: 1, 3: -8, -1: 6, -2: []byte(edPublic), -4: []byte{1}},
		"es256-on-p384":      {1: 2, 3: -7, -1: 2, -2: x, -3: y},
		"es384-on-p256":      {1: 2, 3: -35, -1: 1, -2: x, -3: y},
		"off-curve":          {1: 2, 3: -7, -1: 1, -2: x, -3: offCurve},
		"compressed":         {1: 2, 3: -7, -1: 1, -2: x, -3: true},
		"short-x":            {1: 2, 3: -7, -1: 1, -2: x[1:], -3: y},
		"missing-alg":        {1: 2, -1: 1, -2: x, -3: y},
		"text-alg":           {1: 2, 3: "ES256", -1: 1, -2: x, -3: y},
		"ed25519-short":      {1: 1, 3: -8, -1: 6, -2: []byte(edPublic)[1:]},
		"rsa-small":          {1: 3, 3: -257, -1: make([]byte, 128), -2: []byte{1, 0, 1}},
		"rsa-private":        {1: 3, 3: -257, -1: []byte{1}, -2: []byte{1, 0, 1}, -3: []byte{1}},
		"rsa-leading-zero-e": {1: 3, 3: -257, -1: append([]byte{0x80}, make([]byte, 255)...), -2: []byte{0, 1, 0, 1}},
	}
	for name, fields := range malformed {
		if _, err := ParsePublicKey(encodeCOSE(t, fields)); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: error = %v, want ErrMalformed", name, err)
		}
	}
	unsupported := map[string]map[int]any{
		"ed448":     {1: 1, 3: -53, -1: 7, -2: make([]byte, 57)},
		"x25519":    {1: 1, 3: -8, -1: 4, -2: make([]byte, 32)},
		"symmetric": {1: 4, 3: 5, -1: make([]byte, 32)},
		"p256k":     {1: 2, 3: -47, -1: 8, -2: x, -3: y},
		"rs1":       {1: 3, 3: -65535, -1: make([]byte, 256), -2: []byte{1, 0, 1}},
	}
	for name, fields := range unsupported {
		if _, err := ParsePublicKey(encodeCOSE(t, fields)); !errors.Is(err, ErrUnsupported) || !errors.Is(err, errors.ErrUnsupported) {
			t.Errorf("%s: error = %v, want ErrUnsupported", name, err)
		}
	}
	for _, raw := range [][]byte{nil, {0x80}, {0xa1, 0x01}, append([]byte{0xa1, 0x01, 0x59, 0x10, 0x00}, make([]byte, 4096)...)} {
		if _, err := ParsePublicKey(raw); !errors.Is(err, ErrMalformed) {
			t.Errorf("ParsePublicKey(%x...) = %v", raw[:min(len(raw), 8)], err)
		}
	}
}

func TestVerifyRequiresMatchingKeyAndAlgorithm(t *testing.T) {
	p256 := fixedP256(t, "verify")
	message := []byte("message")
	a := &softAuthenticator{signer: p256}
	signature := a.sign(t, message)
	key := &PublicKey{Algorithm: cose.AlgorithmES256, Key: &p256.PublicKey}
	if key.Verify(message, signature) != nil {
		t.Fatal("valid signature rejected")
	}
	for _, alg := range []cose.Algorithm{cose.AlgorithmES384, cose.AlgorithmEdDSA, cose.AlgorithmRS256} {
		if (&PublicKey{Algorithm: alg, Key: &p256.PublicKey}).Verify(message, signature) == nil {
			t.Errorf("signature accepted under %v", alg)
		}
	}
	p384 := &ecdsa.PublicKey{Curve: elliptic.P384()}
	if verify(cose.AlgorithmES256, p384, message, signature) {
		t.Error("P-384 key accepted for ES256")
	}
	var nilKey *PublicKey
	if nilKey.Verify(message, signature) == nil {
		t.Error("nil key verified")
	}
}
