package cose

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"errors"
	"maps"
	"math/big"
	"sync"
	"testing"

	"github.com/picatz/cbor"
)

// Test keys are generated once; RSA generation is slow.
var (
	testKeys = sync.OnceValue(func() map[Curve]crypto.Signer {
		keys := map[Curve]crypto.Signer{}
		for curve, ec := range map[Curve]elliptic.Curve{CurveP256: elliptic.P256(), CurveP384: elliptic.P384(), CurveP521: elliptic.P521()} {
			key, err := ecdsa.GenerateKey(ec, rand.Reader)
			if err != nil {
				panic(err)
			}
			keys[curve] = key
		}
		keys[CurveEd25519] = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}
		keys[0] = key
		return keys
	})
	// smallRSA is below the 2048-bit minimum.
	smallRSA = sync.OnceValue(func() *rsa.PrivateKey {
		key, err := rsa.GenerateKey(rand.Reader, 1024)
		if err != nil {
			panic(err)
		}
		return key
	})
)

// signerFor returns the test key an implemented algorithm uses.
func signerFor(t testing.TB, algorithm Algorithm) crypto.Signer {
	t.Helper()
	d, ok := algorithm.Descriptor()
	if !ok {
		t.Fatalf("no descriptor for %v", algorithm)
	}
	return testKeys()[d.Curve]
}

func encode(t testing.TB, fields map[int64]any) []byte {
	t.Helper()
	encoded, err := cbor.CoreDeterministicEncoding().Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

type equaler interface{ Equal(crypto.PublicKey) bool }

func TestPublicKeyRoundTrip(t *testing.T) {
	for _, d := range descriptors {
		t.Run(d.Name, func(t *testing.T) {
			public := signerFor(t, d.Algorithm).Public()
			encoded, err := MarshalPublicKey(public, d.Algorithm)
			if err != nil {
				t.Fatal(err)
			}
			parsed, algorithm, err := ParsePublicKey(encoded)
			if err != nil || algorithm != d.Algorithm {
				t.Fatalf("ParsePublicKey = %v, %v", algorithm, err)
			}
			if !parsed.(equaler).Equal(public) {
				t.Fatal("parsed key differs")
			}
			again, err := MarshalPublicKey(parsed, algorithm)
			if err != nil || !bytes.Equal(again, encoded) {
				t.Fatalf("re-encoding differs: %x, %v", again, err)
			}
		})
	}
}

// TestMarshalPublicKeyEd25519 pins the exact encoding of the RFC 8032 §7.1
// TEST 1 public key.
func TestMarshalPublicKeyEd25519(t *testing.T) {
	public, _ := hex.DecodeString("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
	encoded, err := MarshalPublicKey(ed25519.PublicKey(public), AlgorithmEdDSA)
	if err != nil {
		t.Fatal(err)
	}
	// {1: 1, 3: -8, -1: 6, -2: h'd75a...'} in deterministic order.
	want := "a4010103272006215820d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
	if hex.EncodeToString(encoded) != want {
		t.Fatalf("encoding = %x, want %s", encoded, want)
	}
}

func TestParsePublicKeyAcceptsKeyID(t *testing.T) {
	p256 := testKeys()[CurveP256].Public().(*ecdsa.PublicKey)
	point, _ := p256.Bytes()
	fields := map[int64]any{1: 2, 2: []byte("key id"), 3: -7, -1: 1, -2: point[1:33], -3: point[33:]}
	public, algorithm, err := ParsePublicKey(encode(t, fields))
	if err != nil || algorithm != AlgorithmES256 || !public.(equaler).Equal(p256) {
		t.Fatalf("ParsePublicKey = %v, %v", algorithm, err)
	}
}

func TestParsePublicKeyRejects(t *testing.T) {
	p256 := testKeys()[CurveP256].Public().(*ecdsa.PublicKey)
	point, _ := p256.Bytes()
	x, y := point[1:33], point[33:]
	edPublic := []byte(testKeys()[CurveEd25519].Public().(ed25519.PublicKey))
	rsaPublic := testKeys()[0].Public().(*rsa.PublicKey)
	n, e := rsaPublic.N.Bytes(), big.NewInt(int64(rsaPublic.E)).Bytes()
	offCurve := bytes.Clone(y)
	offCurve[31] ^= 1
	ec2 := map[int64]any{1: 2, 3: -7, -1: 1, -2: x, -3: y}
	okp := map[int64]any{1: 1, 3: -8, -1: 6, -2: edPublic}
	rsaKey := map[int64]any{1: 3, 3: -257, -1: n, -2: e}
	with := func(base map[int64]any, change func(map[int64]any)) []byte {
		fields := map[int64]any{}
		maps.Copy(fields, base)
		change(fields)
		return encode(t, fields)
	}
	valid := encode(t, okp)
	unsorted := append([]byte{0xa4, 0x03, 0x27, 0x01, 0x01}, valid[5:]...)
	nonMinimal := append([]byte{0xa4, 0x18, 0x01}, valid[2:]...)
	indefinite := append(append([]byte{0xbf}, valid[1:]...), 0xff)
	duplicate := append([]byte{0xa5, 0x01, 0x01}, valid[1:]...)
	textLabel := append([]byte{0xa5, 0x61, 'a', 0x01}, valid[1:]...)

	for _, test := range []struct {
		name    string
		encoded []byte
		want    error
	}{
		// Not a bounded canonical CBOR map.
		{"empty", nil, ErrFormat},
		{"not a map", []byte{0x01}, ErrFormat},
		{"array", []byte{0x80}, ErrFormat},
		{"truncated", []byte{0xa1, 0x01}, ErrFormat},
		{"oversized", append([]byte{0xa1, 0x01, 0x59, 0x10, 0x00}, make([]byte, 4096)...), ErrFormat},
		{"tagged", append([]byte{0xc0}, valid...), ErrFormat},
		{"trailing data", append(bytes.Clone(valid), 0x00), ErrFormat},
		{"unsorted labels", unsorted, ErrFormat},
		{"non-minimal label", nonMinimal, ErrFormat},
		{"indefinite length", indefinite, ErrFormat},
		{"duplicate label", duplicate, ErrFormat},
		{"text label", textLabel, ErrFormat},
		// Missing, mistyped, extra or private parameters.
		{"missing alg", with(ec2, func(f map[int64]any) { delete(f, 3) }), ErrFormat},
		{"missing kty", with(ec2, func(f map[int64]any) { delete(f, 1) }), ErrFormat},
		{"text alg", with(ec2, func(f map[int64]any) { f[3] = "ES256" }), ErrFormat},
		{"text kty", with(ec2, func(f map[int64]any) { f[1] = "EC2" }), ErrFormat},
		{"missing crv", with(ec2, func(f map[int64]any) { delete(f, -1) }), ErrFormat},
		{"missing y", with(ec2, func(f map[int64]any) { delete(f, -3) }), ErrFormat},
		{"compressed y", with(ec2, func(f map[int64]any) { f[-3] = true }), ErrFormat},
		{"text x", with(ec2, func(f map[int64]any) { f[-2] = "x" }), ErrFormat},
		{"short x", with(ec2, func(f map[int64]any) { f[-2] = x[1:] }), ErrFormat},
		{"key_ops", with(ec2, func(f map[int64]any) { f[4] = []any{2} }), ErrFormat},
		{"unknown parameter", with(ec2, func(f map[int64]any) { f[-5] = 1 }), ErrFormat},
		{"text kid", with(ec2, func(f map[int64]any) { f[2] = "kid" }), ErrFormat},
		{"EC2 private key", with(ec2, func(f map[int64]any) { f[-4] = []byte{1} }), ErrFormat},
		{"OKP private key", with(okp, func(f map[int64]any) { f[-4] = []byte{1} }), ErrFormat},
		{"OKP y", with(okp, func(f map[int64]any) { f[-3] = []byte{1} }), ErrFormat},
		{"RSA private key", with(rsaKey, func(f map[int64]any) { f[-3] = []byte{1} }), ErrFormat},
		{"RSA prime", with(rsaKey, func(f map[int64]any) { f[-5] = []byte{1} }), ErrFormat},
		// Points and sizes.
		{"off curve", with(ec2, func(f map[int64]any) { f[-3] = offCurve }), ErrFormat},
		{"identity", with(ec2, func(f map[int64]any) { f[-2], f[-3] = make([]byte, 32), make([]byte, 32) }), ErrFormat},
		{"Ed25519 short", with(okp, func(f map[int64]any) { f[-2] = edPublic[1:] }), ErrFormat},
		{"RSA small", with(rsaKey, func(f map[int64]any) { f[-1] = smallRSA().N.Bytes() }), ErrFormat},
		{"RSA even modulus", with(rsaKey, func(f map[int64]any) { m := bytes.Clone(n); m[len(m)-1] &^= 1; f[-1] = m }), ErrFormat},
		{"RSA leading zero n", with(rsaKey, func(f map[int64]any) { f[-1] = append([]byte{0}, n...) }), ErrFormat},
		{"RSA leading zero e", with(rsaKey, func(f map[int64]any) { f[-2] = []byte{0, 1, 0, 1} }), ErrFormat},
		{"RSA even exponent", with(rsaKey, func(f map[int64]any) { f[-2] = []byte{2} }), ErrFormat},
		{"RSA exponent 1", with(rsaKey, func(f map[int64]any) { f[-2] = []byte{1} }), ErrFormat},
		{"RSA exponent too large", with(rsaKey, func(f map[int64]any) { f[-2] = []byte{1, 0, 0, 0, 1} }), ErrFormat},
		{"RSA integer n", with(rsaKey, func(f map[int64]any) { f[-1] = 3 }), ErrFormat},
		// Key type and curve that the algorithm does not use.
		{"ES256 on P-384", with(ec2, func(f map[int64]any) { f[-1] = 2 }), ErrFormat},
		{"ES384 with a P-256 key", with(ec2, func(f map[int64]any) { f[3] = -35 }), ErrFormat},
		{"ESP256 on P-521", with(ec2, func(f map[int64]any) { f[3] = -9; f[-1] = 3 }), ErrFormat},
		{"EC2 on Ed25519", with(ec2, func(f map[int64]any) { f[-1] = 6 }), ErrFormat},
		{"EdDSA with EC2 key type", with(okp, func(f map[int64]any) { f[1] = 2 }), ErrFormat},
		{"ES256 with OKP key type", with(ec2, func(f map[int64]any) { f[1] = 1 }), ErrFormat},
		{"ES256 with RSA key type", with(rsaKey, func(f map[int64]any) { f[3] = -7 }), ErrFormat},
		{"RS256 with EC2 key type", with(ec2, func(f map[int64]any) { f[3] = -257 }), ErrFormat},
		{"ES256 with symmetric key type", with(ec2, func(f map[int64]any) { f[1] = 4 }), ErrFormat},
		{"OKP on P-256", with(okp, func(f map[int64]any) { f[-1] = 1 }), ErrFormat},
		// Algorithms and curves this package does not implement.
		{"Ed448", encode(t, map[int64]any{1: 1, 3: -53, -1: 7, -2: make([]byte, 57)}), ErrUnsupported},
		{"EdDSA on Ed448", with(okp, func(f map[int64]any) { f[-1] = 7; f[-2] = make([]byte, 57) }), ErrUnsupported},
		{"EdDSA on X25519", with(okp, func(f map[int64]any) { f[-1] = 4 }), ErrUnsupported},
		{"ES256K", with(ec2, func(f map[int64]any) { f[3] = -47; f[-1] = 8 }), ErrUnsupported},
		{"ES256 on secp256k1", with(ec2, func(f map[int64]any) { f[-1] = 8 }), ErrUnsupported},
		{"PS384", with(rsaKey, func(f map[int64]any) { f[3] = -38 }), ErrUnsupported},
		{"RS1", with(rsaKey, func(f map[int64]any) { f[3] = -65535 }), ErrUnsupported},
		{"ML-DSA-44", encode(t, map[int64]any{1: 7, 3: -48, -1: make([]byte, 32)}), ErrUnsupported},
		{"symmetric", encode(t, map[int64]any{1: 4, 3: 5, -1: make([]byte, 32)}), ErrUnsupported},
	} {
		t.Run(test.name, func(t *testing.T) {
			public, algorithm, err := ParsePublicKey(test.encoded)
			if public != nil || algorithm != 0 || !errors.Is(err, test.want) {
				t.Fatalf("ParsePublicKey = %v, %v, %v; want %v", public, algorithm, err, test.want)
			}
			if test.want == ErrUnsupported && !errors.Is(err, errors.ErrUnsupported) {
				t.Fatal("ErrUnsupported does not match errors.ErrUnsupported")
			}
		})
	}
}

func TestParsePublicKeyDoesNotAlias(t *testing.T) {
	for _, algorithm := range []Algorithm{AlgorithmEdDSA, AlgorithmES256, AlgorithmRS256} {
		public := signerFor(t, algorithm).Public()
		encoded, err := MarshalPublicKey(public, algorithm)
		if err != nil {
			t.Fatal(err)
		}
		parsed, _, err := ParsePublicKey(encoded)
		if err != nil {
			t.Fatal(err)
		}
		clear(encoded)
		if !parsed.(equaler).Equal(public) {
			t.Fatalf("%v: parsed key aliases its input", algorithm)
		}
	}
}

func TestMarshalPublicKeyRejects(t *testing.T) {
	p256 := testKeys()[CurveP256].Public()
	p521 := testKeys()[CurveP521].Public()
	edPublic := testKeys()[CurveEd25519].Public()
	rsaPublic := testKeys()[0].Public().(*rsa.PublicKey)
	for _, test := range []struct {
		name      string
		public    crypto.PublicKey
		algorithm Algorithm
		want      error
	}{
		{"unimplemented algorithm", p256, -48, ErrUnsupported},
		{"nil", nil, AlgorithmES256, ErrInvalidInput},
		{"nil ECDSA", (*ecdsa.PublicKey)(nil), AlgorithmES256, ErrInvalidInput},
		{"wrong curve", p521, AlgorithmES256, ErrInvalidInput},
		{"wrong key type", edPublic, AlgorithmES256, ErrInvalidInput},
		{"RSA for EdDSA", rsaPublic, AlgorithmEdDSA, ErrInvalidInput},
		{"ECDSA for RS256", p256, AlgorithmRS256, ErrInvalidInput},
		{"missing point", &ecdsa.PublicKey{Curve: elliptic.P256()}, AlgorithmES256, ErrInvalidInput},
		{"off curve", &ecdsa.PublicKey{Curve: elliptic.P256(), X: big.NewInt(1), Y: big.NewInt(1)}, AlgorithmES256, ErrInvalidInput},
		{"short Ed25519", ed25519.PublicKey(make([]byte, 31)), AlgorithmEdDSA, ErrInvalidInput},
		{"pointer to Ed25519", &edPublic, AlgorithmEdDSA, ErrInvalidInput},
		{"small RSA", &smallRSA().PublicKey, AlgorithmRS256, ErrInvalidInput},
		{"RSA without modulus", &rsa.PublicKey{E: 65537}, AlgorithmRS256, ErrInvalidInput},
		{"RSA even exponent", &rsa.PublicKey{N: rsaPublic.N, E: 65536}, AlgorithmRS256, ErrInvalidInput},
	} {
		t.Run(test.name, func(t *testing.T) {
			if encoded, err := MarshalPublicKey(test.public, test.algorithm); encoded != nil || !errors.Is(err, test.want) {
				t.Fatalf("MarshalPublicKey = %x, %v; want %v", encoded, err, test.want)
			}
		})
	}
}
