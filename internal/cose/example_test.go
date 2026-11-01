package cose_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"

	"github.com/picatz/doh/internal/cose"
)

// A relying party stores the COSE_Key an authenticator returned, and later
// parses it to verify an assertion.
func ExampleParsePublicKey() {
	seed := make([]byte, ed25519.SeedSize) // a fixed key, for a stable example
	private := ed25519.NewKeyFromSeed(seed)
	stored, err := cose.MarshalPublicKey(private.Public(), cose.AlgorithmEdDSA)
	if err != nil {
		panic(err)
	}

	public, algorithm, err := cose.ParsePublicKey(stored)
	if err != nil {
		panic(err)
	}
	message := []byte("authenticator data || client data hash")
	signature := ed25519.Sign(private, message)
	fmt.Println(algorithm, cose.VerifyASN1(public, algorithm, message, signature) == nil)
	// Output: EdDSA true
}

func ExampleMarshalPublicKey() {
	seed := make([]byte, ed25519.SeedSize)
	public := ed25519.NewKeyFromSeed(seed).Public()
	encoded, err := cose.MarshalPublicKey(public, cose.AlgorithmEd25519)
	if err != nil {
		panic(err)
	}
	fmt.Printf("%x\n", encoded)
	// Output: a40101033220062158203b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29
}

// Verify takes the message, never a digest. A signer for any implemented
// algorithm is called the same way, with Algorithm.Hash as its options.
func ExampleVerify() {
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	algorithm := cose.AlgorithmESP256
	message := []byte("Sig_structure bytes")
	signature, err := crypto.SignMessage(private, rand.Reader, message, algorithm.Hash())
	if err != nil {
		panic(err)
	}

	// crypto.Signer returns ASN.1 DER for ECDSA, as CTAP authenticators do.
	fmt.Println(cose.VerifyASN1(private.Public(), algorithm, message, signature))
	fmt.Println(cose.VerifyASN1(private.Public(), algorithm, []byte("other"), signature))
	// Output:
	// <nil>
	// cose: signature verification failed: ESP256
}

func ExampleAlgorithm_Descriptor() {
	for _, algorithm := range []cose.Algorithm{cose.AlgorithmES256, cose.AlgorithmESP256, cose.AlgorithmEd25519, cose.AlgorithmPS256} {
		d, _ := algorithm.Descriptor()
		curve, hash := "any size", "none"
		if d.Curve != 0 {
			curve = d.Curve.String()
		}
		if d.Hash != 0 {
			hash = d.Hash.String()
		}
		fmt.Printf("%s: %s key, %s, hash %s, fully specified %t\n", d.Name, d.KeyType, curve, hash, d.FullySpecified)
	}
	// Output:
	// ES256: EC2 key, P-256, hash SHA-256, fully specified false
	// ESP256: EC2 key, P-256, hash SHA-256, fully specified true
	// Ed25519: OKP key, Ed25519, hash none, fully specified true
	// PS256: RSA key, any size, hash SHA-256, fully specified true
}

// An identifier this package does not implement is still a value: it
// formats, encodes and decodes, and Available says it cannot be used.
func ExampleAlgorithm_Available() {
	for _, algorithm := range []cose.Algorithm{cose.AlgorithmES384, -48} {
		fmt.Println(algorithm, algorithm.Available())
	}
	// Output:
	// ES384 <nil>
	// Algorithm(-48) cose: algorithm, key type or curve: unsupported operation: Algorithm(-48)
}

// Text uses registry names, for flags and configuration. JSON uses numbers,
// as WebAuthn's pubKeyCredParams does.
func ExampleAlgorithm_UnmarshalText() {
	var algorithm cose.Algorithm
	if err := algorithm.UnmarshalText([]byte("ESP256")); err != nil {
		panic(err)
	}
	parameters, _ := json.Marshal(map[string]any{"type": "public-key", "alg": algorithm})
	fmt.Println(int64(algorithm), string(parameters))
	// Output: -9 {"alg":-9,"type":"public-key"}
}
