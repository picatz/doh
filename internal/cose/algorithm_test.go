package cose

import (
	"crypto"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// TestAlgorithmRegistry pins every implemented identifier to its IANA COSE
// Algorithms registry value and checks its descriptor.
func TestAlgorithmRegistry(t *testing.T) {
	for _, test := range []struct {
		algorithm Algorithm
		value     int64
		name      string
		keyType   KeyType
		curve     Curve
		hash      crypto.Hash
		full      bool
	}{
		{AlgorithmES256, -7, "ES256", KeyTypeEC2, CurveP256, crypto.SHA256, false},
		{AlgorithmEdDSA, -8, "EdDSA", KeyTypeOKP, CurveEd25519, 0, false},
		{AlgorithmESP256, -9, "ESP256", KeyTypeEC2, CurveP256, crypto.SHA256, true},
		{AlgorithmEd25519, -19, "Ed25519", KeyTypeOKP, CurveEd25519, 0, true},
		{AlgorithmES384, -35, "ES384", KeyTypeEC2, CurveP384, crypto.SHA384, false},
		{AlgorithmES512, -36, "ES512", KeyTypeEC2, CurveP521, crypto.SHA512, false},
		{AlgorithmPS256, -37, "PS256", KeyTypeRSA, 0, crypto.SHA256, true},
		{AlgorithmESP384, -51, "ESP384", KeyTypeEC2, CurveP384, crypto.SHA384, true},
		{AlgorithmESP512, -52, "ESP512", KeyTypeEC2, CurveP521, crypto.SHA512, true},
		{AlgorithmRS256, -257, "RS256", KeyTypeRSA, 0, crypto.SHA256, true},
		{AlgorithmRS384, -258, "RS384", KeyTypeRSA, 0, crypto.SHA384, true},
		{AlgorithmRS512, -259, "RS512", KeyTypeRSA, 0, crypto.SHA512, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if int64(test.algorithm) != test.value {
				t.Fatalf("value = %d, want %d", test.algorithm, test.value)
			}
			d, ok := test.algorithm.Descriptor()
			if !ok || d.Algorithm != test.algorithm || d.Name != test.name || d.KeyType != test.keyType ||
				d.Curve != test.curve || d.Hash != test.hash || d.FullySpecified != test.full ||
				!strings.HasPrefix(d.Specification, "https://www.rfc-editor.org/rfc/rfc") {
				t.Fatalf("Descriptor = %+v, %v", d, ok)
			}
			if test.algorithm.String() != test.name || test.algorithm.Hash() != test.hash || test.algorithm.Available() != nil {
				t.Fatalf("String, Hash, Available = %v, %v, %v", test.algorithm, test.algorithm.Hash(), test.algorithm.Available())
			}
		})
	}
	if len(descriptors) != 12 {
		t.Fatalf("descriptor table has %d entries; add a registry row above for each", len(descriptors))
	}
}

func TestAlgorithmUnimplemented(t *testing.T) {
	// ML-DSA-44, Ed448, ES256K, PS384, RS1, an unassigned value and zero.
	for _, algorithm := range []Algorithm{-48, -53, -47, -38, -65535, 7, 0} {
		if _, ok := algorithm.Descriptor(); ok {
			t.Errorf("%d has a descriptor", algorithm)
		}
		if err := algorithm.Available(); !errors.Is(err, ErrUnsupported) || !errors.Is(err, errors.ErrUnsupported) {
			t.Errorf("Available(%d) = %v", algorithm, err)
		}
		if algorithm.Hash() != 0 || !strings.HasPrefix(algorithm.String(), "Algorithm(") {
			t.Errorf("%d: Hash %v, String %q", algorithm, algorithm.Hash(), algorithm.String())
		}
	}
	if got := Algorithm(-48).String(); got != "Algorithm(-48)" {
		t.Errorf("String = %q", got)
	}
}

func TestAlgorithmText(t *testing.T) {
	for _, algorithm := range []Algorithm{AlgorithmES256, AlgorithmEd25519, AlgorithmRS512, -48, 0, 1 << 62, -1 << 63} {
		text, err := algorithm.MarshalText()
		if err != nil {
			t.Fatal(err)
		}
		var parsed Algorithm
		if err := parsed.UnmarshalText(text); err != nil || parsed != algorithm {
			t.Errorf("%d: %q parsed to %d, %v", algorithm, text, parsed, err)
		}
	}
	for text, want := range map[string]Algorithm{"ES256": AlgorithmES256, "ESP384": AlgorithmESP384, "-7": AlgorithmES256, "-48": -48, "0": 0} {
		var parsed Algorithm
		if err := parsed.UnmarshalText([]byte(text)); err != nil || parsed != want {
			t.Errorf("UnmarshalText(%q) = %d, %v; want %d", text, parsed, err, want)
		}
	}
	for _, text := range []string{"", "es256", " ES256", "ES256 ", "+7", "-07", "-0", "0x10", "ES256\x00", "Algorithm(-48)", "9223372036854775808", strings.Repeat("9", 100)} {
		parsed := AlgorithmEdDSA
		err := parsed.UnmarshalText([]byte(text))
		if !errors.Is(err, ErrFormat) || parsed != AlgorithmEdDSA {
			t.Errorf("UnmarshalText(%q) = %d, %v; want ErrFormat and no change", text, parsed, err)
		}
		if len(err.Error()) > 100 {
			t.Errorf("error message repeats long input: %d bytes", len(err.Error()))
		}
	}
}

func TestAlgorithmJSON(t *testing.T) {
	type parameter struct {
		Type      string    `json:"type"`
		Algorithm Algorithm `json:"alg"`
	}
	encoded, err := json.Marshal([]parameter{{"public-key", AlgorithmES256}, {"public-key", -48}})
	if err != nil || string(encoded) != `[{"type":"public-key","alg":-7},{"type":"public-key","alg":-48}]` {
		t.Fatalf("json.Marshal = %s, %v", encoded, err)
	}
	var decoded []parameter
	if err := json.Unmarshal([]byte(`[{"alg":-9},{"alg":-257}]`), &decoded); err != nil ||
		decoded[0].Algorithm != AlgorithmESP256 || decoded[1].Algorithm != AlgorithmRS256 {
		t.Fatalf("json.Unmarshal = %v, %v", decoded, err)
	}
	kept := parameter{Algorithm: AlgorithmEdDSA}
	if err := json.Unmarshal([]byte(`{"alg":null}`), &kept); err != nil || kept.Algorithm != AlgorithmEdDSA {
		t.Fatalf("null changed the value: %v, %v", kept, err)
	}
	for _, input := range []string{`{"alg":"ES256"}`, `{"alg":-7.0}`, `{"alg":-7e0}`, `{"alg":true}`, `{"alg":9223372036854775808}`} {
		var p parameter
		if err := json.Unmarshal([]byte(input), &p); !errors.Is(err, ErrFormat) {
			t.Errorf("json.Unmarshal(%s) = %v; want ErrFormat", input, err)
		}
	}
}

func TestKeyTypeAndCurveString(t *testing.T) {
	for value, want := range map[interface{ String() string }]string{
		KeyTypeOKP: "OKP", KeyTypeEC2: "EC2", KeyTypeRSA: "RSA", KeyType(4): "KeyType(4)",
		CurveP256: "P-256", CurveP384: "P-384", CurveP521: "P-521", CurveEd25519: "Ed25519", Curve(7): "Curve(7)",
	} {
		if got := value.String(); got != want {
			t.Errorf("String = %q, want %q", got, want)
		}
	}
}
