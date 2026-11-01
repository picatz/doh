package cose

import (
	"bytes"
	"errors"
	"testing"

	"github.com/picatz/cbor"
)

// FuzzParsePublicKey checks that ParsePublicKey returns a whole result or
// a categorized error, and that every accepted key re-encodes to exactly its
// input, less a kid.
func FuzzParsePublicKey(f *testing.F) {
	for _, d := range descriptors {
		encoded, err := MarshalPublicKey(signerFor(f, d.Algorithm).Public(), d.Algorithm)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(encoded)
	}
	f.Add([]byte{0xa5, 0x01, 0x01, 0x02, 0x41, 0x00, 0x03, 0x27, 0x20, 0x06, 0x21, 0x58, 0x20})
	f.Fuzz(func(t *testing.T, data []byte) {
		public, algorithm, err := ParsePublicKey(data)
		if err != nil {
			if public != nil || algorithm != 0 {
				t.Fatal("partial result on error")
			}
			if !errors.Is(err, ErrFormat) && !errors.Is(err, ErrUnsupported) {
				t.Fatalf("uncategorized error: %v", err)
			}
			return
		}
		again, err := MarshalPublicKey(public, algorithm)
		if err != nil {
			t.Fatalf("accepted key does not encode: %v", err)
		}
		if !bytes.Equal(again, data) {
			var fields map[int64]cbor.RawMessage
			if decoder().Unmarshal(data, &fields) != nil || fields[labelKeyID] == nil {
				t.Fatalf("accepted key re-encodes differently:\n%x\n%x", data, again)
			}
		}
		reparsed, realgorithm, err := ParsePublicKey(again)
		if err != nil || realgorithm != algorithm || !reparsed.(equaler).Equal(public) {
			t.Fatal("round trip changed the key")
		}
	})
}

// FuzzVerify checks that Verify and VerifyASN1 never panic, return only
// categorized errors, accept a signature only for a key their algorithm
// uses, and reject it for any other message.
func FuzzVerify(f *testing.F) {
	message := []byte("seed message")
	for _, d := range descriptors {
		cose, der := signatures(f, signerFor(f, d.Algorithm), d.Algorithm, message)
		f.Add(int64(d.Algorithm), uint8(d.Curve), message, cose)
		f.Add(int64(d.Algorithm), uint8(d.Curve), message, der)
	}
	f.Add(int64(-48), uint8(0), message, []byte{})
	curves := []Curve{0, CurveP256, CurveP384, CurveP521, CurveEd25519}
	f.Fuzz(func(t *testing.T, alg int64, key uint8, message, signature []byte) {
		algorithm := Algorithm(alg)
		public := testKeys()[curves[int(key)%len(curves)]].Public()
		for _, check := range []func(any, Algorithm, []byte, []byte) error{
			func(p any, a Algorithm, m, s []byte) error { return Verify(p, a, m, s) },
			func(p any, a Algorithm, m, s []byte) error { return VerifyASN1(p, a, m, s) },
		} {
			err := check(public, algorithm, message, signature)
			if err != nil {
				if !errors.Is(err, ErrVerification) && !errors.Is(err, ErrUnsupported) {
					t.Fatalf("uncategorized error: %v", err)
				}
				continue
			}
			d, _ := algorithm.Descriptor()
			if d.Curve != curves[int(key)%len(curves)] {
				t.Fatalf("%v accepted a %v key", algorithm, curves[int(key)%len(curves)])
			}
			if check(public, algorithm, append(bytes.Clone(message), 0), signature) == nil {
				t.Fatal("signature verified for another message")
			}
		}
	})
}
