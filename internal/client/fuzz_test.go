package client

import (
	"strings"
	"testing"

	"github.com/picatz/jose/pkg/dpop"
)

// FuzzEvents parses server-sent event streams, as the server (or anything
// between) sends them: it must never panic, and yields at most one event
// per line. (A lone carriage return, which the format allows as a line
// ending and doh's server never sends, isn't treated as one.)
func FuzzEvents(f *testing.F) {
	f.Add("event: entry\ndata: {\"a\":1}\n\n: keepalive\n\ndata: x\ndata: y\n\n")
	f.Add("data:no-space\r\n\r\nevent\n\ndata\n\n")
	f.Add("data: " + strings.Repeat("x", 100) + "\n")
	f.Fuzz(func(t *testing.T, stream string) {
		n := 0
		for _, err := range events(strings.NewReader(stream)) {
			if err != nil {
				return
			}
			n++
		}
		if n > strings.Count(stream, "\n")+1 {
			t.Fatalf("%d events from %d lines", n, strings.Count(stream, "\n"))
		}
	})
}

// FuzzParseDPoPKey parses DPoP key files: it must never panic, and a key
// it accepts signs proofs.
func FuzzParseDPoPKey(f *testing.F) {
	key, err := GenerateDPoPKey()
	if err != nil {
		f.Fatal(err)
	}
	b, err := MarshalDPoPKey(key)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(b)
	f.Add([]byte("-----BEGIN EC PARAMETERS-----\nBggqhkjOPQMBBw==\n-----END EC PARAMETERS-----\n"))
	f.Add([]byte("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"))
	f.Add([]byte("not pem"))
	f.Fuzz(func(t *testing.T, b []byte) {
		s, err := ParseDPoPKey(b)
		if err != nil {
			return
		}
		if _, err := s.Proof("GET", "https://dns.example.com/api/v1/policy", dpop.ProofOptions{}); err != nil {
			t.Fatalf("an accepted key doesn't sign: %v", err)
		}
	})
}
