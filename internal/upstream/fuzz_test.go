package upstream

import "testing"

// FuzzParse parses upstream URLs, as flags, config files, and forward
// zones give them: it must never panic, and must refuse what it can't
// use rather than return a nil exchanger.
func FuzzParse(f *testing.F) {
	for _, s := range []string{
		"1.1.1.1", "udp://9.9.9.9:53", "tcp://[2620:fe::fe]", "tls://dns.quad9.net", "tls://1.1.1.1:853#cloudflare-dns.com",
		"https://dns.google/dns-query", "quic://dns.adguard-dns.com", "http://127.0.0.1:8080/dns-query", "ftp://x", "://",
		"udp://:0", "tls://", "https://", "udp://host:99999", "[::1]:53",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		ex, err := Parse(raw, Options{})
		if err == nil && ex == nil {
			t.Fatalf("Parse(%q) = nil, nil", raw)
		}
	})
}
