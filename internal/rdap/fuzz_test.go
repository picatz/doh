package rdap

import (
	"strings"
	"testing"
	"time"
)

// FuzzParseBootstrap parses IANA bootstrap registries, as fetched from
// the network: it must never panic, and every service it keeps must map
// a non-empty, lower-case TLD without dots at its ends to an absolute
// URL of an allowed scheme, ending in a slash.
func FuzzParseBootstrap(f *testing.F) {
	f.Add([]byte(`{"version":"1.0","services":[[["com","net"],["https://rdap.verisign.com/com/v1/"]],[["org"],["http://rdap.org/","https://rdap.org"]]]}`), false)
	f.Add([]byte(`{"services":[[["COM."],["ftp://x/","//no-scheme/"]],[["a"]],[]]}`), true)
	f.Add([]byte(`{"services":null}`), false)
	f.Add([]byte(`[]`), false)
	f.Fuzz(func(t *testing.T, body []byte, allowHTTP bool) {
		services, err := parseBootstrap(body, allowHTTP)
		if err != nil {
			return
		}
		if len(services) == 0 {
			t.Fatal("no services, but no error")
		}
		for tld, u := range services {
			if tld == "" || tld != strings.ToLower(tld) || strings.HasPrefix(tld, ".") || strings.HasSuffix(tld, ".") {
				t.Fatalf("TLD %q", tld)
			}
			if u == nil || u.Host == "" || !strings.HasSuffix(u.Path, "/") || !schemeAllowed(u, allowHTTP) {
				t.Fatalf("base URL %v for %q", u, tld)
			}
		}
	})
}

// FuzzParseRegistration parses RDAP domain objects: it must never panic,
// and a registration date it returns must be plausible: after 1985 and
// at most a day ahead.
func FuzzParseRegistration(f *testing.F) {
	f.Add([]byte(`{"events":[{"eventAction":"registration","eventDate":"2024-01-02T03:04:05Z"}]}`))
	f.Add([]byte(`{"events":[{"eventAction":"last changed","eventDate":"x"},{"eventAction":"REGISTRATION","eventDate":"1984-12-31T23:59:59Z"}]}`))
	f.Add([]byte(`{"events":[{"eventAction":"registration","eventDate":"9999-12-31T23:59:59+14:00"}]}`))
	f.Add([]byte(`{}`))
	now := time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC)
	f.Fuzz(func(t *testing.T, body []byte) {
		reg, err := parseRegistration(body, now)
		if err != nil {
			return
		}
		if reg.Before(earliestRegistration) || reg.After(now.Add(24*time.Hour)) || reg.Location() != time.UTC {
			t.Fatalf("implausible registration %v", reg)
		}
	})
}

// FuzzNormalize checks the domains looked up: normalized ones are
// normalized.
func FuzzNormalize(f *testing.F) {
	for _, s := range []string{"Example.COM.", "xn--pple-43d.com", "a..b", "", "_x.example", strings.Repeat("a", 300)} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		d, err := normalize(s)
		if err != nil {
			return
		}
		if again, err := normalize(d); err != nil || again != d {
			t.Fatalf("normalize(%q) = %q, then %q, %v", s, d, again, err)
		}
	})
}
