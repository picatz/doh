package querylog

import (
	"net/url"
	"testing"
)

// FuzzParseFilter parses the Activity view's query parameters, as any
// reader sends them: it must never panic; a filter it accepts must have a
// valid status and a limit in range; and its page token must decode.
func FuzzParseFilter(f *testing.F) {
	f.Add("profile=kids&status=blocked&since=2026-01-02T03:04:05Z&limit=50&page_token=" + encodeToken(42))
	f.Add("status=bogus&limit=0&until=yesterday&page_token=!!!")
	f.Add("q=%00&limit=999999999999999999999&page_token=eyJ2IjoxLCJiIjowfQ")
	f.Fuzz(func(t *testing.T, query string) {
		v, err := url.ParseQuery(query)
		if err != nil {
			return
		}
		filter, err := ParseFilter(v)
		if err != nil {
			return
		}
		if filter.Status != "" && !filter.Status.valid() {
			t.Fatalf("status %q", filter.Status)
		}
		if filter.Limit < 0 || filter.Limit > MaxLimit {
			t.Fatalf("limit %d", filter.Limit)
		}
		if filter.PageToken != "" {
			if before, err := decodeToken(filter.PageToken); err != nil || before == 0 {
				t.Fatalf("page token %q: %d, %v", filter.PageToken, before, err)
			}
		}
	})
}

// FuzzDecodeToken checks page tokens: what decodes encodes back to a
// token that decodes the same.
func FuzzDecodeToken(f *testing.F) {
	f.Add(encodeToken(1))
	f.Add(encodeToken(^uint64(0)))
	f.Add("eyJ2IjoxLCJiIjotMX0")
	f.Fuzz(func(t *testing.T, s string) {
		before, err := decodeToken(s)
		if err != nil {
			return
		}
		if again, err := decodeToken(encodeToken(before)); err != nil || again != before {
			t.Fatalf("decodeToken(%q) = %d, but re-encoded gives %d, %v", s, before, again, err)
		}
	})
}
