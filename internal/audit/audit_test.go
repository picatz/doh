package audit

import (
	"errors"
	"maps"
	"net/url"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func TestDiff(t *testing.T) {
	type security struct {
		Bypass bool `json:"bypass"`
	}
	type rewrite struct {
		Domain string `json:"domain"`
		To     string `json:"to"`
	}
	type profile struct {
		ID       string    `json:"id"`
		Allow    []string  `json:"allow,omitempty"`
		Services []string  `json:"services,omitempty"`
		Security security  `json:"security"`
		Rewrites []rewrite `json:"rewrites,omitempty"`
		Name     string    `json:"name,omitempty"`
	}
	before := profile{ID: "kids", Services: []string{"tiktok", "fortnite"}, Rewrites: []rewrite{{"nas.lan", "192.168.1.2"}, {"old.lan", "192.168.1.3"}}}
	after := profile{ID: "kids", Allow: []string{"example.com"}, Services: []string{"fortnite", "roblox"},
		Security: security{Bypass: true}, Rewrites: []rewrite{{"nas.lan", "192.168.1.9"}, {"new.lan", "192.168.1.4"}}, Name: "Kids"}

	want := map[string]string{
		"allow.added":      "example.com",
		"services.added":   "roblox",
		"services.removed": "tiktok",
		"security.bypass":  "true",
		"rewrites.added":   "new.lan",
		"rewrites.removed": "old.lan",
		"rewrites.changed": "nas.lan",
		"name":             "Kids",
	}
	if got := Diff(before, after); !maps.Equal(got, want) {
		t.Errorf("Diff:\n got %v\nwant %v", got, want)
	}
	if got := Diff(before, before); len(got) != 0 {
		t.Errorf("Diff of the same = %v", got)
	}
	if got := Diff(make(chan int), before); got[""] != "changed" {
		t.Errorf("Diff of what can't be marshaled = %v", got)
	}
}

func TestNormalize(t *testing.T) {
	long := strings.Repeat("ü", MaxFieldLength)
	details := map[string]string{strings.Repeat("k", 100): "v"}
	for i := range MaxDetails + 5 {
		details[string(rune('a'+i%26))+strings.Repeat("x", i)] = long
	}
	e := Event{Action: long, Tenant: long, Summary: "a\xffb", Actor: Actor{Name: long}, Target: Target{ID: long}, Details: details}.Normalize()
	for name, s := range map[string]string{"action": e.Action, "tenant": e.Tenant, "actor": e.Actor.Name, "target": e.Target.ID} {
		if len(s) > MaxFieldLength || !utf8.ValidString(s) || !strings.HasSuffix(s, "…") {
			t.Errorf("%s: %d bytes, valid %v", name, len(s), utf8.ValidString(s))
		}
	}
	if e.Summary != "a�b" {
		t.Errorf("summary = %q", e.Summary)
	}
	if len(e.Details) != MaxDetails {
		t.Errorf("%d details, want %d", len(e.Details), MaxDetails)
	}
	for k, v := range e.Details {
		if len(k) > MaxKeyLength || len(v) > MaxValueLength || !utf8.ValidString(v) {
			t.Errorf("detail %q: %d bytes", k, len(v))
		}
	}
}

func TestParseFilter(t *testing.T) {
	f, err := ParseFilter(url.Values{"actor": {"Kent"}, "action": {"profile"}, "before": {"2026-11-02T15:04:05Z"}, "limit": {"10"}, "page_token": {EncodePageToken(42)}})
	if err != nil {
		t.Fatal(err)
	}
	if f.Actor != "Kent" || f.Action != "profile" || !f.Before.Equal(time.Date(2026, 11, 2, 15, 4, 5, 0, time.UTC)) || f.PageLimit() != 10 {
		t.Errorf("filter = %+v", f)
	}
	if !f.MatchesAction("profile.updated") || !f.MatchesAction("profile") || f.MatchesAction("profiles") {
		t.Error("MatchesAction")
	}
	if (Filter{}).PageLimit() != DefaultLimit || (Filter{Limit: 5000}).PageLimit() != MaxLimit {
		t.Error("PageLimit defaults")
	}
	for _, v := range []url.Values{
		{"limit": {"0"}}, {"limit": {"1001"}}, {"limit": {"x"}},
		{"before": {"yesterday"}},
		{"actor": {strings.Repeat("a", MaxFieldLength+1)}},
		{"page_token": {"forged"}},
		{"page_token": {EncodePageToken(0)}},
		{"page_token": {strings.Repeat("A", 200)}},
		{"page_token": {"eyJ2IjoyLCJiIjoxfQ"}}, // {"v":2,"b":1}
	} {
		if _, err := ParseFilter(v); !errors.Is(err, ErrInvalidFilter) {
			t.Errorf("ParseFilter(%v) = %v, want ErrInvalidFilter", v, err)
		}
	}
	if seq, err := DecodePageToken(EncodePageToken(7)); err != nil || seq != 7 {
		t.Errorf("round trip = %d, %v", seq, err)
	}
}

func FuzzDecodePageToken(f *testing.F) {
	f.Add(EncodePageToken(1))
	f.Add("")
	f.Fuzz(func(t *testing.T, s string) {
		if seq, err := DecodePageToken(s); err == nil && seq == 0 {
			t.Errorf("DecodePageToken(%q) = 0 without an error", s)
		}
	})
}
