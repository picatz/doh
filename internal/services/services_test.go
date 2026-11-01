package services

import (
	"strings"
	"testing"
)

func TestCatalog(t *testing.T) {
	ids := map[string]bool{}
	owner := map[string]string{}
	for _, s := range Catalog {
		if s.ID == "" || s.Name == "" || len(s.Domains) == 0 || ids[s.ID] {
			t.Errorf("bad service %+v", s)
		}
		ids[s.ID] = true

		switch s.Category {
		case CategorySocial, CategoryVideo, CategoryGaming, CategoryMessaging:
		default:
			t.Errorf("%s: unknown category %q", s.ID, s.Category)
		}

		for _, d := range s.Domains {
			if d != strings.ToLower(d) || strings.HasPrefix(d, ".") || strings.HasSuffix(d, ".") || !strings.Contains(d, ".") {
				t.Errorf("%s: malformed domain %q", s.ID, d)
			}
			// Each domain belongs to one service, so blocking one never
			// blocks another by accident.
			if other, ok := owner[d]; ok {
				t.Errorf("%s and %s both list %s", other, s.ID, d)
			}
			owner[d] = s.ID
		}
	}

	// Services mustn't claim domains so broad they'd break unrelated
	// sites.
	for _, shared := range []string{"google.com", "googleapis.com", "gstatic.com", "akamaized.net", "cloudfront.net", "amazonaws.com", "appspot.com", "microsoft.com", "apple.com"} {
		if s, ok := owner[shared]; ok {
			t.Errorf("%s lists the shared domain %s", s, shared)
		}
	}
}

func TestLookupAndDomains(t *testing.T) {
	if s, ok := Lookup("roblox"); !ok || s.Name != "Roblox" {
		t.Errorf("Lookup(roblox) = %+v, %v", s, ok)
	}
	if _, ok := Lookup("nope"); ok {
		t.Error("found an unknown service")
	}
	d := Domains("x", "nope", "WHATSAPP")
	if len(d) != 7 || d[0] != "x.com" {
		t.Errorf("Domains = %v", d)
	}
	if len(IDs()) != len(Catalog) {
		t.Error("IDs doesn't list every service")
	}
}
