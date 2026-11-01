package services_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/picatz/doh/internal/policy"
	"github.com/picatz/doh/internal/services"
)

func TestCatalog(t *testing.T) {
	ids := map[string]bool{}
	owner := map[string]string{}
	for _, s := range services.Catalog {
		if s.ID == "" || s.Name == "" || len(s.Domains) == 0 || ids[s.ID] {
			t.Errorf("bad service %+v", s)
		}
		ids[s.ID] = true

		if !slices.Contains(services.Categories, s.Category) {
			t.Errorf("%s: unknown category %q", s.ID, s.Category)
		}
		if !policy.ValidID(s.ID) {
			t.Errorf("%s: not a valid ID", s.ID)
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
	for _, shared := range []string{"google.com", "googleapis.com", "gstatic.com", "akamaized.net", "cloudfront.net", "amazonaws.com", "appspot.com", "microsoft.com", "apple.com", "openai.com", "qq.com", "amazon.com", "meta.com", "bytedance.com", "alicdn.com"} {
		if s, ok := owner[shared]; ok {
			t.Errorf("%s lists the shared domain %s", s, shared)
		}
	}
}

// TestCatalog_Grouped checks the catalog lists each category's services
// together, in the order of Categories, as they're presented.
func TestCatalog_Grouped(t *testing.T) {
	last := -1
	for _, s := range services.Catalog {
		i := slices.Index(services.Categories, s.Category)
		if i < last {
			t.Errorf("%s (%s) is out of category order", s.ID, s.Category)
		}
		last = i
	}
	for _, c := range services.Categories {
		if !slices.ContainsFunc(services.Catalog, func(s services.Service) bool { return s.Category == c }) {
			t.Errorf("category %s has no services", c)
		}
	}
}

func TestLookupAndDomains(t *testing.T) {
	if s, ok := services.Lookup("roblox"); !ok || s.Name != "Roblox" {
		t.Errorf("Lookup(roblox) = %+v, %v", s, ok)
	}
	if _, ok := services.Lookup("nope"); ok {
		t.Error("found an unknown service")
	}
	d := services.Domains("x", "nope", "WHATSAPP")
	if len(d) != 7 || d[0] != "x.com" {
		t.Errorf("Domains = %v", d)
	}
	if len(services.IDs()) != len(services.Catalog) {
		t.Error("IDs doesn't list every service")
	}
}
