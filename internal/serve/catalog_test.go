package serve

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/picatz/doh/internal/api"
	"github.com/picatz/doh/internal/policy"
	"github.com/picatz/doh/internal/safebrowsing"
)

// catalogFeature returns the catalog's feature id, as s serves it.
func catalogFeature(t *testing.T, s *Server, dataDir, id string) api.Feature {
	t.Helper()
	c := apiClient{t, startAdmin(t, s), token(t, dataDir, ReaderTokenFile)}
	resp, body := c.do(http.MethodGet, "/api/v1/catalog", "")
	var cat api.Catalog
	if err := json.Unmarshal(body, &cat); resp.StatusCode != http.StatusOK || err != nil {
		t.Fatalf("catalog = %d %s", resp.StatusCode, body)
	}
	for _, f := range cat.Features {
		if f.ID == id {
			return f
		}
	}
	t.Fatalf("no feature %q in %+v", id, cat.Features)
	return api.Feature{}
}

// The web UI offers Safe Browsing only where the server can apply it.
func TestCatalog_SaysWhenSafeBrowsingIsUnavailable(t *testing.T) {
	up, _ := startZone(t, nil)
	pol := &policy.Policy{Profiles: []policy.Profile{{ID: "default"}}}

	s, dataDir := newPolicyServer(t, up, pol)
	if f := catalogFeature(t, s, dataDir, "safe_browsing"); f.Unavailable == "" {
		t.Errorf("without a key, safe_browsing = %+v, want it unavailable, saying why", f)
	}
	if f := catalogFeature(t, s, dataDir, "typosquatting"); f.Unavailable != "" {
		t.Errorf("typosquatting = %+v, want it available", f)
	}

	s, dataDir = newPolicyServer(t, up, pol)
	checker, err := safebrowsing.New(safebrowsing.Options{Key: "test-key", BaseURL: "http://127.0.0.1:1"})
	if err != nil {
		t.Fatal(err)
	}
	s.browsing = checker
	if f := catalogFeature(t, s, dataDir, "safe_browsing"); f.Unavailable != "" {
		t.Errorf("with a key, safe_browsing = %+v, want it available", f)
	}
}
