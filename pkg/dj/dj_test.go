package dj_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/picatz/doh/pkg/dj"
)

// requireLiveNetwork skips the test unless DOH_LIVE_TESTS is set, since
// public DoH resolvers are not reliably reachable from CI runners.
func requireLiveNetwork(t *testing.T) {
	t.Helper()

	if os.Getenv("DOH_LIVE_TESTS") == "" {
		t.Skip("skipping live network test; set DOH_LIVE_TESTS=1 to enable")
	}
}

func TestQuery(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got, want := r.Header.Get("Accept"), "application/dns-json"; got != want {
			t.Errorf("got Accept header %q, want %q", got, want)
		}

		if got, want := r.URL.Query().Get("name"), "example.com"; got != want {
			t.Errorf("got name %q, want %q", got, want)
		}

		if got, want := r.URL.Query().Get("type"), "A"; got != want {
			t.Errorf("got type %q, want %q", got, want)
		}

		w.Header().Set("Content-Type", "application/dns-json")

		err := json.NewEncoder(w).Encode(map[string]any{
			"Status": 0,
			"RD":     true,
			"RA":     true,
			"Question": []map[string]any{
				{"name": "example.com.", "type": 1},
			},
			"Answer": []map[string]any{
				{"name": "example.com.", "type": 1, "TTL": 60, "data": "192.0.2.1"},
			},
		})
		if err != nil {
			t.Error(err)
		}
	}))
	t.Cleanup(server.Close)

	resp, err := dj.Query(t.Context(), server.Client(), server.URL, &dj.Request{
		Name: "example.com",
		Type: "A",
	})
	if err != nil {
		t.Fatal(err)
	}

	if !resp.RD || !resp.RA {
		t.Errorf("got RD=%t RA=%t, want both true", resp.RD, resp.RA)
	}

	if len(resp.Answer) != 1 {
		t.Fatalf("got %d answers, want 1", len(resp.Answer))
	}

	if got, want := resp.Answer[0].Data, "192.0.2.1"; got != want {
		t.Errorf("got answer data %q, want %q", got, want)
	}
}

func TestQuery_Live(t *testing.T) {
	requireLiveNetwork(t)

	client := http.DefaultClient

	tests := []struct {
		name   string
		server string
		domain string
	}{
		{name: "google", server: dj.Google, domain: "google.com"},
		{name: "cloudflare", server: dj.Cloudflare, domain: "cloudflare.com"},
		{name: "quad9", server: dj.Quad9, domain: "yahoo.com"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resp, err := dj.Query(t.Context(), client, test.server, &dj.Request{
				Name: test.domain,
				Type: "A",
			})
			if err != nil {
				t.Fatal(err)
			}

			if len(resp.Answer) == 0 {
				t.Error("got no answer for known domain")
			}
		})
	}
}
