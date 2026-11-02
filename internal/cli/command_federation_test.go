package cli

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/picatz/doh/internal/api"
	"github.com/picatz/doh/internal/serviceaccount"
	"github.com/spf13/cobra"
)

func trustResponses(now time.Time) map[string]any {
	responses := serviceAccountResponses(now)
	rule := serviceaccount.TrustRule{
		ID:       "3f2a9c0d1e4b5a67",
		Issuer:   githubIssuer,
		Audience: "https://dns.example.com",
		Subject:  "repo:octo/app:ref:refs/heads/main",
		Claims:   map[string]string{"repository_id": "123456", "environment": "prod"},
	}
	responses["GET /api/v1/service-accounts/ciiiiiiiiiiiiiii/federation"] = api.TrustRules{Rules: []serviceaccount.TrustRule{rule}}
	responses["GET /api/v1/service-accounts/haaaaaaaaaaaaaaa/federation"] = api.TrustRules{Rules: []serviceaccount.TrustRule{}}
	responses["POST /api/v1/service-accounts/ciiiiiiiiiiiiiii/federation"] = rule
	responses["DELETE /api/v1/service-accounts/ciiiiiiiiiiiiiii/federation/3f2a9c0d1e4b5a67"] = struct{}{}
	return responses
}

func TestTrustCommands(t *testing.T) {
	responses := trustResponses(time.Now())

	t.Run("add a GitHub repository", func(t *testing.T) {
		out, f, err := runClient(t, newServiceAccountCommand(), responses, "sa", "trust", "add", "CI",
			"--github-repo", "octo/app", "--audience", "https://dns.example.com", "--claim", "repository_id=123456", "--token-lifetime", "30m")
		if err != nil {
			t.Fatal(err)
		}
		var req api.TrustRuleRequest
		if err := json.Unmarshal([]byte(f.bodies[len(f.bodies)-1]), &req); err != nil {
			t.Fatal(err)
		}
		if req.Issuer != githubIssuer || req.Subject != "repo:octo/app:ref:refs/heads/main" || req.Audience != "https://dns.example.com" ||
			req.Claims["repository_id"] != "123456" || req.TokenLifetime != 1800 || req.JWKSURL != "" {
			t.Errorf("request = %+v", req)
		}
		if !strings.Contains(out, "rule 3f2a9c0d1e4b5a67") || !strings.Contains(out, "doh token exchange --account ciiiiiiiiiiiiiii") {
			t.Errorf("add output:\n%s", out)
		}
	})

	t.Run("add with a ref wildcard", func(t *testing.T) {
		_, f, err := runClient(t, newServiceAccountCommand(), responses, "sa", "trust", "add", "CI", "--github-repo", "octo/app", "--github-ref", "refs/heads/*")
		if err != nil {
			t.Fatal(err)
		}
		var req api.TrustRuleRequest
		if err := json.Unmarshal([]byte(f.bodies[len(f.bodies)-1]), &req); err != nil || req.Subject != "repo:octo/app:ref:refs/heads/*" || req.Audience != "" {
			t.Errorf("request = %s", f.bodies[len(f.bodies)-1])
		}
	})

	t.Run("add any issuer", func(t *testing.T) {
		_, f, err := runClient(t, newServiceAccountCommand(), responses, "sa", "trust", "add", "CI",
			"--issuer", "https://k8s.example", "--subject", "system:serviceaccount:ci:deployer", "--audience", "doh", "--jwks-url", "https://k8s.example/openid/v1/jwks")
		if err != nil {
			t.Fatal(err)
		}
		var req api.TrustRuleRequest
		if err := json.Unmarshal([]byte(f.bodies[len(f.bodies)-1]), &req); err != nil || req.Issuer != "https://k8s.example" || req.JWKSURL != "https://k8s.example/openid/v1/jwks" || req.Subject != "system:serviceaccount:ci:deployer" {
			t.Errorf("request = %s", f.bodies[len(f.bodies)-1])
		}
	})

	t.Run("list", func(t *testing.T) {
		out, _, err := runClient(t, newServiceAccountCommand(), responses, "sa", "trust", "list", "CI")
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{"3f2a9c0d1e4b5a67", githubIssuer, "repo:octo/app:ref:refs/heads/main", "environment=prod,repository_id=123456", "15m0s"} {
			if !strings.Contains(out, want) {
				t.Errorf("list lacks %q:\n%s", want, out)
			}
		}
		out, _, err = runClient(t, newServiceAccountCommand(), responses, "sa", "trust", "list", "Home Assistant")
		if err != nil || !strings.Contains(out, "trusts no workloads") {
			t.Errorf("empty list = %q, %v", out, err)
		}
	})

	t.Run("remove", func(t *testing.T) {
		out, _, err := runClient(t, newServiceAccountCommand(), responses, "sa", "trust", "remove", "ci", "3f2a9c0d1e4b5a67")
		if err != nil || !strings.Contains(out, "no longer work") {
			t.Errorf("remove = %q, %v", out, err)
		}
	})

	t.Run("bad flags fail before any request", func(t *testing.T) {
		for _, args := range [][]string{
			{"sa", "trust", "add", "CI"},
			{"sa", "trust", "add", "CI", "--issuer", githubIssuer},
			{"sa", "trust", "add", "CI", "--github-repo", "octo"},
			{"sa", "trust", "add", "CI", "--github-repo", "octo/app/x"},
			{"sa", "trust", "add", "CI", "--github-repo", "octo/app", "--subject", "x"},
			{"sa", "trust", "add", "CI", "--github-ref", "refs/heads/dev", "--issuer", githubIssuer, "--subject", "x"},
			{"sa", "trust", "add", "CI", "--github-repo", "octo/app", "--claim", "novalue"},
			{"sa", "trust", "add", "CI", "--github-repo", "octo/app", "--token-lifetime", "2h"},
			{"sa", "trust", "add", "CI", "--github-repo", "octo/app", "--token-lifetime", "30s"},
		} {
			_, f, err := runClient(t, newServiceAccountCommand(), responses, args...)
			if err == nil || len(f.requests) != 0 {
				t.Errorf("%q: %v after %d requests", args, err, len(f.requests))
			}
		}
	})
}

// runTokenExchange runs "doh token exchange" against handler, with stdin.
func runTokenExchange(t *testing.T, handler http.HandlerFunc, stdin string, args ...string) (string, error) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	root := &cobra.Command{Use: "doh", SilenceErrors: true}
	root.AddCommand(newTokenCommand())
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(io.Discard)
	root.SetIn(strings.NewReader(stdin))
	root.SetArgs(append([]string{"token", "exchange", "--addr", srv.URL}, args...))
	err := root.Execute()
	return out.String(), err
}

func TestTokenExchangeCommand(t *testing.T) {
	var form url.Values
	handler := func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" || r.URL.Path != "/api/v1/token" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_ = r.ParseForm()
		form = r.PostForm
		if r.PostForm.Get("subject_token") != "eyJ.id.token" {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(api.OAuthError{Error: "invalid_grant", Description: "the subject token wasn't accepted"})
			return
		}
		json.NewEncoder(w).Encode(api.TokenResponse{AccessToken: "doh_at_abc", TokenType: "Bearer", IssuedTokenType: api.TokenTypeAccessToken, ExpiresIn: 900})
	}

	path := filepath.Join(t.TempDir(), "id.jwt")
	if err := os.WriteFile(path, []byte("eyJ.id.token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := runTokenExchange(t, handler, "", "--account", "ciiiiiiiiiiiiiii", "--subject-token-file", path)
	if err != nil || out != "doh_at_abc\n" {
		t.Fatalf("exchange = %q, %v", out, err)
	}
	if form.Get("audience") != "ciiiiiiiiiiiiiii" || form.Get("subject_token_type") != api.TokenTypeJWT || form.Get("grant_type") != api.GrantTypeTokenExchange {
		t.Errorf("form = %v", form)
	}

	// From standard input, as an ID token, as JSON.
	out, err = runTokenExchange(t, handler, "eyJ.id.token", "--account", "ciiiiiiiiiiiiiii", "--subject-token-file", "-", "--id-token", "--json")
	var tr api.TokenResponse
	if err != nil || json.Unmarshal([]byte(out), &tr) != nil || tr.ExpiresIn != 900 || form.Get("subject_token_type") != api.TokenTypeIDToken {
		t.Errorf("exchange from stdin = %q, %v", out, err)
	}

	// Refusals say why, as the server put it.
	if _, err := runTokenExchange(t, handler, "forged", "--account", "ciiiiiiiiiiiiiii", "--subject-token-file", "-"); err == nil || !strings.Contains(err.Error(), "invalid_grant") {
		t.Errorf("refused exchange: %v", err)
	}
	if _, err := runTokenExchange(t, handler, " \n", "--account", "ciiiiiiiiiiiiiii", "--subject-token-file", "-"); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Errorf("empty token: %v", err)
	}
	if _, err := runTokenExchange(t, handler, "", "--subject-token-file", path); err == nil {
		t.Error("exchange without --account succeeded")
	}
}
