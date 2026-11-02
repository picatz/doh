package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/picatz/doh/internal/api"
	"github.com/picatz/doh/internal/policy"
	"github.com/picatz/doh/internal/querylog"
	"github.com/picatz/doh/internal/serviceaccount"
	"github.com/picatz/doh/internal/signin"
)

func newTestClient(t *testing.T, h http.HandlerFunc) *Client {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return &Client{Addr: srv.URL, Token: "secret"}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func TestClient_SendsTokenAndUserAgent(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer secret" {
			t.Errorf("Authorization = %q", got)
		}
		if got := r.Header.Get("User-Agent"); got != "doh-cli" {
			t.Errorf("User-Agent = %q", got)
		}
		if r.URL.Path != "/api/v1/status" {
			t.Errorf("path = %q", r.URL.Path)
		}
		writeJSON(w, 200, api.Status{Version: "v1.2.3"})
	})

	s, err := c.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if s.Version != "v1.2.3" {
		t.Errorf("Version = %q", s.Version)
	}
}

func TestClient_DecodesErrors(t *testing.T) {
	tests := []struct {
		name    string
		status  int
		body    string
		wantMsg string
	}{
		{"api error", 403, `{"error":"reader tokens can't change the policy"}`, "doh: 403 Forbidden: reader tokens can't change the policy"},
		{"details", 400, `{"error":"invalid policy","details":["a","b"]}`, "doh: 400 Bad Request: invalid policy: a; b"},
		{"plain text", 502, "bad gateway\n", "doh: 502 Bad Gateway: bad gateway"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.status)
				io.WriteString(w, tt.body)
			})
			_, err := c.Status(context.Background())
			var e *Error
			if !errors.As(err, &e) {
				t.Fatalf("err = %v, want *Error", err)
			}
			if e.Status != tt.status {
				t.Errorf("Status = %d", e.Status)
			}
			if err.Error() != tt.wantMsg {
				t.Errorf("Error() = %q, want %q", err.Error(), tt.wantMsg)
			}
		})
	}
}

func TestClient_PatchProfileUsesMergePatch(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPatch || r.URL.Path != "/api/v1/profiles/kids" {
			t.Errorf("%s %s", r.Method, r.URL.Path)
		}
		if ct := r.Header.Get("Content-Type"); ct != api.MergePatchType {
			t.Errorf("Content-Type = %q", ct)
		}
		body, _ := io.ReadAll(r.Body)
		if string(body) != `{"safe_search":true}` {
			t.Errorf("body = %s", body)
		}
		writeJSON(w, 200, policy.Profile{ID: "kids", SafeSearch: true})
	})

	p, err := c.PatchProfile(context.Background(), "kids", map[string]any{"safe_search": true})
	if err != nil {
		t.Fatal(err)
	}
	if !p.SafeSearch {
		t.Error("SafeSearch not set")
	}
}

func TestClient_PolicyETag(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut && r.Header.Get("If-Match") != `"old"` {
			t.Errorf("If-Match = %q", r.Header.Get("If-Match"))
		}
		w.Header().Set("ETag", `"new"`)
		writeJSON(w, 200, policy.Policy{Version: 1})
	})

	_, etag, err := c.Policy(context.Background())
	if err != nil || etag != `"new"` {
		t.Fatalf("etag = %q, err = %v", etag, err)
	}
	_, etag, err = c.PutPolicy(context.Background(), &policy.Policy{}, `"old"`)
	if err != nil || etag != `"new"` {
		t.Fatalf("etag = %q, err = %v", etag, err)
	}
}

func TestClient_EscapesDomains(t *testing.T) {
	var got []string
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		got = append(got, r.Method+" "+r.URL.EscapedPath())
		if r.Method == http.MethodPost {
			var req api.DomainRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			got = append(got, "body "+req.Domain)
		}
		writeJSON(w, 200, policy.Profile{ID: "p"})
	})

	ctx := context.Background()
	weird := "a/b?c#d.example"
	if _, err := c.Unallow(ctx, "my profile", weird); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Deny(ctx, "p", weird); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Undeny(ctx, "p", ".."); err != nil {
		t.Fatal(err)
	}

	want := []string{
		"DELETE /api/v1/profiles/my%20profile/allow/a%2Fb%3Fc%23d.example",
		"POST /api/v1/profiles/p/deny",
		"body " + weird,
		"DELETE /api/v1/profiles/p/deny/..",
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("requests =\n%q\nwant\n%q", got, want)
	}
}

func TestClient_PlaintextOnlyToLoopback(t *testing.T) {
	tests := []struct {
		addr  string
		token string
		ok    bool
	}{
		{"http://127.0.0.1:9090", "t", true},
		{"http://[::1]:9090", "t", true},
		{"http://localhost:9090", "t", true},
		{"127.0.0.1:9090", "t", true},
		{"http://192.168.1.10:9090", "t", false},
		{"http://doh.example.com", "t", false},
		{"http://192.168.1.10:9090", "", true}, // no credential to leak
		{"https://192.168.1.10:9090", "t", true},
		{"ftp://127.0.0.1", "t", false},
	}
	for _, tt := range tests {
		c := &Client{Addr: tt.addr, Token: tt.token}
		_, err := c.base(c.Token != "")
		if (err == nil) != tt.ok {
			t.Errorf("base(%q, token=%q) err = %v, want ok=%v", tt.addr, tt.token, err, tt.ok)
		}
	}

	// The refusal happens before any request is sent.
	c := &Client{Addr: "http://192.0.2.1:9", Token: "t"}
	if _, err := c.Status(context.Background()); err == nil || !strings.Contains(err.Error(), "https") {
		t.Errorf("Status over remote plaintext err = %v", err)
	}
}

func TestClient_LogsAndExplainQuery(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/logs":
			if r.URL.Query().Get("status") != "blocked" {
				t.Errorf("query = %s", r.URL.RawQuery)
			}
			writeJSON(w, 200, querylog.Page{Entries: []querylog.Entry{{ID: 7, Name: "ads.example"}}, NextPageToken: "x"})
		case "/api/v1/explain":
			q := r.URL.Query()
			if q.Get("name") != "ads.example" || q.Get("type") != "AAAA" || q.Get("profile") != "kids" || q.Has("client") {
				t.Errorf("explain query = %s", r.URL.RawQuery)
			}
			writeJSON(w, 200, api.Explanation{Name: "ads.example", Decision: api.Decision{Action: api.ActionBlock}})
		default:
			http.NotFound(w, r)
		}
	})

	page, err := c.Logs(context.Background(), url.Values{"status": {"blocked"}})
	if err != nil || len(page.Entries) != 1 || page.NextPageToken != "x" {
		t.Fatalf("page = %+v, err = %v", page, err)
	}
	e, err := c.Explain(context.Background(), "ads.example", "AAAA", "kids", "")
	if err != nil || e.Decision.Action != api.ActionBlock {
		t.Fatalf("explain = %+v, err = %v", e, err)
	}
}

func TestClient_ResponseSizeLimit(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`"`))
		chunk := strings.Repeat("a", 1<<20)
		for range MaxResponseSize/len(chunk) + 1 {
			w.Write([]byte(chunk))
		}
	})
	if _, err := c.Status(context.Background()); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Errorf("err = %v, want size error", err)
	}
}

func TestEvents(t *testing.T) {
	stream := ": ping\n\n" +
		"event: entry\ndata: {\"id\":1,\ndata: \"name\":\"a.example\"}\n\n" +
		"event: other\ndata: ignored\n\n" +
		"data: {\"id\":2}\r\n\r\n" +
		"event: entry\n\n" + // no data: not dispatched
		"data:{\"id\":3}\n" // unterminated: not dispatched

	var got []event
	for ev, err := range events(strings.NewReader(stream)) {
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, ev)
	}
	want := []event{
		{name: "entry", data: "{\"id\":1,\n\"name\":\"a.example\"}"},
		{name: "other", data: "ignored"},
		{data: `{"id":2}`},
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("events = %q, want %q", got, want)
	}
}

func TestClient_Stream(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/logs/stream" || r.URL.Query().Get("profile") != "kids" {
			t.Errorf("request = %s", r.URL)
		}
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, ": ping\n\nevent: entry\ndata: {\"id\":1,\"name\":\"a.example\"}\n\nevent: entry\ndata: {\"id\":2,\"name\":\"b.example\"}\n\n")
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var names []string
	for e, err := range c.Stream(ctx, url.Values{"profile": {"kids"}}) {
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, e.Name)
		if len(names) == 2 {
			cancel() // the next read ends without an error
		}
	}
	if fmt.Sprint(names) != "[a.example b.example]" {
		t.Errorf("names = %v", names)
	}
}

func TestClient_StreamError(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 401, api.Error{Error: "invalid token"})
	})
	for _, err := range c.Stream(context.Background(), nil) {
		var e *Error
		if !errors.As(err, &e) || e.Status != 401 {
			t.Fatalf("err = %v", err)
		}
		return
	}
	t.Fatal("no error yielded")
}

func TestClient_Setup(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.EscapedPath() != "/api/v1/profiles/kids/setup" || r.URL.Query().Get("device") != "tablet" {
			writeJSON(w, http.StatusNotFound, api.Error{Error: "unexpected " + r.URL.String()})
			return
		}
		writeJSON(w, http.StatusOK, api.Setup{Profile: "kids", Device: "tablet", DoTHost: "tablet--kids.dns.example.com"})
	})

	setup, err := c.Setup(t.Context(), "kids", "tablet")
	if err != nil {
		t.Fatal(err)
	}
	if setup.DoTHost != "tablet--kids.dns.example.com" {
		t.Errorf("Setup = %+v", setup)
	}
}

func TestClient_SetupWithoutDevice(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RawQuery != "" {
			writeJSON(w, http.StatusBadRequest, api.Error{Error: "unexpected query " + r.URL.RawQuery})
			return
		}
		writeJSON(w, http.StatusOK, api.Setup{Profile: "default"})
	})
	if _, err := c.Setup(t.Context(), "default", ""); err != nil {
		t.Fatal(err)
	}
}

func TestClient_MobileConfig(t *testing.T) {
	const plist = `<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict/></plist>`
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		switch {
		case r.URL.EscapedPath() != "/api/v1/profiles/kids/apple.mobileconfig":
			writeJSON(w, http.StatusNotFound, api.Error{Error: "unexpected path"})
		case r.Header.Get("Accept") != api.MobileConfigType:
			writeJSON(w, http.StatusNotAcceptable, api.Error{Error: "unexpected Accept " + r.Header.Get("Accept")})
		case q.Get("protocol") == "ftp":
			writeJSON(w, http.StatusBadRequest, api.Error{Error: "protocol must be https or tls"})
		case q.Get("protocol") != "tls" || q.Get("device") != "tablet":
			writeJSON(w, http.StatusBadRequest, api.Error{Error: "unexpected query " + r.URL.RawQuery})
		default:
			w.Header().Set("Content-Type", api.MobileConfigType)
			_, _ = w.Write([]byte(plist))
		}
	})

	b, err := c.MobileConfig(t.Context(), "kids", "tablet", "tls")
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != plist {
		t.Errorf("MobileConfig = %q", b)
	}

	_, err = c.MobileConfig(t.Context(), "kids", "tablet", "ftp")
	var apiErr *Error
	if !errors.As(err, &apiErr) || apiErr.Status != http.StatusBadRequest || apiErr.Message != "protocol must be https or tls" {
		t.Errorf("MobileConfig with a bad protocol = %v, want the server's 400", err)
	}
}

func TestClient_SigninLink(t *testing.T) {
	expires := time.Date(2026, 11, 1, 12, 5, 0, 0, time.UTC)
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/signin-links" {
			t.Errorf("%s %s", r.Method, r.URL.Path)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("Content-Type = %q", ct)
		}
		var req api.SigninLinkRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Role != "reader" || req.Tenant != "smiths" {
			t.Errorf("request = %+v, %v", req, err)
		}
		writeJSON(w, http.StatusCreated, api.SigninLink{URL: "http://localhost:9090/#signin=abc", Expires: expires, PasskeyRequired: true})
	})

	link, err := c.SigninLink(context.Background(), "reader", "smiths")
	if err != nil {
		t.Fatal(err)
	}
	if link.URL != "http://localhost:9090/#signin=abc" || !link.Expires.Equal(expires) || !link.PasskeyRequired {
		t.Errorf("link = %+v", link)
	}
}

func TestClient_People(t *testing.T) {
	var deleted []string
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method + " " + r.URL.EscapedPath() {
		case "GET /api/v1/people":
			writeJSON(w, 200, api.People{People: []signin.Person{{
				ID: "aGFuZGxl", Name: "Alice", Role: signin.RoleAdmin,
				Passkeys: []signin.Passkey{{ID: "a/b", Name: "MacBook", Synced: true}},
			}}})
		case "DELETE /api/v1/people/aGFuZGxl", "DELETE /api/v1/people/aGFuZGxl/passkeys/a%2Fb":
			deleted = append(deleted, r.URL.EscapedPath())
			w.WriteHeader(http.StatusNoContent)
		default:
			writeJSON(w, 404, api.Error{Error: "not found"})
		}
	})
	ctx := context.Background()

	people, err := c.People(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(people) != 1 || people[0].Name != "Alice" || len(people[0].Passkeys) != 1 || !people[0].Passkeys[0].Synced {
		t.Fatalf("people = %+v", people)
	}

	if err := c.DeletePasskey(ctx, "aGFuZGxl", "a/b"); err != nil {
		t.Fatal(err)
	}
	if err := c.DeletePerson(ctx, "aGFuZGxl"); err != nil {
		t.Fatal(err)
	}
	if len(deleted) != 2 {
		t.Errorf("deleted = %q", deleted)
	}

	var e *Error
	if err := c.DeletePerson(ctx, "nobody"); !errors.As(err, &e) || e.Status != 404 {
		t.Errorf("DeletePerson(nobody) = %v, want 404", err)
	}
}

func TestClient_Tenants(t *testing.T) {
	var calls []string
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.EscapedPath())
		switch r.Method + " " + r.URL.EscapedPath() {
		case "GET /api/v1/tenants":
			writeJSON(w, 200, api.Tenants{Tenants: []policy.Tenant{{ID: "smiths", Name: "The Smiths", Networks: []string{"192.168.10.0/24"}}}})
		case "POST /api/v1/tenants":
			var tn policy.Tenant
			if err := json.NewDecoder(r.Body).Decode(&tn); err != nil || tn.ID != "jones" || len(tn.Networks) != 1 {
				t.Errorf("create body = %+v, %v", tn, err)
			}
			writeJSON(w, http.StatusCreated, tn)
		case "PATCH /api/v1/tenants/jones":
			if ct := r.Header.Get("Content-Type"); ct != api.MergePatchType {
				t.Errorf("patch Content-Type = %q", ct)
			}
			writeJSON(w, 200, policy.Tenant{ID: "jones", CustomLists: true})
		case "DELETE /api/v1/tenants/jones":
			writeJSON(w, http.StatusBadRequest, api.Error{Error: `tenant "jones" still has 2 profiles; delete or move them first`})
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
	})
	ctx := context.Background()

	tenants, err := c.Tenants(ctx)
	if err != nil || len(tenants) != 1 || tenants[0].Name != "The Smiths" {
		t.Errorf("Tenants = %+v, %v", tenants, err)
	}
	if tn, err := c.CreateTenant(ctx, policy.Tenant{ID: "jones", Networks: []string{"192.168.20.0/24"}}); err != nil || tn.ID != "jones" {
		t.Errorf("CreateTenant = %+v, %v", tn, err)
	}
	if tn, err := c.PatchTenant(ctx, "jones", map[string]any{"custom_lists": true}); err != nil || !tn.CustomLists {
		t.Errorf("PatchTenant = %+v, %v", tn, err)
	}
	var apiErr *Error
	if err := c.DeleteTenant(ctx, "jones"); !errors.As(err, &apiErr) || apiErr.Status != 400 || !strings.Contains(apiErr.Message, "still has 2 profiles") {
		t.Errorf("DeleteTenant = %v, want the server's refusal", err)
	}
	if len(calls) != 4 {
		t.Errorf("calls = %v", calls)
	}
}

func TestClient_ConditionalProfilePatch(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			w.Header().Set("ETag", `"v1"`)
			writeJSON(w, 200, policy.Profile{ID: "kids"})
		case http.MethodPatch:
			if ct := r.Header.Get("Content-Type"); ct != api.MergePatchType {
				t.Errorf("Content-Type = %q", ct)
			}
			if r.Header.Get("If-Match") != `"v1"` {
				writeJSON(w, http.StatusPreconditionFailed, api.Error{Error: "the policy changed"})
				return
			}
			writeJSON(w, 200, policy.Profile{ID: "kids", Services: []string{"tiktok"}})
		}
	})

	p, etag, err := c.ProfileVersion(t.Context(), "kids")
	if err != nil || p.ID != "kids" || etag != `"v1"` {
		t.Fatalf("ProfileVersion = %+v, %q, %v", p, etag, err)
	}
	if p, err := c.PatchProfileIf(t.Context(), "kids", map[string]any{"services": []string{"tiktok"}}, etag); err != nil || len(p.Services) != 1 {
		t.Errorf("PatchProfileIf = %+v, %v", p, err)
	}
	_, err = c.PatchProfileIf(t.Context(), "kids", map[string]any{}, `"stale"`)
	if !IsPreconditionFailed(err) {
		t.Errorf("stale PatchProfileIf = %v, want a precondition failure", err)
	}
	if IsPreconditionFailed(errors.New("other")) {
		t.Error("IsPreconditionFailed matched an unrelated error")
	}
}

func TestClient_TrustRules(t *testing.T) {
	var got []string
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		got = append(got, r.Method+" "+r.URL.EscapedPath()+" "+strings.TrimSpace(string(body)))
		switch r.Method {
		case http.MethodGet:
			writeJSON(w, http.StatusOK, api.TrustRules{Rules: []serviceaccount.TrustRule{{ID: "r1", Issuer: "https://issuer.example"}}})
		case http.MethodPost:
			writeJSON(w, http.StatusCreated, serviceaccount.TrustRule{ID: "r2"})
		default:
			w.WriteHeader(http.StatusNoContent)
		}
	})
	ctx := context.Background()
	rules, err := c.TrustRules(ctx, "acct")
	if err != nil || len(rules) != 1 || rules[0].ID != "r1" {
		t.Fatalf("TrustRules = %+v, %v", rules, err)
	}
	r, err := c.AddTrustRule(ctx, "acct", api.TrustRuleRequest{Issuer: "https://issuer.example", Subject: "s", Claims: map[string]string{"k": "v"}})
	if err != nil || r.ID != "r2" {
		t.Fatalf("AddTrustRule = %+v, %v", r, err)
	}
	if err := c.DeleteTrustRule(ctx, "acct", "r/2"); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"GET /api/v1/service-accounts/acct/federation ",
		`POST /api/v1/service-accounts/acct/federation {"issuer":"https://issuer.example","subject":"s","claims":{"k":"v"}}`,
		"DELETE /api/v1/service-accounts/acct/federation/r%2F2 ",
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("requests =\n%q\nwant\n%q", got, want)
	}
}

func TestClient_ExchangeToken(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			t.Error("the exchange sent the client's API token")
		}
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/token" || r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
			t.Errorf("exchange %s %s %s", r.Method, r.URL.Path, r.Header.Get("Content-Type"))
		}
		_ = r.ParseForm()
		switch r.PostForm.Get("subject_token") {
		case "good":
			if r.PostForm.Get("grant_type") != api.GrantTypeTokenExchange || r.PostForm.Get("subject_token_type") != api.TokenTypeJWT || r.PostForm.Get("audience") != "acct" {
				t.Errorf("form = %v", r.PostForm)
			}
			writeJSON(w, http.StatusOK, api.TokenResponse{AccessToken: "doh_at_x", TokenType: "Bearer", IssuedTokenType: api.TokenTypeAccessToken, ExpiresIn: 900})
		default:
			writeJSON(w, http.StatusBadRequest, api.OAuthError{Error: "invalid_grant", Description: "not accepted"})
		}
	})
	ctx := context.Background()

	tr, err := c.ExchangeToken(ctx, api.TokenExchangeRequest{SubjectToken: "good", Audience: "acct"})
	if err != nil || tr.AccessToken != "doh_at_x" || tr.ExpiresIn != 900 {
		t.Fatalf("ExchangeToken = %+v, %v", tr, err)
	}
	_, err = c.ExchangeToken(ctx, api.TokenExchangeRequest{SubjectToken: "bad", Audience: "acct"})
	var e *Error
	if !errors.As(err, &e) || e.Status != http.StatusBadRequest || e.Message != "invalid_grant: not accepted" {
		t.Errorf("refused exchange err = %v", err)
	}

	// The identity token is a credential, so it isn't sent over plain
	// HTTP to a remote host, even by a client without an API token.
	remote := &Client{Addr: "http://192.0.2.1:9"}
	if _, err := remote.ExchangeToken(ctx, api.TokenExchangeRequest{SubjectToken: "good", Audience: "acct"}); err == nil || !strings.Contains(err.Error(), "plain HTTP") {
		t.Errorf("exchange over remote plaintext err = %v", err)
	}
}
