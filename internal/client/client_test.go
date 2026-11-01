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
		_, err := c.base()
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
