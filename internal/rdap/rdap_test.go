package rdap

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// fakeNow is a fixed reference time for tests.
var fakeNow = time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)

// rdapServer serves a bootstrap registry at /bootstrap mapping tlds to its
// own RDAP service under /rdap, answering domain queries with handle.
//
// It's served either over a real HTTP server, or in memory, for tests in
// synctest bubbles, where network I/O isn't durably blocking.
type rdapServer struct {
	URL        string
	httpClient *http.Client
	mux        http.Handler

	bootstrapHits atomic.Int64
	domainHits    atomic.Int64
}

// newRDAPServer serves an RDAP service over a real HTTP server.
func newRDAPServer(t *testing.T, tlds []string, handle func(w http.ResponseWriter, domain string)) *rdapServer {
	t.Helper()

	s := &rdapServer{}
	s.mux = s.handler(t, tlds, handle)
	srv := httptest.NewServer(s.mux)
	t.Cleanup(srv.Close)
	s.URL, s.httpClient = srv.URL, srv.Client()
	return s
}

// newMemoryRDAPServer serves an RDAP service in memory, through an
// [http.RoundTripper] that calls its handler directly, so handlers that
// block on channels block durably, as synctest needs.
func newMemoryRDAPServer(t *testing.T, tlds []string, handle func(w http.ResponseWriter, domain string)) *rdapServer {
	t.Helper()

	s := &rdapServer{URL: "http://rdap.test"}
	s.mux = s.handler(t, tlds, handle)
	s.httpClient = &http.Client{Transport: memoryTransport{s.mux}}
	return s
}

func (s *rdapServer) handler(t *testing.T, tlds []string, handle func(w http.ResponseWriter, domain string)) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /bootstrap", func(w http.ResponseWriter, r *http.Request) {
		s.bootstrapHits.Add(1)
		quoted := make([]string, len(tlds))
		for i, tld := range tlds {
			quoted[i] = fmt.Sprintf("%q", tld)
		}
		fmt.Fprintf(w, `{"version":"1.0","services":[[[%s],["%s/rdap"]]]}`, strings.Join(quoted, ","), s.URL)
	})
	mux.HandleFunc("GET /rdap/domain/{domain}", func(w http.ResponseWriter, r *http.Request) {
		s.domainHits.Add(1)
		if got := r.Header.Get("Accept"); got != mediaType {
			t.Errorf("Accept = %q, want %q", got, mediaType)
		}
		if got := r.Header.Get("User-Agent"); got != userAgent {
			t.Errorf("User-Agent = %q, want %q", got, userAgent)
		}
		handle(w, r.PathValue("domain"))
	})
	return mux
}

func (s *rdapServer) client() *Client {
	return &Client{HTTPClient: s.httpClient, BootstrapURL: s.URL + "/bootstrap", now: func() time.Time { return fakeNow }}
}

// memoryTransport answers requests by calling a handler directly. Like a
// real transport, it gives up when the request's context is done, even if
// the handler hasn't returned.
type memoryTransport struct{ h http.Handler }

func (m memoryTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	rec := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		defer close(done)
		m.h.ServeHTTP(rec, req)
	}()

	select {
	case <-done:
		return rec.Result(), nil
	case <-req.Context().Done():
		return nil, req.Context().Err()
	}
}

func registeredAt(t time.Time) func(http.ResponseWriter, string) {
	return func(w http.ResponseWriter, domain string) {
		fmt.Fprintf(w, `{"objectClassName":"domain","ldhName":%q,"events":[{"eventAction":"expiration","eventDate":"2030-01-01T00:00:00Z"},{"eventAction":"registration","eventDate":%q}]}`,
			domain, t.Format(time.RFC3339))
	}
}

func TestParseBootstrap(t *testing.T) {
	body := []byte(`{"services":[
		[["com","NET"],["http://insecure.example/rdap/","https://rdap.example/com/v1/"]],
		[["uk"],["https://rdap.example/uk"]],
		[["co.uk"],["https://rdap.example/couk/"]],
		[["onlyhttp"],["http://plain.example/"]],
		[["bad"]],
		[["gopher"],["gopher://x.example/"]]
	]}`)

	services, err := parseBootstrap(body, false)
	if err != nil {
		t.Fatal(err)
	}

	tests := map[string]string{
		"com":   "https://rdap.example/com/v1/",
		"net":   "https://rdap.example/com/v1/",
		"uk":    "https://rdap.example/uk/",
		"co.uk": "https://rdap.example/couk/",
	}
	for tld, want := range tests {
		if got := services[tld]; got == nil || got.String() != want {
			t.Errorf("services[%q] = %v, want %s", tld, got, want)
		}
	}
	for _, tld := range []string{"onlyhttp", "bad", "gopher"} {
		if u, ok := services[tld]; ok {
			t.Errorf("services[%q] = %v, want none", tld, u)
		}
	}

	if services, _ := parseBootstrap(body, true); services["onlyhttp"] == nil {
		t.Error("http service URL dropped when http is allowed")
	}

	for _, bad := range []string{`not json`, `{"services":[]}`, `{"services":[[["x"],["ftp://a/"]]]}`} {
		if _, err := parseBootstrap([]byte(bad), false); err == nil {
			t.Errorf("parseBootstrap(%s) succeeded", bad)
		}
	}
}

func TestClient_ServiceURLLongestMatch(t *testing.T) {
	c := &Client{now: func() time.Time { return fakeNow }}
	services, err := parseBootstrap([]byte(`{"services":[
		[["uk"],["https://uk.example/"]],
		[["co.uk"],["https://couk.example/"]]
	]}`), false)
	if err != nil {
		t.Fatal(err)
	}
	c.services, c.fetched = services, fakeNow

	tests := []struct {
		domain, want string
		err          error
	}{
		{"example.co.uk", "https://couk.example/", nil},
		{"example.uk", "https://uk.example/", nil},
		{"example.org.uk", "https://uk.example/", nil},
		{"example.sh", "", ErrUnsupported},
	}
	for _, tt := range tests {
		u, err := c.serviceURL(t.Context(), tt.domain)
		if !errors.Is(err, tt.err) {
			t.Errorf("serviceURL(%q) error = %v, want %v", tt.domain, err, tt.err)
			continue
		}
		if err == nil && u.String() != tt.want {
			t.Errorf("serviceURL(%q) = %s, want %s", tt.domain, u, tt.want)
		}
	}
}

func TestClient_Registered(t *testing.T) {
	when := time.Date(2024, 3, 4, 5, 6, 7, 0, time.UTC)
	s := newRDAPServer(t, []string{"test"}, func(w http.ResponseWriter, domain string) {
		switch domain {
		case "found.test":
			registeredAt(when)(w, domain)
		case "missing.test":
			http.NotFound(w, nil)
		case "busy.test":
			w.WriteHeader(http.StatusTooManyRequests)
		default:
			http.Error(w, "boom", http.StatusInternalServerError)
		}
	})
	c := s.client()

	got, err := c.Registered(t.Context(), "Found.Test.")
	if err != nil || !got.Equal(when) {
		t.Errorf("Registered(found.test) = %v, %v; want %v", got, err, when)
	}

	if _, err := c.Registered(t.Context(), "missing.test"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Registered(missing.test) error = %v, want ErrNotFound", err)
	}
	if _, err := c.Registered(t.Context(), "busy.test"); err == nil {
		t.Error("Registered(busy.test) succeeded")
	} else if _, ok := errors.AsType[*rateLimitedError](err); !ok {
		t.Errorf("Registered(busy.test) error = %v, want rate limited", err)
	}
	if _, err := c.Registered(t.Context(), "broken.test"); err == nil {
		t.Error("Registered(broken.test) succeeded")
	}
	if _, err := c.Registered(t.Context(), "example.sh"); !errors.Is(err, ErrUnsupported) {
		t.Errorf("Registered(example.sh) error = %v, want ErrUnsupported", err)
	}

	// The bootstrap registry is fetched once and reused.
	if n := s.bootstrapHits.Load(); n != 1 {
		t.Errorf("bootstrap fetched %d times, want 1", n)
	}
}

func TestClient_RegisteredRejectsInvalidDomains(t *testing.T) {
	c := &Client{BootstrapURL: "http://127.0.0.1:1/never"}
	for _, domain := range []string{"", ".", "a..b", "../etc/passwd", "a/b.test", "a?b.test", "ünicode.test", strings.Repeat("a", 64) + ".test"} {
		if _, err := c.Registered(t.Context(), domain); err == nil || !strings.Contains(err.Error(), "invalid domain") {
			t.Errorf("Registered(%q) error = %v, want invalid domain", domain, err)
		}
	}
}

func TestParseRegistration_Malicious(t *testing.T) {
	tests := map[string]string{
		"not json":        `<html>`,
		"no events":       `{"objectClassName":"domain"}`,
		"other events":    `{"events":[{"eventAction":"expiration","eventDate":"2030-01-01T00:00:00Z"}]}`,
		"garbage date":    `{"events":[{"eventAction":"registration","eventDate":"yesterday-ish"}]}`,
		"huge year":       `{"events":[{"eventAction":"registration","eventDate":"99999999-01-01T00:00:00Z"}]}`,
		"future date":     `{"events":[{"eventAction":"registration","eventDate":"2099-01-01T00:00:00Z"}]}`,
		"ancient date":    `{"events":[{"eventAction":"registration","eventDate":"0001-01-01T00:00:00Z"}]}`,
		"wrong type date": `{"events":[{"eventAction":"registration","eventDate":12345}]}`,
		"events object":   `{"events":{"eventAction":"registration"}}`,
		"long date":       `{"events":[{"eventAction":"registration","eventDate":"` + strings.Repeat("9", 100_000) + `"}]}`,
	}
	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			if got, err := parseRegistration([]byte(body), fakeNow); err == nil {
				t.Errorf("parseRegistration = %v, want error", got)
			}
		})
	}

	// Event actions are matched case-insensitively.
	if _, err := parseRegistration([]byte(`{"events":[{"eventAction":"Registration","eventDate":"2001-02-03T04:05:06Z"}]}`), fakeNow); err != nil {
		t.Errorf("parseRegistration(Registration) = %v", err)
	}
}

func TestClient_OversizeBody(t *testing.T) {
	s := newRDAPServer(t, []string{"test"}, func(w http.ResponseWriter, domain string) {
		fmt.Fprintf(w, `{"events":[],"pad":"%s"}`, strings.Repeat("x", maxBodySize))
	})

	if _, err := s.client().Registered(t.Context(), "big.test"); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Errorf("Registered(big.test) error = %v, want size limit", err)
	}
}

func TestClient_RefusesInsecureServiceURLs(t *testing.T) {
	var plainHits atomic.Int64
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		plainHits.Add(1)
		registeredAt(fakeNow.Add(-time.Hour))(w, "x.test")
	}))
	defer plain.Close()

	// An https bootstrap pointing at an http service, and an https service
	// redirecting to http.
	var tlsURL string
	tlsServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/bootstrap":
			fmt.Fprintf(w, `{"services":[[["plain"],["%s/"]],[["redir"],["%s/rdap/"]]]}`, plain.URL, tlsURL)
		case strings.HasPrefix(r.URL.Path, "/rdap/"):
			http.Redirect(w, r, plain.URL+"/domain/x.redir", http.StatusFound)
		default:
			http.NotFound(w, r)
		}
	}))
	defer tlsServer.Close()
	tlsURL = tlsServer.URL

	c := &Client{HTTPClient: tlsServer.Client(), BootstrapURL: tlsServer.URL + "/bootstrap"}

	if _, err := c.Registered(t.Context(), "x.plain"); !errors.Is(err, ErrUnsupported) {
		t.Errorf("Registered(x.plain) error = %v, want ErrUnsupported (http service dropped)", err)
	}
	if _, err := c.Registered(t.Context(), "x.redir"); err == nil || !strings.Contains(err.Error(), "refusing redirect") {
		t.Errorf("Registered(x.redir) error = %v, want refused redirect", err)
	}
	if n := plainHits.Load(); n != 0 {
		t.Errorf("plain http server hit %d times, want 0", n)
	}
}

func TestClient_RedirectLimit(t *testing.T) {
	var base string
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/bootstrap" {
			fmt.Fprintf(w, `{"services":[[["test"],["%s/"]]]}`, base)
			return
		}
		http.Redirect(w, r, r.URL.Path+"x", http.StatusFound)
	}))
	defer s.Close()
	base = s.URL

	c := &Client{BootstrapURL: s.URL + "/bootstrap"}
	if _, err := c.Registered(t.Context(), "loop.test"); err == nil || !strings.Contains(err.Error(), "redirects") {
		t.Errorf("Registered(loop.test) error = %v, want redirect limit", err)
	}
}

func TestClient_BootstrapRefreshKeepsOldOnFailure(t *testing.T) {
	var fail atomic.Bool
	s := newRDAPServer(t, []string{"test"}, registeredAt(fakeNow.Add(-time.Hour)))
	broken := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fail.Load() {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		s.mux.ServeHTTP(w, r)
	}))
	defer broken.Close()

	now := fakeNow
	c := &Client{BootstrapURL: broken.URL + "/bootstrap", now: func() time.Time { return now }}

	if _, err := c.Registered(context.Background(), "a.test"); err != nil {
		t.Fatal(err)
	}

	fail.Store(true)
	now = now.Add(bootstrapTTL + time.Second)
	if _, err := c.Registered(context.Background(), "b.test"); err != nil {
		t.Errorf("Registered after failed refresh = %v, want old bootstrap kept", err)
	}
}

func TestClient_BootstrapFailureIsRemembered(t *testing.T) {
	var hits atomic.Int64
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		http.Error(w, "down", http.StatusServiceUnavailable)
	}))
	defer s.Close()

	c := &Client{BootstrapURL: s.URL, now: func() time.Time { return fakeNow }}
	for range 3 {
		if _, err := c.Registered(t.Context(), "a.test"); err == nil {
			t.Fatal("Registered succeeded without bootstrap")
		}
	}
	if n := hits.Load(); n != 1 {
		t.Errorf("bootstrap fetched %d times within retry interval, want 1", n)
	}
}
