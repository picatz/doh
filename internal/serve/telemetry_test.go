package serve

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/picatz/doh/pkg/doh"
)

// startAdmin serves s's admin endpoints on a local port until the test
// ends, returning the base URL.
func startAdmin(t *testing.T, s *Server) string {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.ServeAdmin(ctx, ln) }()

	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("serve admin: %v", err)
		}
	})

	return "http://" + ln.Addr().String()
}

func get(t *testing.T, url string) (int, string) {
	t.Helper()

	resp, err := (&http.Client{Transport: &http.Transport{}}).Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	return resp.StatusCode, string(b)
}

func TestTelemetry(t *testing.T) {
	s, err := New(Config{Plaintext: true, Upstreams: []string{startResolver(t)}}, testLogger(t))
	if err != nil {
		t.Fatal(err)
	}

	dohAddr := start(t, s)
	udpAddr, _ := startDNS(t, s)
	admin := startAdmin(t, s)

	query(t, &http.Client{Transport: &http.Transport{}}, "http://"+dohAddr+doh.DefaultPath)
	exchange(t, "udp", udpAddr, new(dns.Msg).SetQuestion("example.com.", dns.TypeA))
	exchange(t, "udp", udpAddr, new(dns.Msg).SetQuestion("example.com.", dns.TypeA))

	t.Run("prometheus metrics", func(t *testing.T) {
		status, body := get(t, admin+MetricsPath)
		if status != http.StatusOK {
			t.Fatalf("got status %d", status)
		}

		for _, want := range []string{
			`doh_queries_total{transport="doh"} 1`,
			`doh_queries_total{transport="udp"} 2`,
			`doh_responses_total{rcode="NOERROR"} 3`,
			`doh_upstream_queries_total{upstream="udp://`,
			`doh_upstream_errors_total{upstream="udp://`,
			"# TYPE doh_queries_total counter",
			"go_goroutines ",
		} {
			if !strings.Contains(body, want) {
				t.Errorf("metrics missing %q:\n%s", want, body)
			}
		}
	})

	t.Run("vars", func(t *testing.T) {
		status, body := get(t, admin+VarsPath)
		if status != http.StatusOK {
			t.Fatalf("got status %d", status)
		}

		var vars struct {
			DoH struct {
				Queries   map[string]int `json:"queries"`
				Responses map[string]int `json:"responses"`
				Upstreams map[string]struct {
					Queries int     `json:"queries"`
					Errors  int     `json:"errors"`
					Seconds float64 `json:"seconds"`
				} `json:"upstreams"`
			} `json:"doh"`
			Runtime []runtimeSample   `json:"runtime"`
			Build   map[string]string `json:"build"`
		}
		if err := json.Unmarshal([]byte(body), &vars); err != nil {
			t.Fatalf("invalid JSON: %v\n%s", err, body)
		}

		if vars.DoH.Queries["udp"] != 2 || vars.DoH.Responses["NOERROR"] != 3 {
			t.Errorf("got %+v, want 2 UDP queries and 3 NOERROR responses", vars.DoH)
		}

		if len(vars.DoH.Upstreams) != 1 {
			t.Errorf("got upstreams %+v, want 1", vars.DoH.Upstreams)
		}
		for _, u := range vars.DoH.Upstreams {
			if u.Queries != 3 || u.Errors != 0 {
				t.Errorf("got upstream %+v, want 3 queries and no errors", u)
			}
		}

		if len(vars.Runtime) == 0 || vars.Build["go"] == "" {
			t.Errorf("got runtime %v and build %v, want both", vars.Runtime, vars.Build)
		}

		if strings.Contains(body, "cmdline") {
			t.Error("vars expose the process command line")
		}
	})

	t.Run("pprof", func(t *testing.T) {
		if status, _ := get(t, admin+PprofPath); status != http.StatusOK {
			t.Errorf("got status %d for the pprof index", status)
		}
	})

	t.Run("flight recorder disabled", func(t *testing.T) {
		if status, _ := get(t, admin+FlightRecorderPath); status != http.StatusNotFound {
			t.Errorf("got status %d, want 404", status)
		}
	})

	t.Run("admin endpoints aren't public", func(t *testing.T) {
		for _, path := range []string{MetricsPath, VarsPath, PprofPath, FlightRecorderPath} {
			if status, _ := get(t, "http://"+dohAddr+path); status != http.StatusNotFound {
				t.Errorf("DoH listener served %s with status %d", path, status)
			}
		}
	})
}

func TestTelemetry_CountsRejectedDNSQueries(t *testing.T) {
	s, err := New(Config{Plaintext: true, Upstreams: []string{startResolver(t)}}, testLogger(t))
	if err != nil {
		t.Fatal(err)
	}

	notify := new(dns.Msg).SetQuestion("example.com.", dns.TypeSOA)
	notify.Opcode = dns.OpcodeNotify
	s.answerDNS(t.Context(), "udp", notify)

	if got := s.telemetry.queries.Get("udp"); got == nil || got.String() != "1" {
		t.Errorf("got %v UDP queries, want the rejected query counted", got)
	}
	if got := s.telemetry.responses.Get("NOTIMP"); got == nil || got.String() != "1" {
		t.Errorf("got %v NOTIMP responses, want 1", got)
	}
}

func TestTelemetry_SharesCountersForEquivalentUpstreams(t *testing.T) {
	resolver := startResolver(t)

	// Both forms name the same upstream, udp://<addr>.
	s, err := New(Config{Plaintext: true, Upstreams: []string{resolver, "udp://" + resolver}}, testLogger(t))
	if err != nil {
		t.Fatal(err)
	}

	s.answerDNS(t.Context(), "udp", new(dns.Msg).SetQuestion("example.com.", dns.TypeA))

	m, ok := s.telemetry.upstreams.Get("udp://" + resolver).(*upstreamMetrics)
	if !ok {
		t.Fatalf("no counters for udp://%s", resolver)
	}
	if got := m.queries.Value(); got != 1 {
		t.Errorf("got %d queries for the upstream, want 1", got)
	}
}

func TestTelemetry_FlightRecorder(t *testing.T) {
	traceDir := t.TempDir()

	s, err := New(Config{
		Plaintext: true,
		Upstreams: []string{startResolver(t)},
		Admin: AdminConfig{
			FlightRecorder: true,
			// Every query is slow, to trigger a snapshot.
			SlowQuery: Duration(time.Nanosecond),
			TraceDir:  traceDir,
		},
	}, testLogger(t))
	if err != nil {
		t.Fatal(err)
	}

	stop, err := s.startTelemetry()
	if err != nil {
		t.Fatal(err)
	}

	// Cleanups run last-in first-out, so registering this before starting
	// the listeners stops the recorder after they've shut down, as
	// ListenAndServe does, waiting for pending snapshots.
	t.Cleanup(stop)

	admin := startAdmin(t, s)
	dohAddr := start(t, s)

	t.Run("on demand", func(t *testing.T) {
		status, body := get(t, admin+FlightRecorderPath)
		if status != http.StatusOK || len(body) == 0 {
			t.Errorf("got status %d with %d bytes, want a trace", status, len(body))
		}
	})

	t.Run("slow queries", func(t *testing.T) {
		client := &http.Client{Transport: &http.Transport{}}
		query(t, client, "http://"+dohAddr+doh.DefaultPath)
		query(t, client, "http://"+dohAddr+doh.DefaultPath)

		// Snapshots are written in the background.
		var entries []os.DirEntry
		for range 200 {
			if entries, err = os.ReadDir(traceDir); err != nil {
				t.Fatal(err)
			}
			if len(entries) > 0 {
				if info, err := entries[0].Info(); err == nil && info.Size() > 0 {
					break
				}
			}
			time.Sleep(10 * time.Millisecond)
		}

		if len(entries) != 1 {
			t.Fatalf("got %d snapshots, want 1, since snapshots are rate limited", len(entries))
		}

		if name := entries[0].Name(); !strings.HasPrefix(name, "doh-") || !strings.HasSuffix(name, ".trace") {
			t.Errorf("got snapshot %q", name)
		}

		if got := s.telemetry.slowQueries.Value(); got != 2 {
			t.Errorf("got %d slow queries, want 2", got)
		}
	})

	t.Run("snapshots are private", func(t *testing.T) {
		entries, err := os.ReadDir(traceDir)
		if err != nil || len(entries) == 0 {
			t.Fatalf("no snapshots: %v", err)
		}

		info, err := entries[0].Info()
		if err != nil {
			t.Fatal(err)
		}

		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("got snapshot permissions %v, want 0600", perm)
		}
	})
}

func TestConfig_ValidateAdmin(t *testing.T) {
	tests := []struct {
		name    string
		admin   AdminConfig
		wantErr string
	}{
		{name: "listen", admin: AdminConfig{Listen: "localhost:9090"}},
		{name: "flight recorder", admin: AdminConfig{Listen: "localhost:9090", FlightRecorder: true}},
		{name: "slow query", admin: AdminConfig{SlowQuery: Duration(time.Second), TraceDir: "/tmp/traces"}},
		{name: "bad listen", admin: AdminConfig{Listen: "9090"}, wantErr: "admin listen"},
		{name: "slow query without dir", admin: AdminConfig{SlowQuery: Duration(time.Second)}, wantErr: "needs a trace_dir"},
		{name: "dir without slow query", admin: AdminConfig{TraceDir: "/tmp/traces"}, wantErr: "only used with slow_query"},
		{name: "recorder with no way to snapshot", admin: AdminConfig{FlightRecorder: true}, wantErr: "needs an admin listen"},
		{name: "negative slow query", admin: AdminConfig{SlowQuery: -1}, wantErr: "must not be negative"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := Config{Plaintext: true, Admin: test.admin}.Validate()

			switch {
			case test.wantErr == "" && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case test.wantErr != "" && (err == nil || !strings.Contains(err.Error(), test.wantErr)):
				t.Fatalf("got error %v, want %q", err, test.wantErr)
			}
		})
	}
}

func TestPromLabel(t *testing.T) {
	if got, want := promLabel("a\"b\\c\nd"), `"a\"b\\c\nd"`; got != want {
		t.Errorf("got %s, want %s", got, want)
	}
}
