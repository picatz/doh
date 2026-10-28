package httpretry

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// fastTransport returns a Transport with negligible backoff for tests.
func fastTransport(base http.RoundTripper, maxRetries int) *Transport {
	return &Transport{
		Base:       base,
		MaxRetries: maxRetries,
		MinWait:    time.Millisecond,
		MaxWait:    5 * time.Millisecond,
	}
}

// statusServer responds with each status in turn, repeating the last one,
// and counts the requests it receives.
func statusServer(t *testing.T, statuses ...int) (*httptest.Server, *atomic.Int32) {
	t.Helper()

	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := int(requests.Add(1))
		w.WriteHeader(statuses[min(n, len(statuses))-1])
		fmt.Fprintf(w, "attempt %d", n)
	}))
	t.Cleanup(server.Close)

	return server, &requests
}

func TestTransport_RetriesUntilSuccess(t *testing.T) {
	server, requests := statusServer(t, http.StatusServiceUnavailable, http.StatusBadGateway, http.StatusOK)

	client := &http.Client{Transport: fastTransport(server.Client().Transport, 3)}

	resp, err := client.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("got status %d, want %d", resp.StatusCode, http.StatusOK)
	}

	if got, want := requests.Load(), int32(3); got != want {
		t.Errorf("got %d requests, want %d", got, want)
	}
}

func TestTransport_ReturnsLastResponseWhenExhausted(t *testing.T) {
	server, requests := statusServer(t, http.StatusServiceUnavailable)

	client := &http.Client{Transport: fastTransport(server.Client().Transport, 2)}

	resp, err := client.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("got status %d, want %d", resp.StatusCode, http.StatusServiceUnavailable)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	if got, want := string(body), "attempt 3"; got != want {
		t.Errorf("got body %q, want %q", got, want)
	}

	if got, want := requests.Load(), int32(3); got != want {
		t.Errorf("got %d requests, want %d", got, want)
	}
}

func TestTransport_NoRetry(t *testing.T) {
	tests := []struct {
		name       string
		status     int
		maxRetries int
	}{
		{name: "client error", status: http.StatusBadRequest, maxRetries: 3},
		{name: "not implemented", status: http.StatusNotImplemented, maxRetries: 3},
		{name: "zero value retries", status: http.StatusServiceUnavailable, maxRetries: 0},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server, requests := statusServer(t, test.status)

			client := &http.Client{Transport: fastTransport(server.Client().Transport, test.maxRetries)}

			resp, err := client.Get(server.URL)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()

			if resp.StatusCode != test.status {
				t.Errorf("got status %d, want %d", resp.StatusCode, test.status)
			}

			if got := requests.Load(); got != 1 {
				t.Errorf("got %d requests, want 1", got)
			}
		})
	}
}

func TestTransport_ReplaysBody(t *testing.T) {
	var (
		requests atomic.Int32
		bodies   = make(chan string, 2)
	)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		bodies <- string(b)

		if requests.Add(1) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
	}))
	t.Cleanup(server.Close)

	client := &http.Client{Transport: fastTransport(server.Client().Transport, 1)}

	resp, err := client.Post(server.URL, "text/plain", strings.NewReader("payload"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("got status %d, want %d", resp.StatusCode, http.StatusOK)
	}

	for range 2 {
		if got := <-bodies; got != "payload" {
			t.Errorf("got body %q, want %q", got, "payload")
		}
	}
}

func TestTransport_NonRewindableBodyIsSentOnce(t *testing.T) {
	server, requests := statusServer(t, http.StatusServiceUnavailable)

	req, err := http.NewRequest(http.MethodPost, server.URL, io.NopCloser(bytes.NewReader([]byte("payload"))))
	if err != nil {
		t.Fatal(err)
	}

	resp, err := fastTransport(server.Client().Transport, 3).RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if got := requests.Load(); got != 1 {
		t.Errorf("got %d requests, want 1", got)
	}
}

func TestTransport_NetworkErrorIsRetriedAndWrapped(t *testing.T) {
	// Reserve a port, then close it so connections are refused.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	listener.Close()

	var attempts atomic.Int32
	base := roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		attempts.Add(1)
		return http.DefaultTransport.RoundTrip(req)
	})

	client := &http.Client{Transport: fastTransport(base, 2)}

	_, err = client.Get("http://" + addr)
	if err == nil {
		t.Fatal("expected error for refused connection")
	}

	if !strings.Contains(err.Error(), "giving up after 3 attempts") {
		t.Errorf("got error %q, want attempts in message", err)
	}

	if _, ok := errors.AsType[*net.OpError](err); !ok {
		t.Errorf("got error %v, want wrapped *net.OpError", err)
	}

	if got := attempts.Load(); got != 3 {
		t.Errorf("got %d attempts, want 3", got)
	}
}

func TestTransport_ContextCanceledDuringBackoff(t *testing.T) {
	server, requests := statusServer(t, http.StatusServiceUnavailable)

	transport := &Transport{
		Base:       server.Client().Transport,
		MaxRetries: 3,
		MinWait:    time.Hour,
		MaxWait:    time.Hour,
	}

	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}

	_, err = transport.RoundTrip(req)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("got error %v, want %v", err, context.DeadlineExceeded)
	}

	if got := requests.Load(); got != 1 {
		t.Errorf("got %d requests, want 1", got)
	}
}

func TestTransport_RetryAfter(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requests.Add(1) == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
		}
	}))
	t.Cleanup(server.Close)

	// A Retry-After of zero must override the hour-long backoff.
	transport := &Transport{
		Base:       server.Client().Transport,
		MaxRetries: 1,
		MinWait:    time.Hour,
		MaxWait:    time.Hour,
	}

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("got status %d, want %d", resp.StatusCode, http.StatusOK)
	}
}

func TestRetryable(t *testing.T) {
	status := func(code int) *http.Response { return &http.Response{StatusCode: code} }

	tests := []struct {
		name string
		resp *http.Response
		err  error
		want bool
	}{
		{name: "ok", resp: status(http.StatusOK), want: false},
		{name: "not found", resp: status(http.StatusNotFound), want: false},
		{name: "too many requests", resp: status(http.StatusTooManyRequests), want: true},
		{name: "internal server error", resp: status(http.StatusInternalServerError), want: true},
		{name: "not implemented", resp: status(http.StatusNotImplemented), want: false},
		{name: "service unavailable", resp: status(http.StatusServiceUnavailable), want: true},
		{name: "connection refused", err: &net.OpError{Op: "dial", Err: errors.New("connection refused")}, want: true},
		{name: "dns temporary", err: &net.DNSError{Err: "server misbehaving", IsTemporary: true}, want: true},
		{name: "dns not found", err: &net.DNSError{Err: "no such host", IsNotFound: true}, want: false},
		{name: "unexpected eof", err: io.ErrUnexpectedEOF, want: true},
		{name: "canceled", err: context.Canceled, want: false},
		{name: "deadline exceeded", err: fmt.Errorf("wrapped: %w", context.DeadlineExceeded), want: false},
		{name: "certificate", err: &tls.CertificateVerificationError{Err: x509.UnknownAuthorityError{}}, want: false},
		{name: "unsupported scheme", err: errors.New("unsupported protocol scheme"), want: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := Retryable(test.resp, test.err); got != test.want {
				t.Errorf("got %t, want %t", got, test.want)
			}
		})
	}
}

func TestTransport_Backoff(t *testing.T) {
	transport := &Transport{MinWait: time.Second, MaxWait: 10 * time.Second}

	tests := []struct {
		attempt  int
		min, max time.Duration
	}{
		{attempt: 0, min: 500 * time.Millisecond, max: time.Second},
		{attempt: 1, min: time.Second, max: 2 * time.Second},
		{attempt: 3, min: 4 * time.Second, max: 8 * time.Second},
		{attempt: 4, min: 5 * time.Second, max: 10 * time.Second},
		{attempt: 100, min: 5 * time.Second, max: 10 * time.Second},
	}

	for _, test := range tests {
		t.Run(fmt.Sprint(test.attempt), func(t *testing.T) {
			for range 100 {
				if got := transport.backoff(test.attempt, nil); got < test.min || got > test.max {
					t.Fatalf("got %s, want between %s and %s", got, test.min, test.max)
				}
			}
		})
	}

	t.Run("retry-after is capped", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: http.StatusServiceUnavailable,
			Header:     http.Header{"Retry-After": {"3600"}},
		}

		if got, want := transport.backoff(0, resp), 10*time.Second; got != want {
			t.Errorf("got %s, want %s", got, want)
		}
	})
}

func TestRetryAfter(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	tests := []struct {
		value string
		want  time.Duration
		ok    bool
	}{
		{value: "", ok: false},
		{value: "120", want: 2 * time.Minute, ok: true},
		{value: "-1", ok: false},
		{value: "soon", ok: false},
		{value: now.Add(30 * time.Second).Format(http.TimeFormat), want: 30 * time.Second, ok: true},
		{value: now.Add(-time.Minute).Format(http.TimeFormat), want: 0, ok: true},
	}

	for _, test := range tests {
		t.Run(test.value, func(t *testing.T) {
			got, ok := retryAfter(test.value, now)
			if got != test.want || ok != test.ok {
				t.Errorf("got (%s, %t), want (%s, %t)", got, ok, test.want, test.ok)
			}
		})
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }
