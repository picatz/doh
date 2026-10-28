package doh_test

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/miekg/dns"
	"github.com/picatz/doh/internal/httpretry"
	"github.com/picatz/doh/pkg/dj"
	"github.com/picatz/doh/pkg/doh"
)

// queryTable is a table-driven test for testing DNS queries
// against known DoH servers with known domains and record types.
// It uses a matrix of known servers, domains, and record types
// to return a list of test cases for the test runner to execute.
var queryTable = func() []struct {
	name   string
	server string
	req    *dns.Msg
} {
	var tests []struct {
		name   string
		server string
		req    *dns.Msg
	}

	var domains = []string{
		"google.com",
		"microsoft.com",
		"apple.com",
	}

	var types = []uint16{
		dns.TypeA,
		dns.TypeAAAA,
	}

	var servers = []struct {
		name   string
		server string
	}{
		{
			name:   "google",
			server: doh.Google,
		},
		{
			name:   "cloudflare",
			server: doh.Cloudflare,
		},
		{
			name:   "quad9",
			server: doh.Quad9,
		},
		{
			name:   "canadianshield",
			server: "https://private.canadianshield.cira.ca/dns-query",
		},
		{
			name:   "adguard",
			server: "https://dns.adguard.com/dns-query",
		},
		{
			name:   "libredns",
			server: "https://doh.libredns.gr/dns-query",
		},
		{
			name:   "libredns-ads",
			server: "https://doh.libredns.gr/ads",
		},
		{
			name:   "opendns",
			server: "https://doh.opendns.com/dns-query",
		},
		{
			name:   "xfinity",
			server: "https://doh.xfinity.com/dns-query",
		},
	}

	for _, server := range servers {
		for _, domain := range domains {
			for _, qtype := range types {
				req := &dns.Msg{
					MsgHdr: dns.MsgHdr{
						RecursionDesired: true,
					},
					Question: []dns.Question{
						{
							Name:   dns.Fqdn(domain),
							Qtype:  qtype,
							Qclass: dns.ClassINET,
						},
					},
				}

				tests = append(tests, struct {
					name   string
					server string
					req    *dns.Msg
				}{
					name:   server.name + "-" + domain + "-" + dns.TypeToString[qtype],
					server: server.server,
					req:    req,
				})
			}
		}
	}

	return tests
}()

// requireLiveNetwork skips the test unless DOH_LIVE_TESTS is set, since
// public DoH resolvers are not reliably reachable from CI runners.
func requireLiveNetwork(t *testing.T) {
	t.Helper()

	if os.Getenv("DOH_LIVE_TESTS") == "" {
		t.Skip("skipping live network test; set DOH_LIVE_TESTS=1 to enable")
	}
}

// testServerURL starts a local DoH server that answers A and AAAA
// questions with documentation addresses, returning its query URL.
func testServerURL(t *testing.T) string {
	t.Helper()

	mux := doh.NewServerMux(func(w http.ResponseWriter, r *http.Request, req *dns.Msg) (*dns.Msg, error) {
		resp := new(dns.Msg).SetReply(req)
		resp.RecursionAvailable = true

		for _, q := range req.Question {
			hdr := dns.RR_Header{Name: q.Name, Rrtype: q.Qtype, Class: dns.ClassINET, Ttl: 60}

			switch q.Qtype {
			case dns.TypeA:
				resp.Answer = append(resp.Answer, &dns.A{Hdr: hdr, A: net.ParseIP("192.0.2.1")})
			case dns.TypeAAAA:
				resp.Answer = append(resp.Answer, &dns.AAAA{Hdr: hdr, AAAA: net.ParseIP("2001:db8::1")})
			}
		}

		return resp, nil
	})

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	return server.URL + "/dns-query"
}

// testContext returns a new context for testing purposes with a
// cancel function attached to the testing cleanup function.
// It also sets the deadline if one is set in the test.
func testContext(t *testing.T) context.Context {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	deadline, ok := t.Deadline()
	if ok {
		ctx, cancel = context.WithDeadline(ctx, deadline)
		t.Cleanup(cancel)
	}

	return ctx
}

// testClient returns a new HTTP client that retries failed requests,
// allowing live tests to ride out transient network issues.
func testClient(t *testing.T) *http.Client {
	t.Helper()

	return &http.Client{
		Transport: &httpretry.Transport{MaxRetries: 10},
	}
}

func TestQuery(t *testing.T) {
	ctx := testContext(t)

	client := testClient(t)

	serverURL := testServerURL(t)

	for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
		t.Run(dns.TypeToString[qtype], func(t *testing.T) {
			req := new(dns.Msg).SetQuestion("example.com.", qtype)

			resp, err := doh.Query(ctx, client, serverURL, req)
			if err != nil {
				t.Fatal(err)
			}

			if resp.Id != req.Id {
				t.Errorf("got response ID %d, want %d", resp.Id, req.Id)
			}

			if len(resp.Answer) != 1 {
				t.Fatalf("got %d answers, want 1", len(resp.Answer))
			}

			if got := resp.Answer[0].Header().Rrtype; got != qtype {
				t.Errorf("got answer type %s, want %s", dns.TypeToString[got], dns.TypeToString[qtype])
			}
		})
	}
}

func TestQuery_HTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	t.Cleanup(server.Close)

	_, err := doh.Query(testContext(t), server.Client(), server.URL, new(dns.Msg).SetQuestion("example.com.", dns.TypeA))
	if !errors.Is(err, doh.ErrFailedHTTPRequest) {
		t.Errorf("got error %v, want %v", err, doh.ErrFailedHTTPRequest)
	}
}

func TestSimpleQuery(t *testing.T) {
	ctx := testContext(t)

	resp, err := doh.SimpleQuery(ctx, testClient(t), testServerURL(t), &dj.Request{
		Name: "example.com",
		Type: "AAAA",
	})
	if err != nil {
		t.Fatal(err)
	}

	if !resp.RA {
		t.Error("got RA=false, want true")
	}

	if len(resp.Answer) != 1 {
		t.Fatalf("got %d answers, want 1", len(resp.Answer))
	}

	if got, want := resp.Answer[0].Data, "2001:db8::1"; got != want {
		t.Errorf("got answer data %q, want %q", got, want)
	}
}

func TestQuery_Live(t *testing.T) {
	requireLiveNetwork(t)

	ctx := testContext(t)

	client := testClient(t)

	for _, test := range queryTable {
		t.Run(test.name, func(t *testing.T) {
			resp, err := doh.Query(ctx, client, test.server, test.req)
			if err != nil {
				t.Error(err)
				return
			}

			if len(resp.Answer) == 0 {
				t.Error("got no answer for known domain")
			}

			for _, answer := range resp.Answer {
				t.Logf("answer: %s", answer.String())
			}
		})
	}
}

func TestSimpleQuery_Live(t *testing.T) {
	requireLiveNetwork(t)

	ctx := testContext(t)

	client := testClient(t)

	for _, test := range queryTable {
		t.Run(test.name, func(t *testing.T) {
			// Convert the DNS message to a DJ request, which is
			// a simplified version of the DNS message for DoH based
			// on the original DoH JSON API.
			req := &dj.Request{
				Name: test.req.Question[0].Name,
				Type: dns.TypeToString[test.req.Question[0].Qtype],
			}

			resp, err := doh.SimpleQuery(ctx, client, test.server, req)
			if err != nil {
				t.Error(err)
				return
			}

			if len(resp.Answer) == 0 {
				t.Error("got no answer for known domain")
			}

			for _, answer := range resp.Answer {
				t.Logf("answer: %s", answer.Data)
			}
		})
	}
}

func TestKnownServers_Query_Live(t *testing.T) {
	requireLiveNetwork(t)

	ctx := testContext(t)

	client := testClient(t)

	req := &dns.Msg{
		MsgHdr: dns.MsgHdr{
			RecursionDesired: true,
		},
		Question: []dns.Question{
			{
				Name:   dns.Fqdn("google.com"),
				Qtype:  dns.TypeA,
				Qclass: dns.ClassINET,
			},
		},
	}

	for _, server := range doh.KnownServerURLs {
		t.Run(server, func(t *testing.T) {
			t.Parallel()

			resp, err := doh.Query(ctx, client, server, req)
			if err != nil {
				t.Error(err)
				return
			}

			if len(resp.Answer) == 0 {
				t.Error("got no answer for known domain")
			}

			for _, answer := range resp.Answer {
				t.Logf("%s answer: %s", server, answer.String())
			}
		})
	}
}
