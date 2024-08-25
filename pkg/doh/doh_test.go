package doh_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/hashicorp/go-cleanhttp"
	"github.com/hashicorp/go-retryablehttp"
	"github.com/miekg/dns"
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
	req    dns.Msg
} {
	var tests []struct {
		name   string
		server string
		req    dns.Msg
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
			name:   "quad9",
			server: "https://dns.quad9.net/dns-query",
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
				req := dns.Msg{
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
					req    dns.Msg
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

// testClient returns a new HTTP client with retryablehttp settings
// for testing purposes with a cleanhttp.DefaultClient as the base.
// It also sets the retry max to 10 for testing purposes, allowing
// for more retries in case of network issues or other problems,
// preventing flaky tests.
func testClient(t *testing.T) *http.Client {
	t.Helper()

	retryClient := retryablehttp.NewClient()

	retryClient.RetryMax = 10

	retryClient.HTTPClient = cleanhttp.DefaultClient()

	retryClient.Logger = nil

	retryClient.CheckRetry = func(ctx context.Context, resp *http.Response, err error) (bool, error) {
		return retryablehttp.DefaultRetryPolicy(ctx, resp, err)
	}

	retryClient.Backoff = func(min, max time.Duration, attemptNum int, resp *http.Response) time.Duration {
		return retryablehttp.DefaultBackoff(min, max, attemptNum, resp)
	}

	retryClient.ErrorHandler = func(resp *http.Response, err error, numTries int) (*http.Response, error) {
		return nil, err
	}

	return retryClient.StandardClient()
}

func TestQuery(t *testing.T) {
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

func TestSimpleQuery(t *testing.T) {
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

func TestKnownServers_Query(t *testing.T) {
	ctx := testContext(t)

	client := testClient(t)

	for _, server := range doh.KnownServerURLs {
		server := server
		t.Run(server, func(t *testing.T) {
			t.Parallel()

			req := dns.Msg{
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
