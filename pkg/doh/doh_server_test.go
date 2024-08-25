package doh_test

import (
	"bytes"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/miekg/dns"
	"github.com/picatz/doh/pkg/doh"
)

func TestNewServer(t *testing.T) {
	mux := doh.NewServerMux(func(w http.ResponseWriter, r *http.Request, req *dns.Msg) (*dns.Msg, error) {
		dnsResp := new(dns.Msg).SetReply(req)

		dnsResp.Answer = []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{
					Name:   req.Question[0].Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				A: net.IPv4(8, 8, 8, 8),
			},
		}

		return dnsResp, nil
	})

	checkSuccess := func(t *testing.T, resp *http.Response) {
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("got status code %d, want %d", resp.StatusCode, http.StatusOK)
		}

		b, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}

		var dnsResp dns.Msg
		if err := dnsResp.Unpack(b); err != nil {
			t.Fatal(err)
		}

		if len(dnsResp.Answer) == 0 {
			t.Error("got no answer for known domain")
		}

		for _, answer := range dnsResp.Answer {
			if answer.Header().Rrtype != dns.TypeA {
				t.Errorf("got rrtype %d, want %d", answer.Header().Rrtype, dns.TypeA)
			}

			if answer.Header().Name != "google.com." {
				t.Errorf("got name %s, want %s", answer.Header().Name, "google.com.")
			}

			if answer.Header().Class != dns.ClassINET {
				t.Errorf("got class %d, want %d", answer.Header().Class, dns.ClassINET)
			}

			if answer.Header().Ttl != 300 {
				t.Errorf("got ttl %d, want %d", answer.Header().Ttl, 300)
			}

			if answer.(*dns.A).A.String() != "8.8.8.8" {
				t.Errorf("got ip %s, want %s", answer.(*dns.A).A.String(), "8.8.8.8")
			}
		}
	}

	tests := []struct {
		name  string
		req   *http.Request
		check func(t *testing.T, resp *http.Response)
	}{
		{
			name: "invalid request",
			req:  httptest.NewRequest(http.MethodGet, "/dns-query", nil),
			check: func(t *testing.T, resp *http.Response) {
				if resp.StatusCode != http.StatusBadRequest {
					t.Errorf("got status code %d, want %d", resp.StatusCode, http.StatusBadRequest)
				}
			},
		},
		{
			name: "valid request (GET)",
			req: func() *http.Request {
				dnsReq := dns.Msg{
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

				b, err := dnsReq.Pack()
				if err != nil {
					t.Fatal(err)
				}

				req := httptest.NewRequest(http.MethodGet, "/dns-query", nil)

				q := req.URL.Query()

				q.Set("dns", base64.RawURLEncoding.EncodeToString(b))

				req.URL.RawQuery = q.Encode()

				req.Header.Set("Content-Type", "application/dns-message")
				return req
			}(),
			check: checkSuccess,
		},
		{
			name: "valid request (POST)",
			req: func() *http.Request {
				dnsReq := dns.Msg{
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

				b, err := dnsReq.Pack()
				if err != nil {
					t.Fatal(err)
				}

				req := httptest.NewRequest(http.MethodPost, "/dns-query", bytes.NewReader(b))
				req.Header.Set("Content-Type", "application/dns-message")
				return req
			}(),
			check: checkSuccess,
		},
		{
			name: "valid request (with doh.Query)",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			rec := httptest.NewRecorder()

			mux.ServeHTTP(rec, test.req)

			test.check(t, rec.Result())
		})
	}

	t.Run("doh client query", func(t *testing.T) {
		testServer := httptest.NewServer(mux)
		defer testServer.Close()

		ctx := testContext(t)

		testServerURL := testServer.URL + "/dns-query"

		resp, err := doh.Query(ctx, testClient(t), testServerURL, &dns.Msg{
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
		})
		if err != nil {
			t.Fatal(err)
		}

		if len(resp.Answer) == 0 {
			t.Error("got no answer for known domain")
		}

		for _, answer := range resp.Answer {
			t.Logf("answer: %s", answer.String())
		}
	})
}
