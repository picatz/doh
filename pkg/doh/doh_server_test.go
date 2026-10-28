package doh_test

import (
	"bytes"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
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
					RecursionDesired: true,
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
					RecursionDesired: true,
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
			RecursionDesired: true,
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

func TestForwarder(t *testing.T) {
	mux := doh.NewServerMux(doh.Forwarder(http.DefaultClient, testServerURL(t)))

	testServer := httptest.NewServer(mux)
	defer testServer.Close()

	ctx := testContext(t)

	testServerURL := testServer.URL + "/dns-query"

	resp, err := doh.Query(ctx, testClient(t), testServerURL, &dns.Msg{
		RecursionDesired: true,
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

	if len(resp.Answer) != 1 {
		t.Fatalf("got %d answers, want 1", len(resp.Answer))
	}

	if got, want := resp.Answer[0].(*dns.A).A.String(), "192.0.2.1"; got != want {
		t.Errorf("got forwarded answer %s, want %s", got, want)
	}
}

// packQuery returns the wire format of a query for name and qtype.
func packQuery(t *testing.T, name string, qtype uint16) []byte {
	t.Helper()

	msg := new(dns.Msg).SetQuestion(dns.Fqdn(name), qtype)
	msg.Id = 0xbeef

	b, err := msg.Pack()
	if err != nil {
		t.Fatal(err)
	}

	return b
}

// serve sends req to a server mux using handler and returns the response,
// along with the unpacked DNS message for successful responses.
func serve(t *testing.T, handler doh.Handler, req *http.Request) (*http.Response, *dns.Msg) {
	t.Helper()

	rec := httptest.NewRecorder()
	doh.NewServerMux(handler).ServeHTTP(rec, req)
	resp := rec.Result()

	if resp.StatusCode != http.StatusOK {
		return resp, nil
	}

	if got := resp.Header.Get("Content-Type"); got != doh.MediaType {
		t.Errorf("got Content-Type %q, want %q", got, doh.MediaType)
	}

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	if got, want := resp.Header.Get("Content-Length"), strconv.Itoa(len(b)); got != want {
		t.Errorf("got Content-Length %q, want %q", got, want)
	}

	var msg dns.Msg
	if err := msg.Unpack(b); err != nil {
		t.Fatal(err)
	}

	return resp, &msg
}

func TestNewServerMux_RequestValidation(t *testing.T) {
	answer := func(w http.ResponseWriter, r *http.Request, req *dns.Msg) (*dns.Msg, error) {
		return new(dns.Msg).SetReply(req), nil
	}

	query := packQuery(t, "example.com", dns.TypeA)

	get := func(param string) *http.Request {
		return httptest.NewRequest(http.MethodGet, "/dns-query?dns="+param, nil)
	}

	post := func(contentType string, body []byte) *http.Request {
		req := httptest.NewRequest(http.MethodPost, "/dns-query", bytes.NewReader(body))
		req.Header.Set("Content-Type", contentType)
		return req
	}

	multiQuestion := new(dns.Msg).SetQuestion("example.com.", dns.TypeA)
	multiQuestion.Question = append(multiQuestion.Question, multiQuestion.Question[0])
	multiQuestionBytes, err := multiQuestion.Pack()
	if err != nil {
		t.Fatal(err)
	}

	response := new(dns.Msg).SetQuestion("example.com.", dns.TypeA)
	response.Response = true
	responseBytes, err := response.Pack()
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		req  *http.Request
		want int
	}{
		{name: "GET", req: get(base64.RawURLEncoding.EncodeToString(query)), want: http.StatusOK},
		{name: "GET with padding", req: get(base64.URLEncoding.EncodeToString(query)), want: http.StatusOK},
		{name: "GET missing dns parameter", req: httptest.NewRequest(http.MethodGet, "/dns-query", nil), want: http.StatusBadRequest},
		{name: "GET invalid base64url", req: get("not*base64"), want: http.StatusBadRequest},
		{name: "GET invalid message", req: get(base64.RawURLEncoding.EncodeToString([]byte{1, 2, 3})), want: http.StatusBadRequest},
		{name: "GET oversized", req: get(strings.Repeat("A", base64.RawURLEncoding.EncodedLen(dns.MaxMsgSize)+1)), want: http.StatusRequestURITooLong},
		{name: "POST", req: post(doh.MediaType, query), want: http.StatusOK},
		{name: "POST media type parameters", req: post(doh.MediaType+"; charset=binary", query), want: http.StatusOK},
		{name: "POST wrong media type", req: post("application/json", query), want: http.StatusUnsupportedMediaType},
		{name: "POST missing media type", req: post("", query), want: http.StatusUnsupportedMediaType},
		{name: "POST oversized", req: post(doh.MediaType, make([]byte, dns.MaxMsgSize+1)), want: http.StatusRequestEntityTooLarge},
		{name: "POST multiple questions", req: post(doh.MediaType, multiQuestionBytes), want: http.StatusBadRequest},
		{name: "POST response message", req: post(doh.MediaType, responseBytes), want: http.StatusBadRequest},
		{name: "PUT", req: httptest.NewRequest(http.MethodPut, "/dns-query", nil), want: http.StatusMethodNotAllowed},
		{name: "unknown path", req: httptest.NewRequest(http.MethodGet, "/other", nil), want: http.StatusNotFound},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resp, _ := serve(t, answer, test.req)

			if resp.StatusCode != test.want {
				t.Errorf("got status %d, want %d", resp.StatusCode, test.want)
			}
		})
	}

	t.Run("PUT allow header", func(t *testing.T) {
		resp, _ := serve(t, answer, httptest.NewRequest(http.MethodPut, "/dns-query", nil))

		if got := resp.Header.Get("Allow"); !strings.Contains(got, http.MethodGet) || !strings.Contains(got, http.MethodPost) {
			t.Errorf("got Allow %q, want GET and POST", got)
		}
	})
}

func TestNewServerMux_ServerFailure(t *testing.T) {
	tests := []struct {
		name    string
		handler doh.Handler
	}{
		{
			name: "handler error",
			handler: func(w http.ResponseWriter, r *http.Request, req *dns.Msg) (*dns.Msg, error) {
				return nil, errors.New("upstream unavailable")
			},
		},
		{
			name: "nil response",
			handler: func(w http.ResponseWriter, r *http.Request, req *dns.Msg) (*dns.Msg, error) {
				return nil, nil
			},
		},
		{
			name:    "nil handler",
			handler: nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/dns-query", bytes.NewReader(packQuery(t, "example.com", dns.TypeA)))
			req.Header.Set("Content-Type", doh.MediaType)

			resp, msg := serve(t, test.handler, req)
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("got status %d, want %d", resp.StatusCode, http.StatusOK)
			}

			if msg.Rcode != dns.RcodeServerFailure {
				t.Errorf("got rcode %s, want SERVFAIL", dns.RcodeToString[msg.Rcode])
			}

			if msg.Id != 0xbeef {
				t.Errorf("got ID %#x, want %#x", msg.Id, 0xbeef)
			}

			if got, want := resp.Header.Get("Cache-Control"), "max-age=0"; got != want {
				t.Errorf("got Cache-Control %q, want %q", got, want)
			}
		})
	}
}

func TestNewServerMux_ResponseID(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request, req *dns.Msg) (*dns.Msg, error) {
		resp := new(dns.Msg).SetReply(req)
		resp.Id = 1234
		return resp, nil
	}

	req := httptest.NewRequest(http.MethodGet, "/dns-query?dns="+base64.RawURLEncoding.EncodeToString(packQuery(t, "example.com", dns.TypeA)), nil)

	_, msg := serve(t, handler, req)
	if msg == nil {
		t.Fatal("got no DNS response")
	}

	if msg.Id != 0xbeef {
		t.Errorf("got ID %#x, want request ID %#x", msg.Id, 0xbeef)
	}
}

func TestNewServerMux_CacheControl(t *testing.T) {
	rr := func(s string) dns.RR {
		t.Helper()

		r, err := dns.NewRR(s)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}

	tests := []struct {
		name  string
		rcode int
		ans   []dns.RR
		ns    []dns.RR
		extra []dns.RR
		want  string
	}{
		{
			name: "smallest answer TTL",
			ans:  []dns.RR{rr("example.com. 300 IN A 192.0.2.1"), rr("example.com. 60 IN A 192.0.2.2")},
			want: "max-age=60",
		},
		{
			name:  "additional section TTL",
			ans:   []dns.RR{rr("example.com. 300 IN A 192.0.2.1")},
			extra: []dns.RR{rr("ns.example.com. 30 IN A 192.0.2.53")},
			want:  "max-age=30",
		},
		{
			name:  "OPT pseudo-record ignored",
			ans:   []dns.RR{rr("example.com. 300 IN A 192.0.2.1")},
			extra: []dns.RR{&dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT, Class: 1232}}},
			want:  "max-age=300",
		},
		{
			name:  "negative answer uses SOA minimum",
			rcode: dns.RcodeNameError,
			ns:    []dns.RR{rr("example.com. 3600 IN SOA ns.example.com. admin.example.com. 1 7200 900 1209600 120")},
			want:  "max-age=120",
		},
		{
			name:  "negative answer uses SOA TTL when smaller",
			rcode: dns.RcodeNameError,
			ns:    []dns.RR{rr("example.com. 30 IN SOA ns.example.com. admin.example.com. 1 7200 900 1209600 120")},
			want:  "max-age=30",
		},
		{
			name:  "negative answer after CNAME uses SOA minimum",
			rcode: dns.RcodeNameError,
			ans:   []dns.RR{rr("www.example.com. 300 IN CNAME gone.example.com.")},
			ns:    []dns.RR{rr("example.com. 3600 IN SOA ns.example.com. admin.example.com. 1 7200 900 1209600 120")},
			want:  "max-age=120",
		},
		{
			name: "no data after CNAME uses SOA minimum",
			ans:  []dns.RR{rr("www.example.com. 300 IN CNAME example.net.")},
			ns:   []dns.RR{rr("example.net. 3600 IN SOA ns.example.net. admin.example.net. 1 7200 900 1209600 90")},
			want: "max-age=90",
		},
		{
			name: "no records",
			want: "max-age=0",
		},
		{
			name:  "refused",
			rcode: dns.RcodeRefused,
			ans:   []dns.RR{rr("example.com. 300 IN A 192.0.2.1")},
			want:  "max-age=0",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			handler := func(w http.ResponseWriter, r *http.Request, req *dns.Msg) (*dns.Msg, error) {
				resp := new(dns.Msg).SetRcode(req, test.rcode)
				resp.Answer, resp.Ns, resp.Extra = test.ans, test.ns, test.extra
				return resp, nil
			}

			req := httptest.NewRequest(http.MethodGet, "/dns-query?dns="+base64.RawURLEncoding.EncodeToString(packQuery(t, "example.com", dns.TypeA)), nil)

			resp, _ := serve(t, handler, req)

			if got := resp.Header.Get("Cache-Control"); got != test.want {
				t.Errorf("got Cache-Control %q, want %q", got, test.want)
			}
		})
	}
}

func TestNewServerMux_WithPath(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request, req *dns.Msg) (*dns.Msg, error) {
		return new(dns.Msg).SetReply(req), nil
	}

	mux := doh.NewServerMux(handler, doh.WithPath("/custom"))

	for path, want := range map[string]int{"/custom": http.StatusOK, doh.DefaultPath: http.StatusNotFound} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path+"?dns="+base64.RawURLEncoding.EncodeToString(packQuery(t, "example.com", dns.TypeA)), nil))

		if rec.Code != want {
			t.Errorf("%s: got status %d, want %d", path, rec.Code, want)
		}
	}
}

func TestForwarder_AllFail(t *testing.T) {
	failing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	t.Cleanup(failing.Close)

	handler := doh.Forwarder(failing.Client(), failing.URL+"/a", failing.URL+"/b")

	req := httptest.NewRequest(http.MethodGet, "/dns-query", nil)

	_, err := handler(httptest.NewRecorder(), req, new(dns.Msg).SetQuestion("example.com.", dns.TypeA))
	if !errors.Is(err, doh.ErrForwarderFailed) {
		t.Fatalf("got error %v, want %v", err, doh.ErrForwarderFailed)
	}

	if !errors.Is(err, doh.ErrFailedHTTPRequest) {
		t.Errorf("got error %v, want wrapped %v", err, doh.ErrFailedHTTPRequest)
	}

	for _, path := range []string{"/a", "/b"} {
		if !strings.Contains(err.Error(), failing.URL+path) {
			t.Errorf("got error %q, want mention of %s", err, failing.URL+path)
		}
	}
}

func TestForwarder_RedactsCredentials(t *testing.T) {
	failing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	t.Cleanup(failing.Close)

	serverURL := strings.Replace(failing.URL, "http://", "http://user:hunter2@", 1) + "/dns-query"

	_, err := doh.Forwarder(failing.Client(), serverURL)(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/dns-query", nil), new(dns.Msg).SetQuestion("example.com.", dns.TypeA))
	if err == nil {
		t.Fatal("expected error")
	}

	if strings.Contains(err.Error(), "hunter2") {
		t.Errorf("error %q exposes the upstream password", err)
	}

	if !strings.Contains(err.Error(), "user:xxxxx@") {
		t.Errorf("got error %q, want redacted upstream URL", err)
	}
}
