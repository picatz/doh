package doh_test

import (
	"bytes"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/miekg/dns"
	"github.com/picatz/doh/pkg/doh"
)

// fuzzQueries are seed DNS queries: ordinary, with EDNS, and malformed.
func fuzzQueries(f *testing.F) [][]byte {
	f.Helper()
	var seeds [][]byte
	for _, m := range []*dns.Msg{
		new(dns.Msg).SetQuestion("example.com.", dns.TypeA),
		new(dns.Msg).SetQuestion("xn--pple-43d.com.", dns.TypeAAAA).SetEdns0(1232, true),
		new(dns.Msg).SetQuestion(".", dns.TypeNS),
		new(dns.Msg).SetQuestion("a.b.c.d.e.f.g.example.", dns.TypeHTTPS),
	} {
		b, err := m.Pack()
		if err != nil {
			f.Fatal(err)
		}
		seeds = append(seeds, b, b[:len(b)-1])
	}
	twoQuestions := new(dns.Msg).SetQuestion("example.com.", dns.TypeA)
	twoQuestions.Question = append(twoQuestions.Question, twoQuestions.Question[0])
	b, _ := twoQuestions.Pack()
	return append(seeds, b, nil, []byte{0}, make([]byte, 12))
}

// echo answers every query with an empty reply.
func echo(_ http.ResponseWriter, _ *http.Request, q *dns.Msg) (*dns.Msg, error) {
	return new(dns.Msg).SetReply(q), nil
}

// checkResponse checks that a 200 response answers query, and that other
// statuses are errors for queries that aren't one question.
func checkResponse(t *testing.T, rec *httptest.ResponseRecorder, query []byte, decoded bool) {
	t.Helper()
	var q dns.Msg
	valid := decoded && q.Unpack(query) == nil && !q.Response && len(q.Question) == 1
	switch rec.Code {
	case http.StatusOK:
		if !valid {
			t.Fatalf("200 for an invalid query %x", query)
		}
		var resp dns.Msg
		if err := resp.Unpack(rec.Body.Bytes()); err != nil {
			t.Fatalf("response doesn't unpack: %v", err)
		}
		if resp.Id != q.Id || !resp.Response {
			t.Fatalf("response %d doesn't answer query %d", resp.Id, q.Id)
		}
		if rec.Header().Get("Content-Type") != doh.MediaType {
			t.Fatalf("Content-Type %q", rec.Header().Get("Content-Type"))
		}
	case http.StatusBadRequest, http.StatusRequestURITooLong, http.StatusRequestEntityTooLarge:
		if valid {
			t.Fatalf("%d for a valid query %x", rec.Code, query)
		}
	default:
		t.Fatalf("unexpected status %d", rec.Code)
	}
}

// FuzzHandler_Post sends POST bodies: the handler must answer exactly the
// well-formed one-question queries, never panic, and answer them with a
// response that unpacks.
func FuzzHandler_Post(f *testing.F) {
	for _, q := range fuzzQueries(f) {
		f.Add(q)
	}
	h := doh.NewHandler(echo)
	f.Fuzz(func(t *testing.T, body []byte) {
		req := httptest.NewRequest(http.MethodPost, "/dns-query", bytes.NewReader(body))
		req.Header.Set("Content-Type", doh.MediaType)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		checkResponse(t, rec, body, true)
	})
}

// FuzzHandler_Get sends the dns parameter of GET requests, as given (not
// necessarily valid base64url).
func FuzzHandler_Get(f *testing.F) {
	for _, q := range fuzzQueries(f) {
		f.Add(base64.RawURLEncoding.EncodeToString(q))
	}
	f.Add("AAAA====")
	f.Add("!!!")
	h := doh.NewHandler(echo)
	f.Fuzz(func(t *testing.T, param string) {
		req := httptest.NewRequest(http.MethodGet, "/dns-query?dns="+url.QueryEscape(param), nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		query, err := base64.RawURLEncoding.DecodeString(trimPadding(param))
		checkResponse(t, rec, query, err == nil && param != "")
	})
}

func trimPadding(s string) string {
	for len(s) > 0 && s[len(s)-1] == '=' {
		s = s[:len(s)-1]
	}
	return s
}
