// Package dj provides a DoH JSON API client provided by some DNS providers,
// including Google, Cloudflare, and Quad9.
//
// This is different from [RFC8484], which came later,
// and became the generally accepted standard for DoH.
//
// [RFC8484]: https://tools.ietf.org/html/rfc8484
package dj

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/miekg/dns"
)

// Request is a DNS query to a DoH server using the JSON API.
type Request struct {
	Name string // domain name (e.g. google.com)
	Type string // record type (e.g. A, AAAA, MX, ANY)
}

// Msg returns the DNS query message for r, with recursion desired.
// Type is a record type name, such as "A"; "ANY" queries use class ANY.
func (r *Request) Msg() *dns.Msg {
	class := uint16(dns.ClassINET)
	if r.Type == "ANY" {
		class = dns.ClassANY
	}

	return &dns.Msg{
		RecursionDesired: true,
		Question: []dns.Question{{
			Name:   dns.Fqdn(r.Name),
			Qtype:  dns.StringToType[r.Type],
			Qclass: class,
		}},
	}
}

// Response is a DNS response from a DoH JSON API server.
type Response struct {
	Status   int  `json:"Status"` // DNS response code
	TC       bool `json:"TC"`     // Truncated
	RD       bool `json:"RD"`     // Recursion Desired
	RA       bool `json:"RA"`     // Recursion Available
	AD       bool `json:"AD"`     // Authenticated Data
	CD       bool `json:"CD"`     // Checking Disabled
	Question []struct {
		Name string `json:"name"`
		Type int    `json:"type"`
	} `json:"Question"`
	Answer []struct {
		Name string `json:"name"`
		Type int    `json:"type"`
		TTL  int    `json:"TTL"`
		Data string `json:"data"`
	} `json:"Answer"`
}

// NewResponse converts a DNS response message to the JSON API's response
// format, summarizing each answer's data, such as an address or target name.
func NewResponse(msg *dns.Msg) *Response {
	resp := &Response{
		Status: msg.Rcode,
		TC:     msg.Truncated,
		RD:     msg.RecursionDesired,
		RA:     msg.RecursionAvailable,
		AD:     msg.AuthenticatedData,
		CD:     msg.CheckingDisabled,
	}

	for _, q := range msg.Question {
		resp.Question = append(resp.Question, struct {
			Name string `json:"name"`
			Type int    `json:"type"`
		}{Name: q.Name, Type: int(q.Qtype)})
	}

	for _, rr := range msg.Answer {
		var data string
		switch rr := rr.(type) {
		case *dns.A:
			data = rr.A.String()
		case *dns.AAAA:
			data = rr.AAAA.String()
		case *dns.CNAME:
			data = rr.Target
		case *dns.MX:
			data = rr.Mx
		case *dns.NS:
			data = rr.Ns
		case *dns.PTR:
			data = rr.Ptr
		case *dns.SOA:
			data = rr.Ns
		case *dns.TXT:
			data = strings.Join(rr.Txt, " ")
		default:
			data = rr.String()
		}

		resp.Answer = append(resp.Answer, struct {
			Name string `json:"name"`
			Type int    `json:"type"`
			TTL  int    `json:"TTL"`
			Data string `json:"data"`
		}{Name: rr.Header().Name, Type: int(rr.Header().Rrtype), TTL: int(rr.Header().Ttl), Data: data})
	}

	return resp
}

// KnownServer is a known DoH server URL.
type KnownServer = string

var (
	Google     KnownServer = "https://dns.google.com/resolve"
	Cloudflare KnownServer = "https://cloudflare-dns.com/dns-query"
	Quad9      KnownServer = "https://dns.quad9.net:5053/dns-query"
)

// Query performs a DNS query using a DoH server.
func Query(ctx context.Context, httpClient *http.Client, server string, req *Request) (*Response, error) {
	// Prepare the HTTP request, including the relevant headers and query params.
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, server, nil)
	if err != nil {
		return nil, err
	}

	httpReq.Header.Set("Accept", "application/dns-json")
	httpReq.Header.Set("User-Agent", "doh")

	q := httpReq.URL.Query()
	q.Add("name", req.Name)
	q.Add("type", string(req.Type))

	httpReq.URL.RawQuery = q.Encode()

	httpResp, err := httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer httpResp.Body.Close()

	resp := &Response{}

	err = json.NewDecoder(httpResp.Body).Decode(resp)
	if err != nil {
		return nil, err
	}

	return resp, nil
}
