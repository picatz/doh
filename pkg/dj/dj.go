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
)

// Record is a DNS record type (e.g. A, AAAA, MX, ANY).
type Record string

var (
	// RecordA is a DNS A record, which maps a domain name to IPv4 address.
	RecordA = Record("A")

	// RecordAAAA is a DNS AAAA record, which maps a domain name to IPv6 address.
	RecordAAAA = Record("AAAA")

	// RecordMX is a DNS MX record, which maps a domain name to a mail exchange server.
	RecordMX = Record("MX")

	// RecordTXT is a DNS TXT record, which maps a domain name to text data.
	RecordANY = Record("ANY")
)

// Request is a DNS query to a DoH server.
type Request struct {
	Name string // domain name (e.g. google.com)
	Type Record // record type (e.g. A, AAAA, MX, ANY)
}

// Response is a DNS response from a DoH server.
type Response struct {
	Status   int  `json:"Status"`
	TC       bool `json:"TC"`
	RD       bool `json:"RD"`
	RA       bool `json:"RA"`
	AD       bool `json:"AD"`
	CD       bool `json:"CD"`
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
