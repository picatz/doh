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

// Request is a DNS query to a DoH server using the JSON API.
type Request struct {
	Name string // domain name (e.g. google.com)
	Type string // record type (e.g. A, AAAA, MX, ANY)
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
