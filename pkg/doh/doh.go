// Package doh provides a package DNS-over-HTTPS (DoH) client
// implementation following [RFC8484].
//
// [RFC8484]: https://tools.ietf.org/html/rfc8484
package doh

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/miekg/dns"
	"github.com/picatz/doh/pkg/dj"
)

// KnownServerURL is a known DoH server URL.
type KnownServerURL = string

const (
	Google     KnownServerURL = "https://dns.google/dns-query"
	Cloudflare KnownServerURL = "https://cloudflare-dns.com/dns-query"
	Quad9      KnownServerURL = "https://dns.quad9.net:5053/dns-query"
	OpenDNS    KnownServerURL = "https://doh.opendns.com/dns-query"
	Xfinity    KnownServerURL = "https://doh.xfinity.com/dns-query"
	AdGuard    KnownServerURL = "https://dns.adguard.com/dns-query"
	LibreDNS   KnownServerURL = "https://doh.libredns.gr/dns-query"
	NextDNS    KnownServerURL = "https://dns.nextdns.io/dns-query"
	CIRA       KnownServerURL = "https://private.canadianshield.cira.ca/dns-query"
	Mozilla    KnownServerURL = "https://mozilla.cloudflare-dns.com/dns-query"
)

// KnownServerURLs is a list of known DoH server URLs that can be used
// with the [Query] function.
var KnownServerURLs = []KnownServerURL{
	Google,
	Cloudflare,
	Quad9,
	OpenDNS,
	Xfinity,
	AdGuard,
	LibreDNS,
	NextDNS,
	CIRA,
	Mozilla,
}

var (
	// ErrFailedHTTPRequest is returned when an HTTP request fails to be created or sent.
	ErrFailedHTTPRequest = errors.New("doh: failed HTTP request")

	// ErrFailedHTTPResponseRead is returned when an HTTP response (body) fails to be read.
	ErrFailedHTTPResponseRead = errors.New("doh: failed HTTP response read")

	// ErrFailedDNSRequestPack is returned when a DNS request fails to be packed.
	ErrFailedDNSRequestPack = errors.New("doh: failed DNS request pack")

	// ErrFailedDNSResponseUnpack is returned when a DNS response fails to be unpacked.
	ErrFailedDNSResponseUnpack = errors.New("doh: failed DNS response unpack")
)

// Query performs a DNS query using a DoH server URL and a DNS message.
func Query(ctx context.Context, httpClient *http.Client, serverURL string, dnsReq dns.Msg) (*dns.Msg, error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, serverURL, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrFailedHTTPRequest, err)
	}

	httpReq.Header.Set("Accept", "application/dns-message")

	q := httpReq.URL.Query()

	dnsReqBytes, err := dnsReq.Pack()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrFailedDNSRequestPack, err)
	}

	q.Set("dns", base64.RawURLEncoding.EncodeToString(dnsReqBytes))

	httpReq.URL.RawQuery = q.Encode()

	httpResp, err := httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrFailedHTTPRequest, err)
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: %s", ErrFailedHTTPRequest, httpResp.Status)
	}

	body, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrFailedHTTPResponseRead, err)
	}

	dnsResp := &dns.Msg{}
	err = dnsResp.Unpack(body)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrFailedDNSResponseUnpack, err)
	}

	return dnsResp, nil
}

// SimpleQuery performs a DNS query using a DoH server using the
// dj (DNS JSON) format types to represent the request and response.
//
// Deprecated: this is provided for backwards compatibility with the (original)
// DoH JSON API (and doh CLI tool), but it is generally recommended to use the
// newer [RFC8484] implementation [Query] instead for new applications
// or more advanced use cases.
//
// [RFC8484]: https://tools.ietf.org/html/rfc8484
func SimpleQuery(ctx context.Context, httpClient *http.Client, server string, req *dj.Request) (*dj.Response, error) {
	dnsResp, err := Query(ctx, httpClient, server, dns.Msg{
		MsgHdr: dns.MsgHdr{
			RecursionDesired: true,
		},
		Question: []dns.Question{
			{
				Name:   dns.Fqdn(req.Name),
				Qtype:  dns.StringToType[req.Type],
				Qclass: dns.StringToClass[req.Type],
			},
		},
	})
	if err != nil {
		return nil, err
	}

	resp := &dj.Response{
		Status: int(dnsResp.Rcode),
		TC:     dnsResp.Truncated,
		RD:     dnsResp.RecursionDesired,
		RA:     dnsResp.RecursionAvailable,
		AD:     dnsResp.AuthenticatedData,
		CD:     dnsResp.CheckingDisabled,
	}

	for _, question := range dnsResp.Question {
		resp.Question = append(resp.Question, struct {
			Name string `json:"name"`
			Type int    `json:"type"`
		}{
			Name: question.Name,
			Type: int(question.Qtype),
		})
	}

	for _, answer := range dnsResp.Answer {
		var data string

		// Extract main information from the answer (IP address, etc.)
		// and add it to the response.
		switch answer := answer.(type) {
		case *dns.A:
			data = answer.A.String()
		case *dns.AAAA:
			data = answer.AAAA.String()
		case *dns.CNAME:
			data = answer.Target
		case *dns.MX:
			data = answer.Mx
		case *dns.NS:
			data = answer.Ns
		case *dns.PTR:
			data = answer.Ptr
		case *dns.SOA:
			data = answer.Ns
		case *dns.TXT:
			data = strings.Join(answer.Txt, " ")
		default:
			data = answer.String()
		}

		resp.Answer = append(resp.Answer, struct {
			Name string `json:"name"`
			Type int    `json:"type"`
			TTL  int    `json:"TTL"`
			Data string `json:"data"`
		}{
			Name: answer.Header().Name,
			Type: int(answer.Header().Rrtype),
			TTL:  int(answer.Header().Ttl),
			Data: data,
		})
	}

	return resp, nil
}
