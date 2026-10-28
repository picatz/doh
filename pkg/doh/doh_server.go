package doh

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"mime"
	"net/http"
	"strconv"
	"strings"

	"github.com/miekg/dns"
)

var (
	// ErrForwarderFailed is returned when a forwarder handler fails for all servers.
	ErrForwarderFailed = errors.New("doh: forwarder handler failed for all servers")
)

const (
	// DefaultPath is the URI path of the DoH endpoint served by [NewServerMux],
	// as suggested by [RFC 8484, Section 3].
	//
	// [RFC 8484, Section 3]: https://www.rfc-editor.org/rfc/rfc8484.html#section-3
	DefaultPath = "/dns-query"

	// MediaType is the DNS wire format media type registered by
	// [RFC 8484, Section 6].
	//
	// [RFC 8484, Section 6]: https://www.rfc-editor.org/rfc/rfc8484.html#section-6
	MediaType = "application/dns-message"

	// maxMessageSize is the largest possible DNS message, bounded by the
	// 16-bit length prefix used for DNS over TCP (RFC 1035, Section 4.2.2).
	maxMessageSize = dns.MaxMsgSize
)

// Handler is a function that handles a DNS-over-HTTPS (DoH) request.
//
// A Handler returns the DNS response to send to the client. Returning an
// error, or a nil response, results in a SERVFAIL response to the client.
// The response ID is always set to match the request ID.
type Handler func(w http.ResponseWriter, httpReq *http.Request, dnsReq *dns.Msg) (*dns.Msg, error)

// ServerOption configures the server returned by [NewServerMux].
type ServerOption func(*serverConfig)

type serverConfig struct {
	path   string
	logger *slog.Logger
}

// WithPath sets the URI path of the DoH endpoint. It defaults to [DefaultPath].
func WithPath(path string) ServerOption {
	return func(c *serverConfig) {
		c.path = path
	}
}

// WithLogger sets the logger used to report handler failures.
// By default, nothing is logged.
func WithLogger(logger *slog.Logger) ServerOption {
	return func(c *serverConfig) {
		c.logger = logger
	}
}

// NewServerMux returns an HTTP server mux with an endpoint for the DoH server,
// supporting the DNS-over-HTTPS (DoH) protocol as defined in [RFC 8484].
//
// The endpoint accepts GET requests with a base64url-encoded "dns" query
// parameter and POST requests with an [MediaType] body, as defined in
// [RFC 8484, Section 4.1]. Malformed requests are rejected with an HTTP
// client error, while DNS-level failures are reported as DNS responses with
// a 200 OK status, following [RFC 8484, Section 4.2.1].
//
// Every response carries a Cache-Control max-age no greater than the
// smallest TTL in the response, as required by [RFC 8484, Section 5.1].
//
// [RFC 8484]: https://www.rfc-editor.org/rfc/rfc8484.html
// [RFC 8484, Section 4.1]: https://www.rfc-editor.org/rfc/rfc8484.html#section-4.1
// [RFC 8484, Section 4.2.1]: https://www.rfc-editor.org/rfc/rfc8484.html#section-4.2.1
// [RFC 8484, Section 5.1]: https://www.rfc-editor.org/rfc/rfc8484.html#section-5.1
func NewServerMux(handler Handler, opts ...ServerOption) *http.ServeMux {
	config := &serverConfig{
		path:   DefaultPath,
		logger: slog.New(slog.DiscardHandler),
	}
	for _, opt := range opts {
		opt(config)
	}

	mux := http.NewServeMux()

	mux.HandleFunc("GET "+config.path, func(w http.ResponseWriter, r *http.Request) {
		dnsReq, status := parseGet(r)
		if status != http.StatusOK {
			http.Error(w, http.StatusText(status), status)
			return
		}

		serveDNS(w, r, handler, dnsReq, config.logger)
	})

	mux.HandleFunc("POST "+config.path, func(w http.ResponseWriter, r *http.Request) {
		dnsReq, status := parsePost(w, r)
		if status != http.StatusOK {
			http.Error(w, http.StatusText(status), status)
			return
		}

		serveDNS(w, r, handler, dnsReq, config.logger)
	})

	return mux
}

// parseGet extracts the DNS query from the "dns" query parameter of a GET
// request, returning an HTTP status other than 200 OK if it is invalid.
func parseGet(r *http.Request) (*dns.Msg, int) {
	param := r.URL.Query().Get("dns")
	if param == "" {
		return nil, http.StatusBadRequest
	}

	// Clients must omit padding, but tolerate it rather than fail the query.
	param = strings.TrimRight(param, "=")

	if len(param) > base64.RawURLEncoding.EncodedLen(maxMessageSize) {
		return nil, http.StatusRequestURITooLong
	}

	b, err := base64.RawURLEncoding.DecodeString(param)
	if err != nil {
		return nil, http.StatusBadRequest
	}

	return unpack(b)
}

// parsePost extracts the DNS query from the body of a POST request,
// returning an HTTP status other than 200 OK if it is invalid.
func parsePost(w http.ResponseWriter, r *http.Request) (*dns.Msg, int) {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != MediaType {
		return nil, http.StatusUnsupportedMediaType
	}

	b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxMessageSize))
	if err != nil {
		if _, ok := errors.AsType[*http.MaxBytesError](err); ok {
			return nil, http.StatusRequestEntityTooLarge
		}
		return nil, http.StatusBadRequest
	}

	return unpack(b)
}

// unpack decodes a DNS query, requiring exactly one question.
func unpack(b []byte) (*dns.Msg, int) {
	var msg dns.Msg
	if err := msg.Unpack(b); err != nil {
		return nil, http.StatusBadRequest
	}

	if msg.Response || len(msg.Question) != 1 {
		return nil, http.StatusBadRequest
	}

	return &msg, http.StatusOK
}

// serveDNS calls the handler for a parsed DNS query and writes its response,
// replying with SERVFAIL if the handler fails.
func serveDNS(w http.ResponseWriter, r *http.Request, handler Handler, dnsReq *dns.Msg, logger *slog.Logger) {
	var (
		dnsResp *dns.Msg
		err     error
	)

	if handler == nil {
		err = errors.New("doh: no handler configured")
	} else {
		dnsResp, err = handler(w, r, dnsReq)
		if err == nil && dnsResp == nil {
			err = errors.New("doh: handler returned no response")
		}
	}

	if err != nil {
		logger.WarnContext(r.Context(), "doh: handler failed",
			slog.String("name", dnsReq.Question[0].Name),
			slog.String("type", dns.TypeToString[dnsReq.Question[0].Qtype]),
			slog.Any("error", err),
		)

		dnsResp = new(dns.Msg).SetRcode(dnsReq, dns.RcodeServerFailure)
	}

	// The response must answer the client's query, whatever ID the
	// handler (or an upstream server) used.
	dnsResp.Id = dnsReq.Id

	b, err := dnsResp.Pack()
	if err != nil {
		logger.ErrorContext(r.Context(), "doh: failed to pack response", slog.Any("error", err))

		dnsResp = new(dns.Msg).SetRcode(dnsReq, dns.RcodeServerFailure)
		if b, err = dnsResp.Pack(); err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
	}

	w.Header().Set("Content-Type", MediaType)
	w.Header().Set("Content-Length", strconv.Itoa(len(b)))
	w.Header().Set("Cache-Control", "max-age="+strconv.FormatUint(uint64(maxAge(dnsResp)), 10))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(b)
}

// maxAge returns the HTTP freshness lifetime, in seconds, for a DNS response:
// the smallest TTL of any record in it, as required by RFC 8484, Section 5.1.
//
// For negative answers, the TTL of an SOA record in the authority section is
// further limited by its MINIMUM field, following RFC 2308, Section 5.
// Responses without records, and failures other than NXDOMAIN, are not
// cached.
func maxAge(msg *dns.Msg) uint32 {
	if msg.Rcode != dns.RcodeSuccess && msg.Rcode != dns.RcodeNameError {
		return 0
	}

	age, found := uint32(math.MaxUint32), false

	for _, section := range [][]dns.RR{msg.Answer, msg.Ns, msg.Extra} {
		for _, rr := range section {
			if rr.Header().Rrtype == dns.TypeOPT {
				continue
			}

			ttl := rr.Header().Ttl
			if soa, ok := rr.(*dns.SOA); ok && len(msg.Answer) == 0 {
				ttl = min(ttl, soa.Minttl)
			}

			age, found = min(age, ttl), true
		}
	}

	if !found {
		return 0
	}

	return age
}

// Forwarder returns a DoH handler that forwards DNS queries to multiple DoH servers,
// effectively acting as a DNS-over-HTTPS (DoH) proxy with failover. It will try each server
// in order until one succeeds, or return an error if all fail.
//
// The returned error matches [ErrForwarderFailed] with [errors.Is], and
// includes the error from each server.
func Forwarder(httpClient *http.Client, serverURLs ...string) Handler {
	return func(w http.ResponseWriter, r *http.Request, req *dns.Msg) (*dns.Msg, error) {
		errs := []error{ErrForwarderFailed}

		for _, serverURL := range serverURLs {
			respMsg, err := Query(r.Context(), httpClient, serverURL, req)
			if err == nil {
				return respMsg, nil
			}

			errs = append(errs, fmt.Errorf("%s: %w", serverURL, err))
		}

		return nil, errors.Join(errs...)
	}
}
