package doh

import (
	"encoding/base64"
	"errors"
	"io"
	"net/http"

	"github.com/miekg/dns"
)

var (
	// ErrForwarderFailed is returned when a forwarder handler fails for all servers.
	ErrForwarderFailed = errors.New("doh: forwarder handler failed for all servers")
)

// Handler is a function that handles a DNS-over-HTTPS (DoH) request.
type Handler func(w http.ResponseWriter, httpReq *http.Request, dnsReq *dns.Msg) (*dns.Msg, error)

// NewServerMux returns an HTTP server mux with an endpoint for the DoH server,
// supporting the DNS-over-HTTPS (DoH) protocol as defined in [RFC 8484].
//
// [RFC 8484]: https://tools.ietf.org/html/rfc8484
func NewServerMux(handler Handler) *http.ServeMux {
	mux := http.NewServeMux()

	mux.HandleFunc("/dns-query", func(w http.ResponseWriter, r *http.Request) {
		// https://datatracker.ietf.org/doc/html/rfc8484#section-4.1
		switch r.Method {
		case http.MethodPost:
			serverHandlePost(w, r, handler)
		case http.MethodGet:
			serverHandleGet(w, r, handler)
		default:
			http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		}
	})

	return mux
}

// serverHandlePost handles a POST request to the DoH server endpoint.
func serverHandlePost(w http.ResponseWriter, r *http.Request, handler Handler) {
	switch r.Header.Get("Content-Type") {
	case "application/dns-message":
		b, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		// Unpack the DNS message from the HTTP request.
		var dnsReq dns.Msg
		if err := dnsReq.Unpack(b); err != nil {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}

		serverHandleDNSReq(w, r, handler, &dnsReq)
	default:
		http.Error(w, http.StatusText(http.StatusUnsupportedMediaType), http.StatusUnsupportedMediaType)
	}
}

// serverHandleGet handles a GET request to the DoH server endpoint.
func serverHandleGet(w http.ResponseWriter, r *http.Request, handler Handler) {
	q := r.URL.Query()

	dnsParam := q.Get("dns")

	if dnsParam == "" {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	dnsParamDecoded, err := base64.RawURLEncoding.DecodeString(dnsParam)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	// Unpack the DNS message from the HTTP request.
	var dnsReq dns.Msg
	if err := dnsReq.Unpack(dnsParamDecoded); err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	serverHandleDNSReq(w, r, handler, &dnsReq)
}

// serverHandleDNSReq handles a DNS request to the DoH server endpoint, after unpacking the DNS message
// from a GET or POST request to the DoH server. It then calls the handler to process the DNS request,
// if one is configured, and writes the response back to the HTTP response.
func serverHandleDNSReq(w http.ResponseWriter, r *http.Request, handler Handler, dnsReq *dns.Msg) {
	if handler == nil {
		http.Error(w, http.StatusText(http.StatusNotImplemented), http.StatusNotImplemented)
		return
	}

	dnsResp, err := handler(w, r, dnsReq)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	// Pack the DNS response message into the HTTP response.
	b, err := dnsResp.Pack()
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/dns-message")
	w.WriteHeader(http.StatusOK)
	w.Write(b)

}

// Forwarder returns a DoH handler that forwards DNS queries to multiple DoH servers,
// effectively acting as a DNS-over-HTTPS (DoH) proxy with failover. It will try each server
// in order until one succeeds, or return an error if all fail.
func Forwarder(httpClient *http.Client, serverURLs ...string) Handler {
	return func(w http.ResponseWriter, r *http.Request, req *dns.Msg) (*dns.Msg, error) {
		for _, serverURL := range serverURLs {
			respMsg, err := Query(r.Context(), httpClient, serverURL, req)
			if err == nil {
				return respMsg, nil
			}
		}

		return nil, ErrForwarderFailed
	}
}
