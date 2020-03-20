package core

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"runtime"
	"time"
)

// UseCustomResolver sets a custom resolver for the Client's Dialer
func UseCustomResolver(resolverNetwork, resolverAddress string) {
	Dialer.Resolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			if runtime.GOOS == "windows" {
				return nil, fmt.Errorf("custom resolver is not supported on windows: https://golang.org/pkg/net/#hdr-Name_Resolution")
			}
			d := net.Dialer{
				Timeout: 30 * time.Second,
			}
			return d.DialContext(ctx, resolverNetwork, resolverAddress)
		},
	}
}

// Dialer is a custom net.Dialer
var Dialer *net.Dialer = &net.Dialer{
	Timeout:   30 * time.Second,
	KeepAlive: 30 * time.Second,
	DualStack: true,
	Resolver:  nil,
}

// Transport is a custom http.Transport
var Transport http.RoundTripper = &http.Transport{
	Proxy:                 http.ProxyFromEnvironment,
	DialContext:           (Dialer).DialContext,
	ForceAttemptHTTP2:     true,
	MaxIdleConns:          100,
	IdleConnTimeout:       90 * time.Second,
	TLSHandshakeTimeout:   10 * time.Second,
	ExpectContinueTimeout: 1 * time.Second,
}

// Client is a custom http.Client
var Client *http.Client = &http.Client{
	Transport: Transport,
	Timeout:   30 * time.Second,
}
