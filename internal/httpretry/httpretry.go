// Package httpretry provides an [http.RoundTripper] that retries requests
// which fail with transient network errors or retryable status codes.
//
// It composes with the standard library instead of wrapping it: install a
// [Transport] as the Transport of an ordinary [http.Client], and every caller
// that accepts an *http.Client gets retries for free.
//
//	client := &http.Client{
//		Transport: &httpretry.Transport{MaxRetries: 3},
//	}
package httpretry

import (
	"cmp"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"strconv"
	"time"
)

const (
	// DefaultMinWait is the backoff used before the first retry when
	// [Transport.MinWait] is zero.
	DefaultMinWait = 1 * time.Second

	// DefaultMaxWait is the upper bound on any single backoff when
	// [Transport.MaxWait] is zero.
	DefaultMaxWait = 30 * time.Second
)

// maxDrain bounds how much of a discarded response body is read so its
// connection can be reused, rather than closed, before the next attempt.
const maxDrain = 4 << 10

// Transport is an [http.RoundTripper] that retries requests using
// exponential backoff with jitter.
//
// A request is retried when [Retryable] reports true for its outcome, the
// request's context is still live, and its body (if any) can be replayed
// using [http.Request.GetBody], which [http.NewRequest] sets for common
// in-memory body types.
//
// Retries cover failures up to and including the response headers. The
// response body is streamed to the caller as usual, so a connection that
// fails while the caller reads the body is not retried; callers that need
// that should retry at a higher level.
//
// When retries are exhausted, RoundTrip returns the last response as-is so
// callers can inspect its status, or the last error wrapped with the number
// of attempts made.
//
// The zero value is ready to use: it performs a single attempt with
// [http.DefaultTransport], making no retries.
type Transport struct {
	// Base is the RoundTripper used for each attempt.
	// If nil, [http.DefaultTransport] is used.
	Base http.RoundTripper

	// MaxRetries is the maximum number of retries after the first attempt.
	// Zero disables retries.
	MaxRetries int

	// MinWait is the backoff before the first retry, doubling for each
	// subsequent retry. If zero, [DefaultMinWait] is used.
	MinWait time.Duration

	// MaxWait caps each backoff, including delays requested by a server's
	// Retry-After header. If zero, [DefaultMaxWait] is used.
	MaxWait time.Duration
}

// RoundTrip implements [http.RoundTripper].
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	base := t.Base
	if base == nil {
		base = http.DefaultTransport
	}

	// A body that can't be rewound can only be sent once.
	maxRetries := t.MaxRetries
	if req.Body != nil && req.Body != http.NoBody && req.GetBody == nil {
		maxRetries = 0
	}

	ctx := req.Context()

	for attempt := 0; ; attempt++ {
		attemptReq := req
		if attempt > 0 {
			var err error
			if attemptReq, err = rewind(req); err != nil {
				return nil, err
			}
		}

		resp, err := base.RoundTrip(attemptReq)

		if attempt >= maxRetries || ctx.Err() != nil || !Retryable(resp, err) {
			if err != nil && attempt > 0 {
				err = fmt.Errorf("httpretry: giving up after %d attempts: %w", attempt+1, err)
			}
			return resp, err
		}

		wait := t.backoff(attempt, resp)

		if resp != nil {
			_, _ = io.CopyN(io.Discard, resp.Body, maxDrain)
			_ = resp.Body.Close()
		}

		if err := sleep(ctx, wait); err != nil {
			return nil, err
		}
	}
}

// Retryable reports whether a request that produced resp and err is worth
// retrying, following the conventions of most HTTP retry clients:
//
//   - Network errors ([net.Error]) and connections closed before the
//     response headers are received are retryable, except DNS lookups that
//     found no such host.
//   - Other errors are not, including context cancellation and TLS
//     certificate verification failures, even when wrapped in a
//     [net.Error] such as [*net.OpError].
//   - 429 Too Many Requests and 5xx status codes are retryable, except
//     501 Not Implemented.
func Retryable(resp *http.Response, err error) bool {
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return false
		}

		if isCertificateError(err) {
			return false
		}

		if dnsErr, ok := errors.AsType[*net.DNSError](err); ok {
			return !dnsErr.IsNotFound
		}

		if _, ok := errors.AsType[net.Error](err); ok {
			return true
		}

		return errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)
	}

	switch code := resp.StatusCode; {
	case code == http.StatusTooManyRequests:
		return true
	case code == http.StatusNotImplemented:
		return false
	default:
		return code >= 500
	}
}

// isCertificateError reports whether err stems from TLS certificate
// verification, which fails the same way on every attempt.
func isCertificateError(err error) bool {
	if _, ok := errors.AsType[*tls.CertificateVerificationError](err); ok {
		return true
	}

	if _, ok := errors.AsType[x509.UnknownAuthorityError](err); ok {
		return true
	}

	if _, ok := errors.AsType[x509.HostnameError](err); ok {
		return true
	}

	_, ok := errors.AsType[x509.CertificateInvalidError](err)
	return ok
}

// backoff returns how long to wait before retry number attempt+1, honoring
// the response's Retry-After header for 429 and 503 status codes.
func (t *Transport) backoff(attempt int, resp *http.Response) time.Duration {
	minWait := cmp.Or(t.MinWait, DefaultMinWait)
	maxWait := cmp.Or(t.MaxWait, DefaultMaxWait)

	if resp != nil && (resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusServiceUnavailable) {
		if d, ok := retryAfter(resp.Header.Get("Retry-After"), time.Now()); ok {
			return min(d, maxWait)
		}
	}

	// Double the wait each attempt, guarding the shift against overflow.
	wait := maxWait
	if attempt < 62 && minWait <= maxWait>>attempt {
		wait = minWait << attempt
	}

	// Equal jitter: wait between half and all of the computed backoff, so
	// concurrent clients don't retry in lockstep.
	half := wait / 2
	return half + rand.N(wait-half+1)
}

// retryAfter parses a Retry-After header value, which is either a number of
// seconds or an HTTP date, as defined by RFC 9110, Section 10.2.3.
//
// See https://www.rfc-editor.org/rfc/rfc9110.html#section-10.2.3
func retryAfter(value string, now time.Time) (time.Duration, bool) {
	if value == "" {
		return 0, false
	}

	if seconds, err := strconv.ParseUint(value, 10, 32); err == nil {
		return time.Duration(seconds) * time.Second, true
	}

	if date, err := http.ParseTime(value); err == nil {
		return max(date.Sub(now), 0), true
	}

	return 0, false
}

// rewind returns a copy of req with a fresh body for another attempt.
func rewind(req *http.Request) (*http.Request, error) {
	r := req.Clone(req.Context())

	if req.GetBody != nil {
		body, err := req.GetBody()
		if err != nil {
			return nil, fmt.Errorf("httpretry: rewinding request body: %w", err)
		}
		r.Body = body
	}

	return r, nil
}

// sleep waits for d, returning early with the context's error if it is done.
func sleep(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()

	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
