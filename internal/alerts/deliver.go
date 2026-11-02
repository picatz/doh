package alerts

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// userAgent identifies deliveries.
const userAgent = "doh-alerts/1"

// maxResponseBody bounds how much of a destination's response is read.
const maxResponseBody = 64 << 10

// permanentError is a delivery failure that retrying won't fix.
type permanentError struct{ err error }

func (e permanentError) Error() string { return e.err.Error() }
func (e permanentError) Unwrap() error { return e.err }

// isPermanent reports whether err won't go away by retrying.
func isPermanent(err error) bool {
	var p permanentError
	return errors.As(err, &p)
}

// client returns the HTTP client for scope's destination at u: tenants'
// reach only public addresses, and the operator's http ones only
// loopback.
func (e *Engine) client(scope string, u *url.URL) *http.Client {
	switch {
	case scope != "":
		return e.tenantClient
	case u.Scheme == "http":
		return e.loopbackClient
	}
	return e.operatorClient
}

// post sends a to d, once.
//
// Webhooks get the alert as JSON, signed as Standard Webhooks
// (https://www.standardwebhooks.com/) describes; ntfy topics get its body
// as plain text, with its title, tags, priority, and link in headers
// (https://docs.ntfy.sh/publish/); browsers get it encrypted for them as
// a Web Push message (RFC 8291), signed with the server's VAPID key (RFC
// 8292); and email addresses get it as an email. Nothing about the alert
// is ever added to the URL.
func (e *Engine) post(ctx context.Context, scope string, d destination, a Alert) error {
	if d.Type == Email {
		return e.sendEmail(ctx, d, a)
	}
	u, err := url.Parse(d.url)
	if err != nil {
		return permanentError{err}
	}

	var req *http.Request
	header := http.Header{"User-Agent": {userAgent}}
	var body []byte
	switch d.Type {
	case Webhook:
		if body, err = json.Marshal(a, json.Deterministic(true)); err != nil {
			return permanentError{err}
		}
		now := time.Now()
		sig, err := Sign(d.secret, a.ID, now, body)
		if err != nil {
			return permanentError{err}
		}
		header.Set("Content-Type", "application/json")
		header.Set(HeaderID, a.ID)
		header.Set(HeaderTimestamp, strconv.FormatInt(now.Unix(), 10))
		header.Set(HeaderSignature, sig)
	case Ntfy:
		body = []byte(a.Body)
		header.Set("Content-Type", "text/plain; charset=utf-8")
		// ntfy decodes RFC 2047 encoded words, for titles that aren't
		// ASCII; the encoder leaves ASCII ones as they are.
		header.Set("Title", mime.BEncoding.Encode("UTF-8", a.Title))
		header.Set("Tags", ntfyTags(a))
		header.Set("Priority", ntfyPriority(a.Kind))
		if a.Details.Link != "" {
			header.Set("Click", a.Details.Link)
		}
	case Push:
		// Checked again, in case the file was edited by hand.
		if err := checkPushEndpoint(u); err != nil {
			return permanentError{err}
		}
		if req, err = e.pushRequest(ctx, d, a); err != nil {
			return err
		}
	default:
		return permanentError{fmt.Errorf("unknown destination type %q", d.Type)}
	}

	if req == nil {
		if req, err = http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(body)); err != nil {
			return permanentError{err}
		}
		req.Header = header
	}

	resp, err := e.client(scope, u).Do(req)
	if err != nil {
		// Report what went wrong without the URL, which may hold a token.
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		if errors.Is(err, errRefused) {
			return permanentError{err}
		}
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBody))

	switch code := resp.StatusCode; {
	case code >= 200 && code < 300:
		return nil
	case code >= 300 && code < 400:
		return permanentError{fmt.Errorf("the destination redirected (%s); doh doesn't follow redirects, so use the URL it redirects to", resp.Status)}
	case d.Type == Push && (code == http.StatusNotFound || code == http.StatusGone):
		// The browser unsubscribed, or its subscription expired (RFC 8030,
		// Section 7.3): nothing more is sent to it.
		e.store.markGone(scope, d.ID)
		return permanentError{fmt.Errorf("%w (%s)", errGone, resp.Status)}
	case code == http.StatusRequestTimeout || code == http.StatusTooManyRequests || code >= 500:
		err := fmt.Errorf("the destination answered %s", resp.Status)
		if after := retryAfter(resp.Header.Get("Retry-After"), time.Now()); after > 0 {
			return retryAfterError{err: err, after: after}
		}
		return err
	default:
		return permanentError{fmt.Errorf("the destination answered %s", resp.Status)}
	}
}

// sendEmail sends a to the email address d, unless it has had
// [EmailsPerAddress] this hour.
func (e *Engine) sendEmail(ctx context.Context, d destination, a Alert) error {
	if e.mailer == nil {
		return permanentError{fmt.Errorf("%w: email isn't set up on this server", ErrUnavailable)}
	}
	to := strings.TrimPrefix(d.url, "mailto:")
	if !e.emailRate.Allow(strings.ToLower(to)) {
		return permanentError{fmt.Errorf("%w: more than %d emails to this address this hour, so this one wasn't sent", ErrRateLimited, EmailsPerAddress)}
	}
	unsubscribe := ""
	if e.words.origin != "" && d.unsubscribe != "" {
		unsubscribe = strings.TrimSuffix(e.words.origin, "/") + UnsubscribePath + d.unsubscribe
	}
	msg, err := e.alertEmail(to, unsubscribe, a).bytes()
	if err != nil {
		return permanentError{err}
	}
	return e.mailer.send(ctx, to, msg)
}

// ntfyTags are an alert's ntfy tags, which ntfy shows as emoji
// (https://docs.ntfy.sh/emojis/).
func ntfyTags(a Alert) string {
	switch a.Kind {
	case KindThreat:
		return "shield"
	case KindNewDevice:
		return "new"
	case KindFailing, KindListFailed:
		return "warning"
	}
	return "doughnut"
}

// ntfyPriority is an alert's ntfy priority, from 1 (min) to 5 (max):
// threats and failing lookups are high, the rest the default.
func ntfyPriority(k Kind) string {
	switch k {
	case KindThreat, KindFailing:
		return "4"
	}
	return "3"
}
