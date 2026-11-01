// Package client is a typed client for the admin API that "doh serve"
// exposes on its admin listener. See package [api] for the endpoints.
package client

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"iter"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/picatz/doh/internal/api"
	"github.com/picatz/doh/internal/policy"
	"github.com/picatz/doh/internal/querylog"
)

// DefaultAddr is the admin listener address clients use by default.
const DefaultAddr = "http://127.0.0.1:9090"

// MaxResponseSize bounds the size of a response body the client reads, so a
// misbehaving server can't exhaust memory.
const MaxResponseSize = 32 << 20

// defaultTimeout bounds each request when HTTPClient is nil, except
// streams, which last until their context is done.
const defaultTimeout = 30 * time.Second

// userAgent identifies the client to servers.
const userAgent = "doh-cli"

// Client calls the admin API of a doh server.
type Client struct {
	// Addr is the server's base URL, such as "http://127.0.0.1:9090".
	// If empty, [DefaultAddr] is used.
	Addr string

	// Token is the bearer token sent with every request. Since it's a
	// credential, it's only sent over HTTPS, or plain HTTP to a loopback
	// address.
	Token string

	// HTTPClient sends requests. If nil, a client with a 30-second timeout
	// is used, and streams use a client without one.
	HTTPClient *http.Client
}

// Error is an error response from the API.
type Error struct {
	// Status is the HTTP status code.
	Status int

	// Message and Details are the response's [api.Error] fields.
	Message string
	Details []string
}

// Error implements the error interface, as "doh: 403 Forbidden: message:
// detail; detail".
func (e *Error) Error() string {
	msg := fmt.Sprintf("doh: %d %s", e.Status, http.StatusText(e.Status))
	if e.Message != "" {
		msg += ": " + e.Message
	}
	if len(e.Details) > 0 {
		msg += ": " + strings.Join(e.Details, "; ")
	}
	return msg
}

// IsLoopback reports whether host, a host name or address without a port,
// refers to the local machine.
func IsLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") || strings.HasSuffix(strings.ToLower(host), ".localhost") {
		return true
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && ip.IsLoopback()
}

// base returns the parsed server URL, refusing to send a token over plain
// HTTP to a remote host.
func (c *Client) base() (*url.URL, error) {
	addr := c.Addr
	if addr == "" {
		addr = DefaultAddr
	}
	if !strings.Contains(addr, "://") {
		addr = "http://" + addr
	}

	u, err := url.Parse(addr)
	if err != nil {
		return nil, fmt.Errorf("doh: invalid address %q: %w", c.Addr, err)
	}

	switch u.Scheme {
	case "https":
	case "http":
		if c.Token != "" && !IsLoopback(u.Hostname()) {
			return nil, fmt.Errorf("doh: refusing to send the API token over plain HTTP to %s; use https:// or a loopback address (such as an SSH tunnel)", u.Host)
		}
	default:
		return nil, fmt.Errorf("doh: address %q must be an http or https URL", c.Addr)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("doh: address %q has no host", c.Addr)
	}

	u.Path = strings.TrimSuffix(u.Path, "/")
	return u, nil
}

// request builds a request for path, relative to [api.Prefix], with query
// parameters q.
func (c *Client) request(ctx context.Context, method, path string, q url.Values, body io.Reader) (*http.Request, error) {
	u, err := c.base()
	if err != nil {
		return nil, err
	}
	u = u.JoinPath(api.Prefix)
	// JoinPath would unescape the segments path carries escaped, so set the
	// raw path explicitly.
	u.RawPath = u.EscapedPath() + path
	u.Path, err = url.PathUnescape(u.RawPath)
	if err != nil {
		return nil, err
	}
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "application/json")
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	return req, nil
}

func (c *Client) httpClient(stream bool) *http.Client {
	switch {
	case c.HTTPClient != nil:
		return c.HTTPClient
	case stream:
		return &http.Client{}
	default:
		return &http.Client{Timeout: defaultTimeout}
	}
}

// do sends req and decodes a successful JSON response into out, unless
// out is nil, returning the response headers.
func (c *Client) do(req *http.Request, out any) (http.Header, error) {
	resp, err := c.httpClient(false).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxResponseSize+1))
	if err != nil {
		return nil, err
	}
	if len(body) > MaxResponseSize {
		return nil, fmt.Errorf("doh: response exceeds %d bytes", MaxResponseSize)
	}

	if resp.StatusCode >= 300 {
		return resp.Header, decodeError(resp.StatusCode, body)
	}

	if out != nil && resp.StatusCode != http.StatusNoContent {
		if err := json.Unmarshal(body, out); err != nil {
			return resp.Header, fmt.Errorf("doh: decoding response: %w", err)
		}
	}
	return resp.Header, nil
}

// decodeError turns an error response into an [*Error], using the body as
// the message if it isn't an [api.Error].
func decodeError(status int, raw []byte) error {
	var body api.Error
	if err := json.Unmarshal(raw, &body); err != nil || body.Error == "" {
		body = api.Error{Error: strings.TrimSpace(string(raw))}
	}
	return &Error{Status: status, Message: body.Error, Details: body.Details}
}

// call sends a request with an optional JSON body of contentType.
func (c *Client) call(ctx context.Context, method, path string, q url.Values, in any, contentType string, header http.Header, out any) (http.Header, error) {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return nil, err
		}
		body = bytes.NewReader(b)
	}

	req, err := c.request(ctx, method, path, q, body)
	if err != nil {
		return nil, err
	}
	if in != nil {
		req.Header.Set("Content-Type", contentType)
	}
	for k, v := range header {
		req.Header[k] = v
	}
	return c.do(req, out)
}

func (c *Client) get(ctx context.Context, path string, q url.Values, out any) (http.Header, error) {
	return c.call(ctx, http.MethodGet, path, q, nil, "", nil, out)
}

// segment escapes s as a single path segment.
func segment(s string) string { return "/" + url.PathEscape(s) }

// Status returns the server's status.
func (c *Client) Status(ctx context.Context) (*api.Status, error) {
	var s api.Status
	if _, err := c.get(ctx, "/status", nil, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

// Catalog returns the features and blocklist presets profiles can use.
func (c *Client) Catalog(ctx context.Context) (*api.Catalog, error) {
	var cat api.Catalog
	if _, err := c.get(ctx, "/catalog", nil, &cat); err != nil {
		return nil, err
	}
	return &cat, nil
}

// Policy returns the server's policy and its entity tag.
func (c *Client) Policy(ctx context.Context) (*policy.Policy, string, error) {
	var p policy.Policy
	h, err := c.get(ctx, "/policy", nil, &p)
	if err != nil {
		return nil, "", err
	}
	return &p, h.Get("ETag"), nil
}

// PutPolicy replaces the server's policy with p. If ifMatch is set, the
// change is made only if the policy's entity tag still matches it.
func (c *Client) PutPolicy(ctx context.Context, p *policy.Policy, ifMatch string) (*policy.Policy, string, error) {
	header := http.Header{}
	if ifMatch != "" {
		header.Set("If-Match", ifMatch)
	}
	var out policy.Policy
	h, err := c.call(ctx, http.MethodPut, "/policy", nil, p, "application/json", header, &out)
	if err != nil {
		return nil, "", err
	}
	return &out, h.Get("ETag"), nil
}

// Profiles returns every profile.
func (c *Client) Profiles(ctx context.Context) ([]policy.Profile, error) {
	var ps api.Profiles
	if _, err := c.get(ctx, "/profiles", nil, &ps); err != nil {
		return nil, err
	}
	return ps.Profiles, nil
}

// Profile returns the profile with id.
func (c *Client) Profile(ctx context.Context, id string) (*policy.Profile, error) {
	var p policy.Profile
	if _, err := c.get(ctx, "/profiles"+segment(id), nil, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

// CreateProfile adds a profile.
func (c *Client) CreateProfile(ctx context.Context, p policy.Profile) (*policy.Profile, error) {
	var out policy.Profile
	if _, err := c.call(ctx, http.MethodPost, "/profiles", nil, p, "application/json", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// PatchProfile changes the profile with id by applying patch, encoded as
// JSON, as a merge patch ([RFC 7396]).
//
// [RFC 7396]: https://www.rfc-editor.org/rfc/rfc7396.html
func (c *Client) PatchProfile(ctx context.Context, id string, patch any) (*policy.Profile, error) {
	var out policy.Profile
	if _, err := c.call(ctx, http.MethodPatch, "/profiles"+segment(id), nil, patch, api.MergePatchType, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// DeleteProfile deletes the profile with id.
func (c *Client) DeleteProfile(ctx context.Context, id string) error {
	_, err := c.call(ctx, http.MethodDelete, "/profiles"+segment(id), nil, nil, "", nil, nil)
	return err
}

// domainList adds domain to, or removes it from, a profile's list ("allow"
// or "deny").
func (c *Client) domainList(ctx context.Context, profile, list, domain string, add bool) (*policy.Profile, error) {
	var out policy.Profile
	var err error
	if add {
		_, err = c.call(ctx, http.MethodPost, "/profiles"+segment(profile)+"/"+list, nil, api.DomainRequest{Domain: domain}, "application/json", nil, &out)
	} else {
		_, err = c.call(ctx, http.MethodDelete, "/profiles"+segment(profile)+"/"+list+segment(domain), nil, nil, "", nil, &out)
	}
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// Allow adds domain to the profile's allow list, removing it from its deny
// list.
func (c *Client) Allow(ctx context.Context, profile, domain string) (*policy.Profile, error) {
	return c.domainList(ctx, profile, "allow", domain, true)
}

// Unallow removes domain from the profile's allow list.
func (c *Client) Unallow(ctx context.Context, profile, domain string) (*policy.Profile, error) {
	return c.domainList(ctx, profile, "allow", domain, false)
}

// Deny adds domain to the profile's deny list, removing it from its allow
// list.
func (c *Client) Deny(ctx context.Context, profile, domain string) (*policy.Profile, error) {
	return c.domainList(ctx, profile, "deny", domain, true)
}

// Undeny removes domain from the profile's deny list.
func (c *Client) Undeny(ctx context.Context, profile, domain string) (*policy.Profile, error) {
	return c.domainList(ctx, profile, "deny", domain, false)
}

// Logs returns a page of query log entries matching the filter parameters
// in f, newest first.
func (c *Client) Logs(ctx context.Context, f url.Values) (*querylog.Page, error) {
	var page querylog.Page
	if _, err := c.get(ctx, "/logs", f, &page); err != nil {
		return nil, err
	}
	return &page, nil
}

// Stats returns query log statistics for entries matching the filter
// parameters in f.
func (c *Client) Stats(ctx context.Context, f url.Values) (*querylog.Stats, error) {
	var s querylog.Stats
	if _, err := c.get(ctx, "/stats", f, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

// Explain traces how the server would answer a query for name and qtype,
// as a client of profile or with address client, if set.
func (c *Client) Explain(ctx context.Context, name, qtype, profile, client string) (*api.Explanation, error) {
	q := url.Values{"name": {name}}
	for k, v := range map[string]string{"type": qtype, "profile": profile, "client": client} {
		if v != "" {
			q.Set(k, v)
		}
	}
	var e api.Explanation
	if _, err := c.get(ctx, "/explain", q, &e); err != nil {
		return nil, err
	}
	return &e, nil
}

// Stream returns live query log entries matching the filter parameters in
// f, as the server sends them as server-sent events. The sequence ends
// when ctx is done, the server closes the stream, or an error occurs,
// which is yielded last. Stopping the iteration closes the stream.
func (c *Client) Stream(ctx context.Context, f url.Values) iter.Seq2[querylog.Entry, error] {
	return func(yield func(querylog.Entry, error) bool) {
		ctx, cancel := context.WithCancel(ctx)
		defer cancel()

		req, err := c.request(ctx, http.MethodGet, "/logs/stream", f, nil)
		if err != nil {
			yield(querylog.Entry{}, err)
			return
		}
		req.Header.Set("Accept", "text/event-stream")

		resp, err := c.httpClient(true).Do(req)
		if err != nil {
			if ctx.Err() == nil {
				yield(querylog.Entry{}, err)
			}
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
			yield(querylog.Entry{}, decodeError(resp.StatusCode, body))
			return
		}

		for ev, err := range events(resp.Body) {
			if err != nil {
				if ctx.Err() == nil {
					yield(querylog.Entry{}, err)
				}
				return
			}
			if ev.name != "" && ev.name != "entry" {
				continue
			}
			var e querylog.Entry
			if err := json.Unmarshal([]byte(ev.data), &e); err != nil {
				yield(querylog.Entry{}, fmt.Errorf("doh: decoding stream entry: %w", err))
				return
			}
			if !yield(e, nil) {
				return
			}
		}
	}
}

// event is a server-sent event.
type event struct {
	name, data string
}

// maxEventSize bounds a single server-sent event.
const maxEventSize = 1 << 20

// events parses server-sent events from r, as the HTML Living Standard's
// event stream format describes: "field: value" lines, with events
// separated by blank lines, comments starting with ":", and multiple data
// lines joined by newlines.
func events(r io.Reader) iter.Seq2[event, error] {
	return func(yield func(event, error) bool) {
		sc := bufio.NewScanner(r)
		sc.Buffer(make([]byte, 0, 64<<10), maxEventSize)

		var (
			ev      event
			data    []string
			hasData bool
		)
		for sc.Scan() {
			line := strings.TrimSuffix(sc.Text(), "\r")
			if line == "" {
				if hasData {
					ev.data = strings.Join(data, "\n")
					if !yield(ev, nil) {
						return
					}
				}
				ev, data, hasData = event{}, nil, false
				continue
			}
			if strings.HasPrefix(line, ":") {
				continue
			}

			field, value, _ := strings.Cut(line, ":")
			value = strings.TrimPrefix(value, " ")
			switch field {
			case "event":
				ev.name = value
			case "data":
				data, hasData = append(data, value), true
			}
		}
		if err := sc.Err(); err != nil && !errors.Is(err, context.Canceled) {
			yield(event{}, err)
		}
	}
}
