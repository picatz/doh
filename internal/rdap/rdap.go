// Package rdap looks up domain registration dates using the Registration
// Data Access Protocol (RDAP), to power "newly registered domain"
// protection without relying on third-party feeds.
//
// The RDAP server for a domain is found through IANA's DNS bootstrap
// registry ([RFC 9224]), and the registration date is read from the
// "registration" event of the domain object ([RFC 9083, Section 4.5]).
//
// Not every top-level domain offers RDAP: generic TLDs are required to,
// but many country-code TLDs don't. Lookups for those fail with
// [ErrUnsupported], so callers should fail open.
//
// Lookups reveal the registrable domain being looked up (not who asked for
// it) to the registry's RDAP server.
//
// [RFC 9224]: https://www.rfc-editor.org/rfc/rfc9224.html
// [RFC 9083, Section 4.5]: https://www.rfc-editor.org/rfc/rfc9083.html#section-4.5
package rdap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

// DefaultBootstrapURL is IANA's DNS bootstrap registry, which maps
// top-level domains to their RDAP servers, as described by
// [RFC 9224, Section 4].
//
// [RFC 9224, Section 4]: https://www.rfc-editor.org/rfc/rfc9224.html#section-4
const DefaultBootstrapURL = "https://data.iana.org/rdap/dns.json"

var (
	// ErrUnsupported reports that a domain's top-level domain has no RDAP
	// service in the bootstrap registry.
	ErrUnsupported = errors.New("rdap: no RDAP service for top-level domain")

	// ErrNotFound reports that an RDAP server answered 404 Not Found for a
	// domain, as [RFC 7480, Section 5.3] describes for unknown objects.
	//
	// [RFC 7480, Section 5.3]: https://www.rfc-editor.org/rfc/rfc7480.html#section-5.3
	ErrNotFound = errors.New("rdap: domain not found")

	// errNoRegistration reports a domain object without a usable
	// registration event.
	errNoRegistration = errors.New("rdap: no registration event")
)

// rateLimitedError reports an HTTP 429 Too Many Requests response from an
// RDAP server, as [RFC 7480, Section 5.5] describes.
//
// [RFC 7480, Section 5.5]: https://www.rfc-editor.org/rfc/rfc7480.html#section-5.5
type rateLimitedError struct{ host string }

func (e *rateLimitedError) Error() string { return "rdap: rate limited by " + e.host }

const (
	// mediaType is the RDAP media type ([RFC 7480, Section 4.2]).
	//
	// [RFC 7480, Section 4.2]: https://www.rfc-editor.org/rfc/rfc7480.html#section-4.2
	mediaType = "application/rdap+json"

	userAgent = "doh (+https://github.com/picatz/doh)"

	// maxBodySize bounds every RDAP and bootstrap response.
	maxBodySize = 1 << 20

	// maxRedirects bounds the redirects followed for one request.
	maxRedirects = 3

	// bootstrapTTL is how long a fetched bootstrap registry is used before
	// it's refreshed.
	bootstrapTTL = 24 * time.Hour

	// bootstrapRetry is how long a failed bootstrap fetch is remembered
	// before trying again.
	bootstrapRetry = time.Minute

	defaultHTTPTimeout = 5 * time.Second
)

// Client looks up domain registration dates over RDAP. The zero value is
// ready to use, and a Client is safe for concurrent use.
type Client struct {
	// HTTPClient makes requests. If nil, a client with a 5 second timeout
	// is used. Its CheckRedirect is replaced to follow at most 3 redirects,
	// to https URLs only.
	HTTPClient *http.Client

	// BootstrapURL locates the DNS bootstrap registry. If empty,
	// [DefaultBootstrapURL] is used. When it's an http URL, as in tests,
	// http service URLs are allowed too; otherwise only https ones are.
	BootstrapURL string

	now func() time.Time // for tests

	group singleflight.Group

	mu        sync.Mutex
	services  map[string]*url.URL // by TLD (possibly multi-label), lower case
	fetched   time.Time           // when services was fetched
	failed    time.Time           // when the last fetch failed
	failedErr error
}

func (c *Client) bootstrapURL() string {
	if c.BootstrapURL == "" {
		return DefaultBootstrapURL
	}
	return c.BootstrapURL
}

// allowHTTP reports whether plain http service URLs are acceptable, which
// is only the case when the bootstrap registry itself is served over http.
func (c *Client) allowHTTP() bool {
	return strings.HasPrefix(strings.ToLower(c.bootstrapURL()), "http://")
}

func (c *Client) clock() time.Time {
	if c.now != nil {
		return c.now()
	}
	return time.Now()
}

// httpClient returns a copy of the configured client that follows only a
// few redirects, and only to acceptable schemes.
func (c *Client) httpClient() *http.Client {
	hc := &http.Client{Timeout: defaultHTTPTimeout}
	if c.HTTPClient != nil {
		copied := *c.HTTPClient
		hc = &copied
	}

	allowHTTP := c.allowHTTP()
	hc.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= maxRedirects {
			return fmt.Errorf("rdap: stopped after %d redirects", maxRedirects)
		}
		if !schemeAllowed(req.URL, allowHTTP) {
			return fmt.Errorf("rdap: refusing redirect to %s URL", req.URL.Scheme)
		}
		return nil
	}

	return hc
}

func schemeAllowed(u *url.URL, allowHTTP bool) bool {
	switch u.Scheme {
	case "https":
		return true
	case "http":
		return allowHTTP
	default:
		return false
	}
}

// Registered returns the registration time of domain, a registrable domain
// such as "example.com" (without a trailing dot), from the "registration"
// event of its RDAP domain object ([RFC 9083, Section 4.5]).
//
// It fails with [ErrUnsupported] if the domain's top-level domain has no
// RDAP service, and with [ErrNotFound] if the server doesn't know the
// domain.
//
// [RFC 9083, Section 4.5]: https://www.rfc-editor.org/rfc/rfc9083.html#section-4.5
func (c *Client) Registered(ctx context.Context, domain string) (time.Time, error) {
	domain, err := normalize(domain)
	if err != nil {
		return time.Time{}, err
	}

	base, err := c.serviceURL(ctx, domain)
	if err != nil {
		return time.Time{}, err
	}

	return c.registered(ctx, base, domain)
}

// normalize lower-cases domain and trims a trailing dot, rejecting
// anything but an ASCII (A-label) domain name, so it's safe to put in a
// URL path.
func normalize(domain string) (string, error) {
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	if domain == "" || len(domain) > 253 {
		return "", fmt.Errorf("rdap: invalid domain %q", domain)
	}

	for label := range strings.SplitSeq(domain, ".") {
		if label == "" || len(label) > 63 {
			return "", fmt.Errorf("rdap: invalid domain %q", domain)
		}
		for _, b := range []byte(label) {
			if !('a' <= b && b <= 'z' || '0' <= b && b <= '9' || b == '-' || b == '_') {
				return "", fmt.Errorf("rdap: invalid domain %q", domain)
			}
		}
	}

	return domain, nil
}

// serviceURL returns the base RDAP URL serving domain: the entry for the
// longest matching TLD in the bootstrap registry ([RFC 9224, Section 4]).
//
// [RFC 9224, Section 4]: https://www.rfc-editor.org/rfc/rfc9224.html#section-4
func (c *Client) serviceURL(ctx context.Context, domain string) (*url.URL, error) {
	services, err := c.bootstrap(ctx)
	if err != nil {
		return nil, err
	}

	// Try "a.b.example", then "b.example", then "example": the first hit
	// is the longest match.
	for suffix := domain; ; {
		if u, ok := services[suffix]; ok {
			return u, nil
		}
		_, parent, found := strings.Cut(suffix, ".")
		if !found {
			return nil, fmt.Errorf("%w: %s", ErrUnsupported, suffix)
		}
		suffix = parent
	}
}

// bootstrap returns the TLD-to-service map, fetching it if it's missing or
// stale. A failed refresh keeps the previous map.
func (c *Client) bootstrap(ctx context.Context) (map[string]*url.URL, error) {
	now := c.clock()

	c.mu.Lock()
	services, fetched, failed, failedErr := c.services, c.fetched, c.failed, c.failedErr
	c.mu.Unlock()

	if services != nil && now.Sub(fetched) < bootstrapTTL {
		return services, nil
	}
	if !failed.IsZero() && now.Sub(failed) < bootstrapRetry {
		if services != nil {
			return services, nil
		}
		return nil, failedErr
	}

	ch := c.group.DoChan("bootstrap", func() (any, error) {
		// Don't let one caller's cancellation fail the others.
		fetchCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), defaultHTTPTimeout)
		defer cancel()
		return c.fetchBootstrap(fetchCtx)
	})

	select {
	case <-ctx.Done():
		if services != nil {
			return services, nil
		}
		return nil, ctx.Err()
	case res := <-ch:
		c.mu.Lock()
		defer c.mu.Unlock()

		if res.Err != nil {
			c.failed, c.failedErr = c.clock(), res.Err
			if c.services != nil {
				return c.services, nil
			}
			return nil, res.Err
		}

		m := res.Val.(map[string]*url.URL)
		c.services, c.fetched, c.failed, c.failedErr = m, c.clock(), time.Time{}, nil
		return m, nil
	}
}

// bootstrapFile is the JSON form of a bootstrap registry
// ([RFC 9224, Section 3]): each service is a pair of a list of entries
// (TLDs) and a list of base URLs.
//
// [RFC 9224, Section 3]: https://www.rfc-editor.org/rfc/rfc9224.html#section-3
type bootstrapFile struct {
	Services [][][]string `json:"services"`
}

// fetchBootstrap downloads and parses the bootstrap registry.
func (c *Client) fetchBootstrap(ctx context.Context) (map[string]*url.URL, error) {
	body, err := c.get(ctx, c.bootstrapURL(), "application/json")
	if err != nil {
		return nil, fmt.Errorf("rdap: bootstrap: %w", err)
	}

	return parseBootstrap(body, c.allowHTTP())
}

// parseBootstrap parses a bootstrap registry, choosing for each TLD the
// first https base URL (or http, if allowHTTP), as RFC 9224, Section 3
// recommends preferring https.
func parseBootstrap(body []byte, allowHTTP bool) (map[string]*url.URL, error) {
	var file bootstrapFile
	if err := json.Unmarshal(body, &file); err != nil {
		return nil, fmt.Errorf("rdap: parsing bootstrap: %w", err)
	}

	services := make(map[string]*url.URL)
	for _, service := range file.Services {
		if len(service) != 2 {
			continue
		}

		base := pickURL(service[1], allowHTTP)
		if base == nil {
			continue
		}

		for _, tld := range service[0] {
			tld = strings.ToLower(strings.Trim(tld, "."))
			if tld != "" {
				services[tld] = base
			}
		}
	}

	if len(services) == 0 {
		return nil, errors.New("rdap: bootstrap has no usable services")
	}

	return services, nil
}

// pickURL returns the first acceptable base URL, preferring https, with a
// trailing slash so paths can be resolved against it.
func pickURL(urls []string, allowHTTP bool) *url.URL {
	var fallback *url.URL
	for _, raw := range urls {
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" || !schemeAllowed(u, allowHTTP) {
			continue
		}
		if !strings.HasSuffix(u.Path, "/") {
			u.Path += "/"
		}
		if u.Scheme == "https" {
			return u
		}
		if fallback == nil {
			fallback = u
		}
	}
	return fallback
}

// domainObject is the subset of an RDAP domain object
// ([RFC 9083, Section 5.3]) needed here.
//
// [RFC 9083, Section 5.3]: https://www.rfc-editor.org/rfc/rfc9083.html#section-5.3
type domainObject struct {
	Events []struct {
		EventAction string `json:"eventAction"`
		EventDate   string `json:"eventDate"`
	} `json:"events"`
}

// earliestRegistration bounds plausible registration dates: the first
// domains were registered in 1985.
var earliestRegistration = time.Date(1985, 1, 1, 0, 0, 0, 0, time.UTC)

// registered queries the RDAP server at base for domain.
func (c *Client) registered(ctx context.Context, base *url.URL, domain string) (time.Time, error) {
	u := base.JoinPath("domain", domain)

	body, err := c.get(ctx, u.String(), mediaType)
	if err != nil {
		return time.Time{}, err
	}

	return parseRegistration(body, c.clock())
}

// parseRegistration returns the registration date in an RDAP domain
// object, rejecting dates before 1985 or more than a day in the future.
func parseRegistration(body []byte, now time.Time) (time.Time, error) {
	var obj domainObject
	if err := json.Unmarshal(body, &obj); err != nil {
		return time.Time{}, fmt.Errorf("rdap: parsing domain: %w", err)
	}

	for _, e := range obj.Events {
		if !strings.EqualFold(e.EventAction, "registration") {
			continue
		}

		t, err := time.Parse(time.RFC3339, e.EventDate)
		if err != nil {
			return time.Time{}, fmt.Errorf("rdap: invalid registration date: %w", err)
		}
		if t.Before(earliestRegistration) || t.After(now.Add(24*time.Hour)) {
			return time.Time{}, fmt.Errorf("rdap: implausible registration date %s", t.Format(time.RFC3339))
		}

		return t.UTC(), nil
	}

	return time.Time{}, errNoRegistration
}

// get fetches rawURL, returning its body if the response is 200 OK.
func (c *Client) get(ctx context.Context, rawURL, accept string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	if !schemeAllowed(req.URL, c.allowHTTP()) {
		return nil, fmt.Errorf("rdap: refusing %s URL %s", req.URL.Scheme, req.URL.Redacted())
	}
	req.Header.Set("Accept", accept)
	req.Header.Set("User-Agent", userAgent)

	resp, err := c.httpClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return nil, ErrNotFound
	case http.StatusTooManyRequests:
		return nil, &rateLimitedError{host: req.URL.Host}
	default:
		return nil, fmt.Errorf("rdap: %s: %s", req.URL.Redacted(), resp.Status)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodySize+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxBodySize {
		return nil, fmt.Errorf("rdap: response exceeds %d bytes", maxBodySize)
	}

	return body, nil
}
