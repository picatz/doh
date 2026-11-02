// Package federation verifies workload identity tokens against service
// accounts' trust rules, for workload identity federation: automation
// such as a GitHub Actions job or a Kubernetes pod proves who it is with
// a token from its own identity provider, instead of a stored secret.
//
// A token is accepted when it's a JWT ([RFC 7519]) signed with RS256,
// ES256, or EdDSA by a key its issuer publishes, that a rule's issuer,
// audience, subject, and claims all match, and that is current and
// short-lived. Verification follows the JWT best current practices
// ([RFC 8725]): the algorithm comes from the allowlist, never the token,
// and keys come only from the rule's JWK Set URL, or the one its issuer's
// OpenID Connect discovery document names, never from the token's own
// headers.
//
// [RFC 7519]: https://www.rfc-editor.org/rfc/rfc7519.html
// [RFC 8725]: https://www.rfc-editor.org/rfc/rfc8725.html
package federation

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/picatz/doh/internal/serviceaccount"
	"github.com/picatz/jose/pkg/jwa"
	"github.com/picatz/jose/pkg/jwk/jwkhttp"
	"github.com/picatz/jose/pkg/jwt"
)

// Algorithms are the signature algorithms accepted: those identity
// providers use. HMAC and "none" are never accepted.
var Algorithms = []jwa.Algorithm{jwa.RS256, jwa.ES256, jwa.EdDSA}

// Limits.
const (
	// Leeway is the clock skew tolerated for "exp", "nbf", and "iat".
	Leeway = 30 * time.Second

	// MaxTokenLifetime bounds how long a token may be valid for, from
	// when it was issued, or from now if it doesn't say. Workload tokens
	// last minutes or hours; one that lasts longer is more like a stored
	// secret than an identity.
	MaxTokenLifetime = 24 * time.Hour

	// MaxTokenSize bounds a token's length.
	MaxTokenSize = 16 << 10

	// fetchTimeout bounds each discovery request, retryAfter is how long
	// discovery waits after failing before trying again, and
	// maxDiscoverySize bounds a discovery document.
	fetchTimeout     = 15 * time.Second
	retryAfter       = time.Minute
	maxDiscoverySize = 256 << 10

	// maxSources bounds the issuers whose keys are cached.
	maxSources = 1024
)

// Errors. Every refusal wraps ErrRefused; a provider's keys being
// unavailable wraps ErrKeysUnavailable too, since it's not the token's
// fault.
var (
	ErrRefused         = errors.New("federation: token refused")
	ErrKeysUnavailable = errors.New("federation: the issuer's keys are unavailable")
)

// Verifier verifies workload identity tokens, caching each issuer's
// signing keys. The zero value is ready to use, and it's safe for
// concurrent use.
type Verifier struct {
	// Client fetches discovery documents and JWK Sets. If nil, a client
	// with a 15-second timeout is used.
	Client *http.Client

	// Now is the clock. If nil, time.Now is used.
	Now func() time.Time

	mu      sync.Mutex
	sources map[sourceKey]*source
}

// Verify returns the first of rules that token satisfies, and the
// token's verified claims. The error explains a refusal, for logs: it's
// not for the workload to see, since it says which check failed.
func (v *Verifier) Verify(ctx context.Context, rules []serviceaccount.TrustRule, token string) (serviceaccount.TrustRule, jwt.ClaimsSet, error) {
	if len(token) > MaxTokenSize {
		return serviceaccount.TrustRule{}, nil, fmt.Errorf("%w: it's over %d bytes", ErrRefused, MaxTokenSize)
	}
	// The unverified issuer picks which rules apply, so a token for one
	// provider never makes the server fetch another's keys. Each rule's
	// verifier checks the issuer again, once the signature verifies.
	unverified, err := jwt.Parse(token)
	if err != nil {
		return serviceaccount.TrustRule{}, nil, fmt.Errorf("%w: %w", ErrRefused, err)
	}
	issuer, _ := unverified.Claims[jwt.Issuer].(string)

	var refusals []error
	for _, r := range rules {
		if r.Issuer != issuer {
			continue
		}
		claims, err := v.verify(ctx, r, token)
		if err == nil {
			return r, claims, nil
		}
		refusals = append(refusals, fmt.Errorf("trust rule %s: %w", r.ID, err))
	}
	if len(refusals) == 0 {
		return serviceaccount.TrustRule{}, nil, fmt.Errorf("%w: no trust rule for the issuer %q", ErrRefused, issuer)
	}
	return serviceaccount.TrustRule{}, nil, fmt.Errorf("%w: %w", ErrRefused, errors.Join(refusals...))
}

// verify checks token against one rule.
func (v *Verifier) verify(ctx context.Context, r serviceaccount.TrustRule, token string) (jwt.ClaimsSet, error) {
	verifier := &jwt.Verifier{
		Keys:       v.source(r),
		Algorithms: Algorithms,
		Issuer:     r.Issuer,
		Audience:   r.Audience,
		Leeway:     Leeway,
		MaxSize:    MaxTokenSize,
		Now:        v.Now,
	}
	t, err := verifier.Verify(ctx, token)
	if errors.Is(err, jwt.ErrKeysUnavailable) {
		return nil, fmt.Errorf("%w: %w", ErrKeysUnavailable, err)
	}
	if err != nil {
		return nil, err
	}

	// The verifier required exp, and reads it, iat, and nbf as int64
	// seconds.
	seconds, ok := t.Claims[jwt.ExpirationTime].(int64)
	if !ok {
		return nil, errors.New("it has no expiry")
	}
	now, exp := v.now(), time.Unix(seconds, 0)
	from := now
	if iat, ok := t.Claims[jwt.IssuedAt].(int64); ok {
		from = time.Unix(iat, 0)
	}
	if exp.Sub(from) > MaxTokenLifetime || exp.Sub(now) > MaxTokenLifetime {
		return nil, fmt.Errorf("it's valid for over %v, too long for a workload identity", MaxTokenLifetime)
	}

	if !r.Matches(t.Claims) {
		return nil, errors.New("its subject or claims don't match")
	}
	return t.Claims, nil
}

func (v *Verifier) now() time.Time {
	if v.Now != nil {
		return v.Now()
	}
	return time.Now()
}

func (v *Verifier) client() *http.Client {
	if v.Client != nil {
		return v.Client
	}
	return &http.Client{Timeout: fetchTimeout}
}

// sourceKey identifies where an issuer's keys come from.
type sourceKey struct{ issuer, jwksURL string }

// source returns the cached key source for r.
func (v *Verifier) source(r serviceaccount.TrustRule) *source {
	key := sourceKey{r.Issuer, r.JWKSURL}
	v.mu.Lock()
	defer v.mu.Unlock()
	if s := v.sources[key]; s != nil {
		return s
	}
	if v.sources == nil || len(v.sources) >= maxSources {
		// Rules come and go; rather than track which sources they still
		// use, start over in the rare case there are too many.
		v.sources = make(map[sourceKey]*source)
	}
	s := &source{issuer: r.Issuer, jwksURL: r.JWKSURL, client: v.client(), now: v.now}
	v.sources[key] = s
	return s
}

// source is a [jwt.KeySource] for one issuer: its JWK Set, at a
// configured URL or one found by discovery, fetched and cached by
// [jwkhttp.Keys].
type source struct {
	issuer, jwksURL string
	client          *http.Client
	now             func() time.Time

	mu     sync.Mutex
	keys   *jwkhttp.Keys
	failed time.Time // when discovery last failed
	err    error     // and why
}

// Keys implements [jwt.KeySource].
func (s *source) Keys(ctx context.Context, kid string) ([]jwt.Key, error) {
	keys, err := s.resolve(ctx)
	if err != nil {
		return nil, err
	}
	return keys.Keys(ctx, kid)
}

// resolve returns the issuer's JWK Set, finding its URL by discovery if
// it wasn't configured. A failed discovery isn't retried for a minute.
func (s *source) resolve(ctx context.Context) (*jwkhttp.Keys, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.keys != nil {
		return s.keys, nil
	}
	if s.jwksURL != "" {
		s.keys = &jwkhttp.Keys{URL: s.jwksURL, Client: s.client}
		return s.keys, nil
	}
	if !s.failed.IsZero() && s.now().Sub(s.failed) < retryAfter {
		return nil, fmt.Errorf("discovery failed recently: %w", s.err)
	}

	// The fetch serves every waiting exchange, so one caller giving up
	// doesn't fail it.
	jwksURL, err := discover(context.WithoutCancel(ctx), s.client, s.issuer)
	if err != nil {
		s.failed, s.err = s.now(), err
		return nil, err
	}
	s.keys = &jwkhttp.Keys{URL: jwksURL, Client: s.client}
	return s.keys, nil
}

// discover returns the JWK Set URL in issuer's OpenID Connect discovery
// document ([OpenID Connect Discovery 1.0, Section 4]). The document must
// name issuer exactly ([Section 4.3]), and its JWK Set must be on the
// issuer's host, with the same scheme, so a document can't point the
// server elsewhere. Redirects aren't followed.
//
// [OpenID Connect Discovery 1.0, Section 4]: https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig
// [Section 4.3]: https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationValidation
func discover(ctx context.Context, client *http.Client, issuer string) (string, error) {
	iss, err := url.Parse(issuer)
	if err != nil {
		return "", fmt.Errorf("discovery: %w", err)
	}
	ctx, cancel := context.WithTimeout(ctx, fetchTimeout)
	defer cancel()

	// "If the Issuer value contains a path component, any terminating /
	// MUST be removed before appending /.well-known/openid-configuration."
	where := strings.TrimSuffix(issuer, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, where, nil)
	if err != nil {
		return "", fmt.Errorf("discovery: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	c := *client
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := c.Do(req)
	if err != nil {
		return "", fmt.Errorf("discovery: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("discovery: %s answered %s", where, resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDiscoverySize+1))
	if err != nil {
		return "", fmt.Errorf("discovery: %w", err)
	}
	if len(body) > maxDiscoverySize {
		return "", fmt.Errorf("discovery: %s is over %d bytes", where, maxDiscoverySize)
	}

	var doc struct {
		Issuer  string `json:"issuer"`
		JWKSURI string `json:"jwks_uri"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return "", fmt.Errorf("discovery: %s: %w", where, err)
	}
	if doc.Issuer != issuer {
		return "", fmt.Errorf("discovery: %s names the issuer %q, not %q", where, doc.Issuer, issuer)
	}
	jwks, err := url.Parse(doc.JWKSURI)
	switch {
	case err != nil || doc.JWKSURI == "":
		return "", fmt.Errorf("discovery: %s has no valid jwks_uri", where)
	case jwks.Scheme != iss.Scheme || !strings.EqualFold(jwks.Host, iss.Host) || jwks.User != nil || jwks.Fragment != "":
		return "", fmt.Errorf("discovery: %s puts its keys at %q, not on the issuer's host; set the rule's JWKS URL to trust it", where, doc.JWKSURI)
	}
	return doc.JWKSURI, nil
}
