// Package client is a typed client for the admin API that "doh serve"
// exposes on its admin listener. See package [api] for the endpoints.
package client

import (
	"bufio"
	"bytes"
	"cmp"
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
	"github.com/picatz/doh/internal/serviceaccount"
	"github.com/picatz/doh/internal/signin"
	"github.com/picatz/jose/pkg/dpop"
	"github.com/picatz/jose/pkg/dpop/dpophttp"
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

	// DPoP, if set, signs a DPoP proof ([RFC 9449]) for every request, as
	// a credential bound to its key needs: Token is then sent as
	// "Authorization: DPoP <token>", with a proof bound to it
	// ([RFC 9449, Section 7.1]), and a token exchange gets an access
	// token bound to the key ([RFC 9449, Section 5]). Each proof is made
	// when its request is, and a server accepts it once, so a request
	// isn't to be sent twice.
	//
	// [RFC 9449]: https://www.rfc-editor.org/rfc/rfc9449.html
	// [RFC 9449, Section 7.1]: https://www.rfc-editor.org/rfc/rfc9449.html#section-7.1
	// [RFC 9449, Section 5]: https://www.rfc-editor.org/rfc/rfc9449.html#section-5
	DPoP *dpop.Signer

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

// base returns the parsed server URL, refusing to send a credential, such
// as the API token, over plain HTTP to a remote host.
func (c *Client) base(credential bool) (*url.URL, error) {
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
		if credential && !IsLoopback(u.Hostname()) {
			return nil, fmt.Errorf("doh: refusing to send a credential over plain HTTP to %s; use https:// or a loopback address (such as an SSH tunnel)", u.Host)
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
	return c.newRequest(ctx, method, path, q, body, c.Token, c.Token != "")
}

// newRequest builds a request as request does, sending token, if it's
// not empty, as a bearer token, or with the DPoP scheme and a proof if
// c.DPoP is set. If credential, the request carries one, so it's refused
// over plain HTTP to a remote host.
func (c *Client) newRequest(ctx context.Context, method, path string, q url.Values, body io.Reader, token string, credential bool) (*http.Request, error) {
	u, err := c.base(credential)
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
	switch {
	case c.DPoP != nil:
		proof, err := dpophttp.ProofForRequest(c.DPoP, req, dpop.ProofOptions{AccessToken: token})
		if err != nil {
			return nil, fmt.Errorf("doh: signing the DPoP proof: %w", err)
		}
		req.Header.Set(dpop.HeaderName, proof)
		if token != "" {
			req.Header.Set("Authorization", dpop.AuthorizationScheme+" "+token)
		}
	case token != "":
		req.Header.Set("Authorization", "Bearer "+token)
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

// send sends req and returns a successful response's headers and body,
// read up to [MaxResponseSize], or the error the server reported.
func (c *Client) send(req *http.Request) (http.Header, []byte, error) {
	resp, err := c.httpClient(false).Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxResponseSize+1))
	if err != nil {
		return nil, nil, err
	}
	if len(body) > MaxResponseSize {
		return nil, nil, fmt.Errorf("doh: response exceeds %d bytes", MaxResponseSize)
	}

	if resp.StatusCode >= 300 {
		return resp.Header, nil, decodeError(resp.StatusCode, body)
	}
	return resp.Header, body, nil
}

// do sends req and decodes a successful JSON response into out, unless
// out is nil, returning the response headers.
func (c *Client) do(req *http.Request, out any) (http.Header, error) {
	header, body, err := c.send(req)
	if err != nil {
		return header, err
	}

	if out != nil && len(body) > 0 {
		if err := json.Unmarshal(body, out); err != nil {
			return header, fmt.Errorf("doh: decoding response: %w", err)
		}
	}
	return header, nil
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

// Setup returns how to point a device at profile. device, if set, names
// the device in the settings, so the server's logs show it.
func (c *Client) Setup(ctx context.Context, profile, device string) (*api.Setup, error) {
	var setup api.Setup
	if _, err := c.get(ctx, "/profiles"+segment(profile)+"/setup", deviceQuery(device), &setup); err != nil {
		return nil, err
	}
	return &setup, nil
}

// MobileConfig returns an Apple configuration profile that points a device
// at profile over DNS-over-HTTPS, or with protocol "tls", DNS-over-TLS. An
// empty protocol lets the server choose, preferring DoH.
func (c *Client) MobileConfig(ctx context.Context, profile, device, protocol string) ([]byte, error) {
	q := deviceQuery(device)
	if protocol != "" {
		q.Set("protocol", protocol)
	}

	req, err := c.request(ctx, http.MethodGet, "/profiles"+segment(profile)+"/apple.mobileconfig", q, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", api.MobileConfigType)

	_, body, err := c.send(req)
	return body, err
}

// Download returns a setup file, such as a Windows setup script, from d,
// one of a platform's downloads in a Setup.
func (c *Client) Download(ctx context.Context, d api.Download) ([]byte, error) {
	u, err := url.Parse(d.Path)
	if err != nil || u.IsAbs() || u.Host != "" || !strings.HasPrefix(u.Path, api.Prefix+"/profiles/") {
		return nil, fmt.Errorf("doh: %q isn't a setup file's API path", d.Path)
	}
	req, err := c.request(ctx, http.MethodGet, strings.TrimPrefix(u.EscapedPath(), api.Prefix), u.Query(), nil)
	if err != nil {
		return nil, err
	}
	if d.ContentType != "" {
		req.Header.Set("Accept", d.ContentType)
	}
	_, body, err := c.send(req)
	return body, err
}

// SigninLink creates a single-use link that signs a browser in to the web
// UI with role: "admin", "reader", or "" for admin. With tenant, the link
// signs in to that tenant, such as to invite a household's first admin;
// only the operator may name a tenant. Only admins can create links.
func (c *Client) SigninLink(ctx context.Context, role, tenant string) (*api.SigninLink, error) {
	var link api.SigninLink
	if _, err := c.call(ctx, http.MethodPost, "/signin-links", nil, api.SigninLinkRequest{Role: role, Tenant: tenant}, "application/json", nil, &link); err != nil {
		return nil, err
	}
	return &link, nil
}

// CreateSetupLink makes a short-lived link to a page that sets a device
// up for profile, as device if it's named, on the server's public
// listener.
func (c *Client) CreateSetupLink(ctx context.Context, profile, device string) (*api.SetupLink, error) {
	var link api.SetupLink
	if _, err := c.call(ctx, http.MethodPost, "/profiles"+segment(profile)+"/setup-links", deviceQuery(device), nil, "", nil, &link); err != nil {
		return nil, err
	}
	return &link, nil
}

// Tenants returns the tenants the caller can see: every one for the
// operator, or a tenant's own.
func (c *Client) Tenants(ctx context.Context) ([]policy.Tenant, error) {
	var tenants api.Tenants
	if _, err := c.get(ctx, "/tenants", nil, &tenants); err != nil {
		return nil, err
	}
	return tenants.Tenants, nil
}

// CreateTenant adds a tenant. Only the operator can.
func (c *Client) CreateTenant(ctx context.Context, t policy.Tenant) (*policy.Tenant, error) {
	var out policy.Tenant
	if _, err := c.call(ctx, http.MethodPost, "/tenants", nil, t, "application/json", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// PatchTenant changes the tenant with id by applying patch, encoded as
// JSON, as a merge patch ([RFC 7396]). Only the operator can.
//
// [RFC 7396]: https://www.rfc-editor.org/rfc/rfc7396.html
func (c *Client) PatchTenant(ctx context.Context, id string, patch any) (*policy.Tenant, error) {
	var out policy.Tenant
	if _, err := c.call(ctx, http.MethodPatch, "/tenants"+segment(id), nil, patch, api.MergePatchType, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// DeleteTenant removes the tenant with id, which must have no profiles
// left, its people, and its service accounts. Only the operator can.
func (c *Client) DeleteTenant(ctx context.Context, id string) error {
	_, err := c.call(ctx, http.MethodDelete, "/tenants"+segment(id), nil, nil, "", nil, nil)
	return err
}

// People returns everyone who can sign in to the web UI with passkeys,
// without their credential records.
func (c *Client) People(ctx context.Context) ([]signin.Person, error) {
	var people api.People
	if _, err := c.get(ctx, "/people", nil, &people); err != nil {
		return nil, err
	}
	return people.People, nil
}

// DeletePerson removes a person and their passkeys, signing them out.
func (c *Client) DeletePerson(ctx context.Context, id string) error {
	_, err := c.call(ctx, http.MethodDelete, "/people"+segment(id), nil, nil, "", nil, nil)
	return err
}

// DeletePasskey removes one of a person's passkeys.
func (c *Client) DeletePasskey(ctx context.Context, person, passkey string) error {
	_, err := c.call(ctx, http.MethodDelete, "/people"+segment(person)+"/passkeys"+segment(passkey), nil, nil, "", nil, nil)
	return err
}

// ServiceAccounts returns the service accounts the caller can see: every
// one for the operator, or a tenant's own. Service accounts can't list
// service accounts.
func (c *Client) ServiceAccounts(ctx context.Context) ([]serviceaccount.Account, error) {
	var out api.ServiceAccounts
	if _, err := c.get(ctx, "/service-accounts", nil, &out); err != nil {
		return nil, err
	}
	return out.ServiceAccounts, nil
}

// CreateServiceAccount adds a service account, without keys.
func (c *Client) CreateServiceAccount(ctx context.Context, req api.ServiceAccountRequest) (*serviceaccount.Account, error) {
	var out serviceaccount.Account
	if _, err := c.call(ctx, http.MethodPost, "/service-accounts", nil, req, "application/json", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// DeleteServiceAccount removes a service account, revoking its keys.
func (c *Client) DeleteServiceAccount(ctx context.Context, id string) error {
	_, err := c.call(ctx, http.MethodDelete, "/service-accounts"+segment(id), nil, nil, "", nil, nil)
	return err
}

// AddServiceAccountKey adds a key to a service account. The returned
// secret is shown only this once.
func (c *Client) AddServiceAccountKey(ctx context.Context, account string, req api.KeyRequest) (*api.NewKey, error) {
	var out api.NewKey
	if _, err := c.call(ctx, http.MethodPost, "/service-accounts"+segment(account)+"/keys", nil, req, "application/json", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// RotateServiceAccountKey replaces a key with a new one, letting the old
// one work until req.PreviousExpires.
func (c *Client) RotateServiceAccountKey(ctx context.Context, account, key string, req api.RotateKeyRequest) (*api.NewKey, error) {
	var out api.NewKey
	if _, err := c.call(ctx, http.MethodPost, "/service-accounts"+segment(account)+"/keys"+segment(key)+"/rotate", nil, req, "application/json", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// DeleteServiceAccountKey revokes a key at once.
func (c *Client) DeleteServiceAccountKey(ctx context.Context, account, key string) error {
	_, err := c.call(ctx, http.MethodDelete, "/service-accounts"+segment(account)+"/keys"+segment(key), nil, nil, "", nil, nil)
	return err
}

// TrustRules returns a service account's trust rules: the workload
// identity tokens it accepts in exchange for access tokens.
func (c *Client) TrustRules(ctx context.Context, account string) ([]serviceaccount.TrustRule, error) {
	var out api.TrustRules
	if _, err := c.get(ctx, "/service-accounts"+segment(account)+"/federation", nil, &out); err != nil {
		return nil, err
	}
	return out.Rules, nil
}

// AddTrustRule adds a trust rule to a service account.
func (c *Client) AddTrustRule(ctx context.Context, account string, req api.TrustRuleRequest) (*serviceaccount.TrustRule, error) {
	var out serviceaccount.TrustRule
	if _, err := c.call(ctx, http.MethodPost, "/service-accounts"+segment(account)+"/federation", nil, req, "application/json", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// DeleteTrustRule removes a trust rule from a service account, revoking
// the access tokens it issued at once.
func (c *Client) DeleteTrustRule(ctx context.Context, account, rule string) error {
	_, err := c.call(ctx, http.MethodDelete, "/service-accounts"+segment(account)+"/federation"+segment(rule), nil, nil, "", nil, nil)
	return err
}

// tenantQuery names the tenant whose alerts a request is about, if any.
func tenantQuery(tenant string) url.Values {
	if tenant == "" {
		return nil
	}
	return url.Values{"tenant": {tenant}}
}

// Alerts returns the alert settings, destinations, and recent deliveries
// of the caller's tenant, or, for the operator, of tenant, or with tenant
// empty, the operator's own.
func (c *Client) Alerts(ctx context.Context, tenant string) (*api.Alerts, error) {
	var out api.Alerts
	if _, err := c.get(ctx, "/alerts", tenantQuery(tenant), &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// PatchAlerts changes alert settings with a JSON merge patch, such as
// {"kinds": ["threat"]}.
func (c *Client) PatchAlerts(ctx context.Context, tenant string, patch any) (*api.Alerts, error) {
	var out api.Alerts
	if _, err := c.call(ctx, http.MethodPatch, "/alerts", tenantQuery(tenant), patch, api.MergePatchType, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// AddAlertDestination adds a place to send alerts. A webhook's signing
// secret is returned only this once.
func (c *Client) AddAlertDestination(ctx context.Context, tenant string, req api.AlertDestinationRequest) (*api.NewAlertDestination, error) {
	var out api.NewAlertDestination
	if _, err := c.call(ctx, http.MethodPost, "/alerts/destinations", tenantQuery(tenant), req, "application/json", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// RemoveAlertDestination removes a place alerts are sent.
func (c *Client) RemoveAlertDestination(ctx context.Context, tenant, id string) error {
	_, err := c.call(ctx, http.MethodDelete, "/alerts/destinations"+segment(id), tenantQuery(tenant), nil, "", nil, nil)
	return err
}

// TestAlerts sends a test alert to every destination, reporting how each
// delivery went.
func (c *Client) TestAlerts(ctx context.Context, tenant string) (*api.AlertTest, error) {
	var out api.AlertTest
	if _, err := c.call(ctx, http.MethodPost, "/alerts/test", tenantQuery(tenant), nil, "", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ExchangeToken trades a workload's identity token for a service
// account's short-lived access token ([RFC 8693, Section 2]). It sends no
// API token of its own. Since the identity token is a credential, it's
// only sent over HTTPS, or plain HTTP to a loopback address. With
// c.DPoP set, it sends a DPoP proof, and the access token is bound to
// c.DPoP's key: its TokenType is "DPoP".
//
// A refusal is an [*Error] whose message is the OAuth error code and
// description ([RFC 6749, Section 5.2]).
//
// [RFC 8693, Section 2]: https://www.rfc-editor.org/rfc/rfc8693.html#section-2
// [RFC 6749, Section 5.2]: https://www.rfc-editor.org/rfc/rfc6749.html#section-5.2
func (c *Client) ExchangeToken(ctx context.Context, req api.TokenExchangeRequest) (*api.TokenResponse, error) {
	r, err := c.newRequest(ctx, http.MethodPost, "/token", nil, strings.NewReader(req.Form().Encode()), "", true)
	if err != nil {
		return nil, err
	}
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient(false).Do(r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		var e api.OAuthError
		if err := json.Unmarshal(body, &e); err != nil || e.Error == "" {
			return nil, decodeError(resp.StatusCode, body)
		}
		msg := e.Error
		if e.Description != "" {
			msg += ": " + e.Description
		}
		return nil, &Error{Status: resp.StatusCode, Message: msg}
	}
	var out api.TokenResponse
	if err := json.Unmarshal(body, &out); err != nil || out.AccessToken == "" {
		return nil, fmt.Errorf("doh: decoding the token response: %w", cmp.Or(err, errors.New("no access token")))
	}
	return &out, nil
}

// deviceQuery returns the query parameters naming device, if any.
func deviceQuery(device string) url.Values {
	q := url.Values{}
	if device != "" {
		q.Set("device", device)
	}
	return q
}

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

// ProfileVersion returns the profile with id and the entity tag of the
// policy it belongs to, for a conditional change with
// [Client.PatchProfileIf].
func (c *Client) ProfileVersion(ctx context.Context, id string) (*policy.Profile, string, error) {
	var p policy.Profile
	h, err := c.get(ctx, "/profiles"+segment(id), nil, &p)
	if err != nil {
		return nil, "", err
	}
	return &p, h.Get("ETag"), nil
}

// PatchProfileIf changes the profile with id like [Client.PatchProfile],
// but only if the policy's entity tag is still ifMatch: otherwise the
// server refuses with 412 Precondition Failed ([IsPreconditionFailed]),
// so changes made since the profile was read aren't lost.
func (c *Client) PatchProfileIf(ctx context.Context, id string, patch any, ifMatch string) (*policy.Profile, error) {
	var header http.Header
	if ifMatch != "" {
		header = http.Header{"If-Match": {ifMatch}}
	}
	var out policy.Profile
	if _, err := c.call(ctx, http.MethodPatch, "/profiles"+segment(id), nil, patch, api.MergePatchType, header, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// IsPreconditionFailed reports whether err is the server refusing a
// conditional change because the policy changed first.
func IsPreconditionFailed(err error) bool {
	var e *Error
	return errors.As(err, &e) && e.Status == http.StatusPreconditionFailed
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
