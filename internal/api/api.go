// Package api defines the JSON types and paths of the admin API that
// "doh serve" exposes on its admin listener, shared by the server, the web
// UI, and the doh CLI's client commands.
//
// Every endpoint is under [Prefix] and needs a bearer token
// ([RFC 6750, Section 2.1]) or a signed-in web UI session: admin for every
// request, or reader for GET requests only. Browsers sign in at
// signin.Prefix, with sign-in links from POST /signin-links, or passkeys. Errors are reported as an [Error]
// with a 4xx or 5xx status.
//
// The policy is versioned with entity tags: responses that return or
// change it carry an ETag header, and changes may be made conditional with
// If-Match, failing with 412 Precondition Failed if someone else changed
// it first ([RFC 9110, Section 13.1.1]). Profiles are changed with JSON
// merge patches ([RFC 7396]).
//
//	GET    /api/v1/status                         Status
//	GET    /api/v1/catalog                        Catalog
//	GET    /api/v1/policy                         policy.Policy (If-None-Match → 304)
//	PUT    /api/v1/policy                         policy.Policy
//	GET    /api/v1/profiles                       Profiles
//	POST   /api/v1/profiles                       policy.Profile → 201
//	GET    /api/v1/profiles/{id}                  policy.Profile
//	PATCH  /api/v1/profiles/{id}                  merge patch → policy.Profile
//	DELETE /api/v1/profiles/{id}                  204
//	POST   /api/v1/profiles/{id}/allow            DomainRequest → policy.Profile
//	DELETE /api/v1/profiles/{id}/allow/{domain}   policy.Profile
//	POST   /api/v1/profiles/{id}/deny             DomainRequest → policy.Profile
//	DELETE /api/v1/profiles/{id}/deny/{domain}    policy.Profile
//	GET    /api/v1/logs                           querylog.Page
//	GET    /api/v1/logs/stream                    text/event-stream of querylog.Entry
//	GET    /api/v1/stats                          querylog.Stats
//	GET    /api/v1/explain?name=&type=&profile=&client=   Explanation
//	GET    /api/v1/tenants                        Tenants
//	POST   /api/v1/tenants                        policy.Tenant → 201 (operator)
//	PATCH  /api/v1/tenants/{id}                   merge patch → policy.Tenant (operator)
//	DELETE /api/v1/tenants/{id}                   204 (operator)
//	POST   /api/v1/signin-links                   SigninLinkRequest → SigninLink
//	GET    /api/v1/people                         People
//	DELETE /api/v1/people/{id}                    204
//	DELETE /api/v1/people/{id}/passkeys/{passkey} 204
//	GET    /api/v1/service-accounts               ServiceAccounts
//	POST   /api/v1/service-accounts               ServiceAccountRequest → 201 serviceaccount.Account
//	GET    /api/v1/service-accounts/{id}          serviceaccount.Account
//	DELETE /api/v1/service-accounts/{id}          204
//	POST   /api/v1/service-accounts/{id}/keys     KeyRequest → 201 NewKey
//	POST   /api/v1/service-accounts/{id}/keys/{key}/rotate   RotateKeyRequest → 201 NewKey
//	DELETE /api/v1/service-accounts/{id}/keys/{key}          204
//	GET    /api/v1/profiles/{id}/setup?device=    Setup
//	GET    /api/v1/profiles/{id}/apple.mobileconfig?device=&protocol=   Apple configuration profile
//
// The logs, stream, and stats endpoints take the filter parameters that
// querylog.ParseFilter reads: profile, device, client, status, reason, q,
// since, until, limit, and page_token. Stats also takes top.
//
// [RFC 6750, Section 2.1]: https://www.rfc-editor.org/rfc/rfc6750.html#section-2.1
// [RFC 9110, Section 13.1.1]: https://www.rfc-editor.org/rfc/rfc9110.html#section-13.1.1
// [RFC 7396]: https://www.rfc-editor.org/rfc/rfc7396.html
package api

import (
	"time"

	"github.com/picatz/doh/internal/blocklist"
	"github.com/picatz/doh/internal/policy"
	"github.com/picatz/doh/internal/serviceaccount"
	"github.com/picatz/doh/internal/services"
	"github.com/picatz/doh/internal/signin"
	"github.com/picatz/doh/internal/upstream"
)

// Prefix is the path prefix of every API endpoint.
const Prefix = "/api/v1"

// MergePatchType is the media type of JSON merge patches ([RFC 7396,
// Section 4]).
//
// [RFC 7396, Section 4]: https://www.rfc-editor.org/rfc/rfc7396.html#section-4
const MergePatchType = "application/merge-patch+json"

// Error is the body of every error response.
type Error struct {
	// Error describes what went wrong.
	Error string `json:"error"`

	// Details lists individual problems, such as each invalid field of a
	// rejected policy.
	Details []string `json:"details,omitempty"`
}

// Status describes a running server.
type Status struct {
	// Version is the server's module version, or "(devel)".
	Version string `json:"version"`

	// Started is when the server started.
	Started time.Time `json:"started"`

	// Listeners are the addresses the server serves on, by kind: "doh",
	// "dns", and "admin".
	Listeners map[string]string `json:"listeners,omitempty"`

	// Upstreams are the resolvers queries are forwarded to.
	Upstreams []string `json:"upstreams"`

	// UpstreamHealth describes each upstream's health, in configured
	// order. Unhealthy upstreams are asked last until they recover.
	UpstreamHealth []upstream.Health `json:"upstream_health"`

	// Hostname is the server's public host name, under which each profile
	// is reachable by name, if configured.
	Hostname string `json:"hostname,omitempty"`

	// Tenant is the tenant the caller acts for, empty for the server's
	// operator. Tenants see a narrower status: their own profiles, and
	// nothing about listeners, lists, or traffic.
	Tenant string `json:"tenant,omitempty"`

	// Policy describes where the policy comes from.
	Policy PolicyStatus `json:"policy"`

	// Lists describes every blocklist in use.
	Lists []blocklist.ListStatus `json:"lists"`

	// QueryLog describes the query log.
	QueryLog QueryLogStatus `json:"query_log"`

	// Queries counts queries answered since the server started, by
	// outcome: "total", "blocked", "cached", and "errors".
	Queries map[string]int64 `json:"queries"`
}

// PolicyStatus describes where a server's policy comes from.
type PolicyStatus struct {
	// Source is the policy file's path, or the URL it's synced from. It's
	// empty when the policy is built from flags alone.
	Source string `json:"source,omitempty"`

	// ReadOnly reports whether the policy can't be changed through the
	// API, because it's synced from another server or built from flags.
	ReadOnly bool `json:"read_only"`

	// ETag is the current policy's entity tag.
	ETag string `json:"etag"`

	// Profiles is the number of profiles.
	Profiles int `json:"profiles"`

	// Updated is when the policy was last loaded or changed.
	Updated time.Time `json:"updated,omitzero"`

	// Error reports why the latest reload or sync failed, if it did; the
	// previous policy stays in effect.
	Error string `json:"error,omitempty"`
}

// QueryLogStatus describes a server's query log.
type QueryLogStatus struct {
	// Enabled reports whether queries are logged at all.
	Enabled bool `json:"enabled"`

	// Entries is the number of entries held in memory, which the logs
	// endpoints search.
	Entries int `json:"entries"`

	// Dir is where daily log files are kept, if anywhere.
	Dir string `json:"dir,omitempty"`

	// Retention is how long daily log files are kept, such as "168h0m0s".
	Retention string `json:"retention,omitempty"`
}

// Feature is a built-in protection that profiles toggle.
type Feature struct {
	// ID is the field that toggles it: "security.<id>" in a profile, or
	// "safe_search".
	ID string `json:"id"`

	// Title and Description explain the feature.
	Title       string `json:"title"`
	Description string `json:"description"`

	// Category is "security" or "parental".
	Category string `json:"category"`

	// Default reports whether new policies turn it on.
	Default bool `json:"default"`
}

// Catalog lists what profiles can turn on: built-in features and blocklist
// presets.
type Catalog struct {
	Features []Feature          `json:"features"`
	Presets  []blocklist.Preset `json:"presets"`

	// Services are the apps and sites profiles and schedules can block by
	// name.
	Services []services.Service `json:"services"`
}

// Profiles is the body listing every profile.
type Profiles struct {
	Profiles []policy.Profile `json:"profiles"`
}

// DomainRequest names a domain to allow or deny.
type DomainRequest struct {
	Domain string `json:"domain"`
}

// Explanation traces how a server would answer a query, check by check.
type Explanation struct {
	// Name and Type are the query, such as "ads.example.com" and "A".
	Name string `json:"name"`
	Type string `json:"type"`

	// Profile and Device are the profile and device the query matched.
	Profile string `json:"profile,omitempty"`
	Device  string `json:"device,omitempty"`

	// Client is the client address the query was matched as, if any.
	Client string `json:"client,omitempty"`

	// Decision is the outcome.
	Decision Decision `json:"decision"`

	// Checks are the checks the query went through, in order.
	Checks []Check `json:"checks"`

	// Answers are the records the query would be answered with, such as
	// "A 192.0.2.1", if it was resolved.
	Answers []string `json:"answers,omitempty"`

	// Rcode is the response code the query would get, such as "NOERROR".
	Rcode string `json:"rcode,omitempty"`
}

// Decision actions.
const (
	ActionAllow   = "allow"   // forwarded upstream, or answered from cache
	ActionBlock   = "block"   // answered with the profile's block response
	ActionRewrite = "rewrite" // answered locally with other records
	ActionRefuse  = "refuse"  // no profile matched the client
)

// Decision is the outcome of a policy's checks for one query.
type Decision struct {
	// Action is ActionAllow, ActionBlock, ActionRewrite, or ActionRefuse.
	Action string `json:"action"`

	// Reason is the check that decided, such as "list" or "rebinding".
	// It's empty when nothing matched and the query was allowed.
	Reason string `json:"reason,omitempty"`

	// Rule is the domain or value that matched, such as the blocked domain
	// or the private address an answer pointed to.
	Rule string `json:"rule,omitempty"`

	// Source names the list a rule came from.
	Source string `json:"source,omitempty"`

	// Detail explains the decision for people.
	Detail string `json:"detail,omitempty"`
}

// Check results.
const (
	CheckPass  = "pass"  // ran, and didn't match
	CheckMatch = "match" // ran, and decided the outcome
	CheckSkip  = "skip"  // didn't run, because it's off or didn't apply
)

// Check is one step of an [Explanation].
type Check struct {
	// Check names the check, such as "allow", "list", or "rebinding".
	Check string `json:"check"`

	// Result is CheckPass, CheckMatch, or CheckSkip.
	Result string `json:"result"`

	// Detail explains the result.
	Detail string `json:"detail,omitempty"`
}

// Setup tells people how to point a device at a profile.
type Setup struct {
	// Profile and Device are the profile, and the device name if one was
	// given, that the settings select.
	Profile string `json:"profile"`
	Device  string `json:"device,omitempty"`

	// Hostname is the server's public host name, if configured. Without
	// one, encrypted settings can't be given.
	Hostname string `json:"hostname,omitempty"`

	// DoHURL is the DNS-over-HTTPS URL that selects the profile and device,
	// if the server serves DoH and has a host name. Like DoTHost, it
	// assumes clients reach the server on the standard port (443, or 853
	// for DoT), as they do through port forwarding or a proxy.
	DoHURL string `json:"doh_url,omitempty"`

	// DoTHost is the DNS-over-TLS host name that selects the profile and
	// device, such as Android's Private DNS setting takes, if the server
	// serves DoT and has a host name.
	DoTHost string `json:"dot_host,omitempty"`

	// DNSAddrs are the addresses of the plain DNS listener, for devices
	// that select the profile by address.
	DNSAddrs []string `json:"dns_addrs,omitempty"`

	// Platforms are step-by-step instructions, by platform.
	Platforms []Platform `json:"platforms"`
}

// Platform is how to set up one kind of device.
type Platform struct {
	// ID identifies the platform: "apple", "android", "windows", "linux",
	// "browser", or "router".
	ID string `json:"id"`

	// Name is the platform's name for people, such as "iPhone, iPad, and Mac".
	Name string `json:"name"`

	// Steps are the instructions, in order.
	Steps []string `json:"steps"`

	// Download, if set, is the API path of a file that sets the device up,
	// such as an Apple configuration profile.
	Download string `json:"download,omitempty"`
}

// MobileConfigType is the media type of Apple configuration profiles.
const MobileConfigType = "application/x-apple-aspen-config"

// SigninLinkRequest asks for a sign-in link.
type SigninLinkRequest struct {
	// Role is what the link's session may do: "admin" (the default) or
	// "reader".
	Role string `json:"role,omitempty"`

	// Tenant is the tenant the link signs in to, such as to invite a
	// family's first admin. Only the operator may name one; a tenant's
	// links are always for its own tenant. Empty, from the operator, signs
	// in as the operator.
	Tenant string `json:"tenant,omitempty"`
}

// Tenants lists tenants: every one for the operator, or a tenant's own.
type Tenants struct {
	Tenants []policy.Tenant `json:"tenants"`
}

// SigninLink is a single-use link that signs a browser in to the web UI.
type SigninLink struct {
	// URL opens the web UI and signs in. The code is in its fragment, which
	// browsers never send to servers, so it stays out of logs.
	URL string `json:"url"`

	// Expires is when the link stops working, if unused.
	Expires time.Time `json:"expires"`

	// PasskeyRequired reports that the link only starts signing in: someone
	// has a passkey, so one must finish it.
	PasskeyRequired bool `json:"passkey_required"`
}

// ServiceAccounts lists service accounts.
type ServiceAccounts struct {
	ServiceAccounts []serviceaccount.Account `json:"service_accounts"`
}

// ServiceAccountRequest creates a service account.
type ServiceAccountRequest struct {
	// Name says what it's for, such as "Home Assistant".
	Name string `json:"name"`

	// Role is "admin" or "reader", the default.
	Role string `json:"role,omitempty"`

	// Tenant is the tenant it acts for. Only the operator may choose; a
	// tenant's service accounts are always its own.
	Tenant string `json:"tenant,omitempty"`
}

// KeyRequest adds a key to a service account.
type KeyRequest struct {
	// Expires is when the key stops working: within a year. It defaults
	// to 90 days from now.
	Expires time.Time `json:"expires,omitzero"`
}

// RotateKeyRequest replaces a key with a new one.
type RotateKeyRequest struct {
	// Expires is when the new key stops working, as in [KeyRequest].
	Expires time.Time `json:"expires,omitzero"`

	// PreviousExpires is when the old key stops working: now, the
	// default, or within a week, so automation can switch over.
	PreviousExpires time.Time `json:"previous_expires,omitzero"`
}

// NewKey is a service account's new key, with its secret. The secret is
// shown only this once; send it as a bearer token.
type NewKey struct {
	Account string             `json:"account"`
	Key     serviceaccount.Key `json:"key"`
	Secret  string             `json:"secret"`
}

// People lists who can sign in with passkeys.
type People struct {
	People []signin.Person `json:"people"`
}
