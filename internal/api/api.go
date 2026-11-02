// Package api defines the JSON types and paths of the admin API that
// "doh serve" exposes on its admin listener, shared by the server, the web
// UI, and the doh CLI's client commands.
//
// Every endpoint is under [Prefix] and needs a bearer token
// ([RFC 6750, Section 2.1]) or a signed-in web UI session: admin for every
// request, or reader for GET requests only. A service account key or
// access token bound to a DPoP key is sent as "Authorization: DPoP
// <token>" instead, with a DPoP proof signed by that key in the DPoP
// header ([RFC 9449, Section 7.1]); refusals are 401 with a DPoP
// WWW-Authenticate challenge naming invalid_token or invalid_dpop_proof.
// Browsers sign in at signin.Prefix, with sign-in links from POST
// /signin-links, or passkeys. Errors are reported as an [Error] with a
// 4xx or 5xx status.
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
//	GET    /api/v1/audit?tenant=&actor=&action=&before=&limit=&page_token=   audit.Page (admin)
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
//	GET    /api/v1/service-accounts/{id}/federation           TrustRules
//	POST   /api/v1/service-accounts/{id}/federation           TrustRuleRequest → 201 serviceaccount.TrustRule
//	DELETE /api/v1/service-accounts/{id}/federation/{rule}    204
//	POST   /api/v1/token                          TokenExchangeRequest form → TokenResponse (no credential)
//	GET    /api/v1/profiles/{id}/setup?device=    Setup
//	POST   /api/v1/profiles/{id}/setup-links?device=   → 201 SetupLink
//	GET    /api/v1/profiles/{id}/apple.mobileconfig?device=&protocol=&lock=   Apple configuration profile
//	GET    /api/v1/profiles/{id}/doh-setup.ps1?device=    Windows PowerShell setup script
//	GET    /api/v1/profiles/{id}/doh.conf?device=         systemd-resolved drop-in for Linux
//	GET    /api/v1/profiles/{id}/doh-openwrt.sh           OpenWrt setup script
//	GET    /api/v1/devices?profile=&device=&since=&new=   SeenDevices
//	GET    /api/v1/alerts?tenant=                 Alerts (admin)
//	PATCH  /api/v1/alerts?tenant=                 merge patch of alerts.Settings → Alerts (admin)
//	POST   /api/v1/alerts/destinations?tenant=    AlertDestinationRequest → 201 NewAlertDestination (admin)
//	DELETE /api/v1/alerts/destinations/{id}?tenant=   204 (admin)
//	POST   /api/v1/alerts/test?tenant=            AlertTest (admin)
//	POST   /api/v1/alerts/confirm?tenant=         AlertConfirmRequest → alerts.Destination (admin)
//	GET    /api/v1/alerts/push-key                PushKey (admin)
//
// POST /token is the exception to needing a credential: it's an OAuth 2.0
// token exchange ([RFC 8693]), where a workload trades an identity token
// from its own provider, such as GitHub Actions, for a short-lived access
// token of a service account whose trust rules accept it. It takes a form
// ([TokenExchangeRequest]), and reports errors as an [OAuthError]. An
// exchange with a DPoP proof in its DPoP header ([RFC 9449, Section 5])
// gets an access token bound to the proof's key, with token_type "DPoP".
//
// The alerts endpoints need a person or the operator's token, with an
// admin role, even to read: alerts send query names to their
// destinations, and a destination's URL, such as an ntfy topic, lets
// whoever knows it read them. Service accounts are refused, as they are
// for managing people. Each request is about the caller's own tenant, or
// the operator's own alerts; the operator may name a tenant with
// ?tenant=. A webhook's signing secret is returned only when it's
// created. An email address starts pending: the code that confirms it is
// sent only to the address, never returned, and it's confirmed with
// POST /alerts/confirm, or the page the email links to. A push
// destination is a browser's PushSubscription, made with the key from
// GET /alerts/push-key.
//
// The audit trail records every change made through this API: who made
// it (audit.Actor), for which tenant, the action, its target, a summary
// for people, and details for programs, never a secret. Reading it takes
// an admin role. Tenants see only their own tenant's events, including
// the operator's changes to it, and ?tenant= naming another shows
// nothing; the operator sees every tenant's, or one's with ?tenant=.
// Events are newest first, a page at a time, continued with
// next_page_token. It needs a data directory: 404 without one.
//
// The logs, stream, and stats endpoints take the filter parameters that
// querylog.ParseFilter reads: profile, device, client, status, reason, q,
// since, until, limit, and page_token. Stats also takes top, and interval,
// such as 1h, for a timeline from since.
//
// [RFC 6750, Section 2.1]: https://www.rfc-editor.org/rfc/rfc6750.html#section-2.1
// [RFC 9449, Section 7.1]: https://www.rfc-editor.org/rfc/rfc9449.html#section-7.1
// [RFC 9449, Section 5]: https://www.rfc-editor.org/rfc/rfc9449.html#section-5
// [RFC 9110, Section 13.1.1]: https://www.rfc-editor.org/rfc/rfc9110.html#section-13.1.1
// [RFC 7396]: https://www.rfc-editor.org/rfc/rfc7396.html
// [RFC 8693]: https://www.rfc-editor.org/rfc/rfc8693.html
package api

import (
	"net/url"
	"time"

	"github.com/picatz/doh/internal/alerts"
	"github.com/picatz/doh/internal/blocklist"
	"github.com/picatz/doh/internal/policy"
	"github.com/picatz/doh/internal/serviceaccount"
	"github.com/picatz/doh/internal/services"
	"github.com/picatz/doh/internal/signin"
	"github.com/picatz/doh/internal/upstream"
	"github.com/picatz/doh/internal/webpush"
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

	// Unavailable, if set, says why this server can't apply the feature
	// as it's set up, such as Safe Browsing without an API key. Profiles
	// may still turn it on; it does nothing until the server can.
	Unavailable string `json:"unavailable,omitempty"`
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

	// ServerAddrs are the addresses devices reach the encrypted listeners
	// at, when the server knows them: what Hostname resolves to, as the
	// server sees it, or else its own local network addresses. Settings
	// that pair an address with a host name, such as Windows' and
	// systemd-resolved's, use them.
	ServerAddrs []string `json:"server_addrs,omitempty"`

	// Platforms are step-by-step instructions, by platform, in the order
	// of Groups.
	Platforms []Platform `json:"platforms"`

	// Groups are the groups Platforms belong to, in the order to show
	// them. Only groups with at least one platform are listed.
	Groups []PlatformGroup `json:"groups,omitempty"`
}

// PlatformGroup is a kind of device to show platforms under.
type PlatformGroup struct {
	// ID is one of the Group constants, such as [GroupPhones].
	ID string `json:"id"`

	// Name is the group's name for people, such as "Phones & tablets".
	Name string `json:"name"`
}

// Platform groups, in the order they're shown.
const (
	GroupPhones    = "phones"     // Phones & tablets
	GroupComputers = "computers"  // Computers
	GroupTV        = "tv"         // TV & streaming
	GroupConsoles  = "consoles"   // Game consoles
	GroupSmartHome = "smart-home" // Smart home
	GroupBrowsers  = "browsers"   // Browsers
	GroupNetwork   = "network"    // Whole network
)

// Protection levels of a platform's settings.
const (
	// ProtectionEncrypted is DNS-over-HTTPS or DNS-over-TLS all the way
	// from the device (or, for a router, from the router) to doh.
	ProtectionEncrypted = "encrypted"

	// ProtectionPlain is plain DNS: unencrypted on the local network, with
	// the device known to doh only by its address.
	ProtectionPlain = "plain"

	// ProtectionUnavailable means this server can't serve the platform as
	// it's set up, such as devices that only speak plain DNS when the
	// server doesn't serve it.
	ProtectionUnavailable = "unavailable"
)

// Protection is how well a platform's settings protect a device's DNS.
type Protection struct {
	// Level is ProtectionEncrypted, ProtectionPlain, or
	// ProtectionUnavailable.
	Level string `json:"level"`

	// Protocol is what the device speaks to doh: "https" (DoH), "tls"
	// (DoT), or "dns" (plain DNS); empty when unavailable.
	Protocol string `json:"protocol,omitempty"`

	// Summary says why, in one line.
	Summary string `json:"summary"`
}

// Download is a file that sets a device up.
type Download struct {
	// Name says what it is, such as "Configuration profile
	// (DNS-over-TLS)".
	Name string `json:"name"`

	// File is the name to save it as, such as "doh-setup.ps1".
	File string `json:"file"`

	// Path is its admin API path, query included. A setup link's page
	// serves the same file under the link instead.
	Path string `json:"path"`

	// ContentType is its media type.
	ContentType string `json:"content_type"`
}

// Platform is how to set up one kind of device.
type Platform struct {
	// ID identifies the platform: "apple" (iPhone and iPad), "mac",
	// "apple-tv", "vision-pro", "android", "android-tv", "windows",
	// "linux", "chromeos", "smart-tv", "consoles", "smart-home",
	// "browser", "router", "openwrt", "pfsense", "unifi", or "none" when
	// there's nothing to set up yet.
	ID string `json:"id"`

	// Name is the platform's name for people, such as "iPhone and iPad".
	Name string `json:"name"`

	// Steps are the instructions, in order.
	Steps []string `json:"steps"`

	// Download, if set, is the API path of a file that sets the device up,
	// such as an Apple configuration profile: the first of Downloads.
	Download string `json:"download,omitempty"`

	// Group is the ID of the group the platform belongs to, such as
	// [GroupPhones]; empty for "none".
	Group string `json:"group,omitempty"`

	// Protection is how well the settings protect the device's DNS.
	Protection *Protection `json:"protection,omitempty"`

	// Downloads are files that set the device up, best first.
	Downloads []Download `json:"downloads,omitempty"`

	// Check says how to tell the settings are working.
	Check string `json:"check,omitempty"`

	// Identified says how doh tells which device is asking, and so which
	// profile its queries get and the name the log shows.
	Identified string `json:"identified,omitempty"`

	// Notes are limits and caveats worth knowing.
	Notes []string `json:"notes,omitempty"`

	// Signing, set with an Apple configuration profile's Download, says
	// whether the server signs it, and with what.
	Signing *ProfileSigning `json:"signing,omitempty"`
}

// ProfileSigning describes how a configuration profile is signed. Apple
// devices show a signed profile as Verified only if its certificate
// chains to a root they trust and is valid; otherwise, or unsigned, they
// show it as Unverified, though it installs and works the same.
type ProfileSigning struct {
	// Signed reports whether the profile is signed.
	Signed bool `json:"signed"`

	// Signer is the signing certificate's subject common name, or else its
	// first DNS name, if signed.
	Signer string `json:"signer,omitempty"`

	// Expires is when the signing certificate expires, if signed. A
	// downloaded profile's signature doesn't change, so a profile
	// downloaded after this shows as unverified until the certificate is
	// renewed; installed profiles stay installed and keep working.
	Expires *time.Time `json:"expires,omitempty"`

	// Trusted reports whether the signing certificate's chain verifies
	// against this server's system roots now: a close guide to, though no
	// guarantee of, whether Apple devices show the profile as Verified.
	Trusted bool `json:"trusted"`

	// Note explains an unsigned or untrusted profile, for people.
	Note string `json:"note,omitempty"`
}

// MobileConfigType is the media type of Apple configuration profiles,
// signed or not.
const MobileConfigType = "application/x-apple-aspen-config"

// TextFileType is the media type of the setup files that aren't Apple
// configuration profiles, served as attachments: the PowerShell script for
// Windows, the systemd-resolved drop-in, and the OpenWrt shell script.
const TextFileType = "text/plain; charset=utf-8"

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

	// JKT, if set, binds the key to a DPoP key the client holds: it's
	// the base64url SHA-256 JWK thumbprint ([RFC 7638]) of the key's
	// public half. Requests using the key then need a DPoP proof signed
	// by it ([RFC 9449, Section 7.1]).
	//
	// [RFC 7638]: https://www.rfc-editor.org/rfc/rfc7638.html
	// [RFC 9449, Section 7.1]: https://www.rfc-editor.org/rfc/rfc9449.html#section-7.1
	JKT string `json:"jkt,omitempty"`
}

// RotateKeyRequest replaces a key with a new one.
type RotateKeyRequest struct {
	// Expires is when the new key stops working, as in [KeyRequest].
	Expires time.Time `json:"expires,omitzero"`

	// PreviousExpires is when the old key stops working: now, the
	// default, or within a week, so automation can switch over.
	PreviousExpires time.Time `json:"previous_expires,omitzero"`

	// JKT binds the new key to a DPoP key, as in [KeyRequest]. The new
	// key is bound only if it's set, whether or not the old one was.
	JKT string `json:"jkt,omitempty"`
}

// NewKey is a service account's new key, with its secret. The secret is
// shown only this once; send it as a bearer token, or, if the key is
// bound to a DPoP key, with the DPoP scheme and a proof.
type NewKey struct {
	Account string             `json:"account"`
	Key     serviceaccount.Key `json:"key"`
	Secret  string             `json:"secret"`
}

// Alerts are a tenant's, or the operator's, alert settings and
// destinations, and how recent deliveries went.
type Alerts struct {
	// Tenant is whose alerts these are, or empty for the operator's.
	Tenant string `json:"tenant,omitempty"`

	// Settings are which kinds of alert are sent, and when.
	Settings alerts.Settings `json:"settings"`

	// AvailableKinds are the kinds of alert this tenant, or the operator,
	// can turn on.
	AvailableKinds []alerts.Kind `json:"available_kinds"`

	// AvailableTypes are the destination types that can be added: email
	// only if the server's operator has set up a mail server.
	AvailableTypes []alerts.DestinationType `json:"available_types"`

	// Destinations are where alerts are sent, without their secrets, and
	// with any password in their URLs hidden.
	Destinations []alerts.Destination `json:"destinations"`

	// Deliveries are the most recent deliveries since the server started,
	// newest first.
	Deliveries []alerts.Delivery `json:"deliveries"`
}

// AlertDestinationRequest adds a place to send alerts.
type AlertDestinationRequest struct {
	// Type is "webhook", "ntfy", "email", or "push".
	Type alerts.DestinationType `json:"type"`

	// URL is where a webhook's or ntfy topic's alerts are posted: https,
	// and for a tenant, a service on the internet. Nothing is ever added
	// to it.
	URL string `json:"url,omitempty"`

	// Address is an email destination's address. It's sent a code to
	// confirm it, and gets nothing else until it's confirmed.
	Address string `json:"address,omitempty"`

	// Subscription is a push destination's browser subscription, as its
	// PushSubscription.toJSON() gives it. Its endpoint must be on a known
	// browser push service.
	Subscription *webpush.Subscription `json:"subscription,omitempty"`

	// Name says what it is, such as "Mom's phone".
	Name string `json:"name,omitempty"`
}

// NewAlertDestination is a new destination, with, for a webhook, the
// secret its deliveries are signed with. The secret is shown only this
// once.
type NewAlertDestination struct {
	Destination alerts.Destination `json:"destination"`
	Secret      string             `json:"secret,omitempty"`
}

// AlertConfirmRequest confirms an email address with the code it was
// sent.
type AlertConfirmRequest struct {
	Code string `json:"code"`
}

// PushKey is the server's VAPID public key, which browsers subscribe
// with, as PushManager.subscribe's applicationServerKey.
type PushKey struct {
	// PublicKey is the uncompressed P-256 public key, as unpadded
	// base64url.
	PublicKey string `json:"public_key"`
}

// AlertTest reports how a test alert to each destination went.
type AlertTest struct {
	Deliveries []alerts.Delivery `json:"deliveries"`
}

// SetupLink is a short-lived link to a page that sets a device up for a
// profile, to open on the device itself.
type SetupLink struct {
	// URL is the page, on the server's public listener.
	URL string `json:"url"`

	// Expires is when the link stops working.
	Expires time.Time `json:"expires"`

	// QR is the link as a QR code, to scan with the device's camera.
	QR *QRCode `json:"qr,omitempty"`
}

// SeenDevices lists devices the server has answered, most recently seen
// first, as the caller may see them, whether or not their profiles log
// queries. With a data directory, they're kept across restarts.
type SeenDevices struct {
	// Since is when the server started remembering: before it, nothing
	// is known.
	Since time.Time `json:"since"`

	// Devices are the devices, at most 200.
	Devices []SeenDevice `json:"devices"`
}

// SeenDevice is a device the server has answered: one profile, device
// name, and address.
type SeenDevice struct {
	// Profile is the profile its queries used.
	Profile string `json:"profile"`

	// Device is its name, from the DoH path or the profile's devices, if
	// it has one.
	Device string `json:"device,omitempty"`

	// Hostname is what an unnamed device calls itself on the network, if
	// known. Devices choose their own, so it proves nothing.
	Hostname string `json:"hostname,omitempty"`

	// Client is its address, if known.
	Client string `json:"client,omitempty"`

	// Transport is how it last asked: "doh", "dot", "doq", "udp", or
	// "tcp".
	Transport string `json:"transport"`

	// First and Last are when it was first and last answered.
	First time.Time `json:"first"`
	Last  time.Time `json:"last"`
}

// QRCode is a QR code to show: in doh's colors, with its donut in the
// middle when the link is short enough, dark on light whatever the page's
// theme, so cameras read it.
type QRCode struct {
	// SVG is the code as a standalone SVG image, quiet zone included.
	SVG string `json:"svg"`
}

// People lists who can sign in with passkeys.
type People struct {
	People []signin.Person `json:"people"`
}

// TrustRules lists a service account's trust rules.
type TrustRules struct {
	Rules []serviceaccount.TrustRule `json:"rules"`
}

// TrustRuleRequest adds a trust rule to a service account: the identity
// tokens it accepts in exchange for access tokens. See
// [serviceaccount.TrustRule] for what each field means.
type TrustRuleRequest struct {
	// Issuer is the identity provider's issuer URL.
	Issuer string `json:"issuer"`

	// JWKSURL is where the provider publishes its keys. It defaults to
	// what the issuer's OpenID Connect discovery document says.
	JWKSURL string `json:"jwks_url,omitempty"`

	// Audience is what tokens' "aud" must name. It defaults to the
	// server's first admin origin, if it has one.
	Audience string `json:"audience,omitempty"`

	// Subject is what tokens' "sub" must be, optionally ending in a "*"
	// wildcard after a "/" or ":".
	Subject string `json:"subject"`

	// Claims are other string claims tokens must have, exactly.
	Claims map[string]string `json:"claims,omitempty"`

	// TokenLifetime is how many seconds access tokens last: 60 to 3600,
	// 900 by default.
	TokenLifetime int `json:"token_lifetime,omitzero"`

	// RequireDPoP refuses exchanges that carry no DPoP proof, so every
	// access token the rule issues is bound to a key.
	RequireDPoP bool `json:"require_dpop,omitzero"`
}

// Token exchange parameters ([RFC 8693, Section 3]).
//
// [RFC 8693, Section 3]: https://www.rfc-editor.org/rfc/rfc8693.html#section-3
const (
	// GrantTypeTokenExchange is the grant_type of a token exchange.
	GrantTypeTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange"

	// TokenTypeJWT and TokenTypeIDToken are the subject token types
	// accepted: a workload's identity token.
	TokenTypeJWT     = "urn:ietf:params:oauth:token-type:jwt"
	TokenTypeIDToken = "urn:ietf:params:oauth:token-type:id_token"

	// TokenTypeAccessToken is the type of the token issued.
	TokenTypeAccessToken = "urn:ietf:params:oauth:token-type:access_token"
)

// TokenExchangeRequest is the form POST /token takes
// ([RFC 8693, Section 2.1]), sent as application/x-www-form-urlencoded.
//
// [RFC 8693, Section 2.1]: https://www.rfc-editor.org/rfc/rfc8693.html#section-2.1
type TokenExchangeRequest struct {
	// SubjectToken is the workload's identity token, a JWT.
	SubjectToken string

	// SubjectTokenType is [TokenTypeJWT], the default, or
	// [TokenTypeIDToken].
	SubjectTokenType string

	// Audience is the ID of the service account to act as.
	Audience string
}

// Form returns r as a form, with the token exchange grant type.
func (r TokenExchangeRequest) Form() url.Values {
	subjectType := r.SubjectTokenType
	if subjectType == "" {
		subjectType = TokenTypeJWT
	}
	return url.Values{
		"grant_type":         {GrantTypeTokenExchange},
		"subject_token":      {r.SubjectToken},
		"subject_token_type": {subjectType},
		"audience":           {r.Audience},
	}
}

// TokenResponse is a successful token exchange ([RFC 8693, Section
// 2.2.1]).
//
// [RFC 8693, Section 2.2.1]: https://www.rfc-editor.org/rfc/rfc8693.html#section-2.2.1
type TokenResponse struct {
	// AccessToken is the issued token, to send as TokenType says. It's
	// kept only in the server's memory, so it doesn't survive a restart.
	AccessToken string `json:"access_token"`

	// IssuedTokenType is [TokenTypeAccessToken].
	IssuedTokenType string `json:"issued_token_type"`

	// TokenType is "Bearer", or "DPoP" if the exchange carried a DPoP
	// proof ([RFC 9449, Section 5]): the token is bound to the proof's
	// key, and is sent with the DPoP scheme and a proof by that key.
	//
	// [RFC 9449, Section 5]: https://www.rfc-editor.org/rfc/rfc9449.html#section-5
	TokenType string `json:"token_type"`

	// ExpiresIn is how many seconds the token lasts.
	ExpiresIn int `json:"expires_in"`
}

// OAuthError is the body of a failed token exchange ([RFC 6749, Section
// 5.2]).
//
// [RFC 6749, Section 5.2]: https://www.rfc-editor.org/rfc/rfc6749.html#section-5.2
type OAuthError struct {
	// Error is a code, such as "invalid_grant".
	Error string `json:"error"`

	// Description says more, without revealing which check refused an
	// identity token: that's only in the server's log.
	Description string `json:"error_description,omitempty"`
}
