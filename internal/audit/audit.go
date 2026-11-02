// Package audit defines doh's audit trail: a durable record of every
// change made through the admin API, saying who made it, for whom, what
// they did, and to what, so "who unblocked TikTok?" has an answer.
//
// An [Event] never holds a secret: no tokens, keys, codes, webhook
// secrets, or full destination URLs, only what identifies them. Events are
// kept by a [Store], such as the server's state database, for a retention
// period, and listed newest first with [Filter], a page at a time.
//
// Events belong to a tenant: the one whose profiles, people, service
// accounts, or alerts changed, or "" for the server's operator. Tenants see
// only their own; the operator sees every tenant's, including changes the
// operator made to a tenant.
package audit

import (
	"context"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"fmt"
	"maps"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// ActorKind says what kind of credential made a change.
type ActorKind string

// Kinds of actors.
const (
	// ActorToken is one of the operator's own API tokens.
	ActorToken ActorKind = "token"

	// ActorPerson is a person signed in with a passkey.
	ActorPerson ActorKind = "person"

	// ActorLink is a browser signed in with a sign-in link alone, before
	// anyone in its tenant had a passkey.
	ActorLink ActorKind = "link"

	// ActorServiceAccount is a service account, by key or by an access
	// token from a token exchange.
	ActorServiceAccount ActorKind = "service_account"

	// ActorRecipient is whoever holds a link sent to an alert address,
	// confirming or unsubscribing it, without signing in.
	ActorRecipient ActorKind = "recipient"
)

// Actor is who made a change.
type Actor struct {
	// Kind is the kind of credential used.
	Kind ActorKind `json:"kind"`

	// ID identifies the actor: a person's or service account's ID, or for
	// tokens, "admin".
	ID string `json:"id,omitempty"`

	// Name is how the actor is shown, such as a person's name, a service
	// account's name, or "admin token".
	Name string `json:"name,omitempty"`

	// Tenant is the actor's tenant, or empty for the operator.
	Tenant string `json:"tenant,omitempty"`

	// Via says how a service account authenticated: "key <id>", or
	// "token exchange from <issuer>".
	Via string `json:"via,omitempty"`
}

// Target is what a change was made to.
type Target struct {
	// Type is the kind of resource, such as "profile", "tenant",
	// "service_account", "person", or "alert_destination".
	Type string `json:"type"`

	// ID identifies it.
	ID string `json:"id,omitempty"`
}

// Event is one change.
type Event struct {
	// ID identifies the event. It's opaque.
	ID string `json:"id"`

	// Time is when the change was made.
	Time time.Time `json:"time"`

	// Tenant is whose resource changed, or empty for the operator's.
	Tenant string `json:"tenant,omitempty"`

	// Actor is who made the change.
	Actor Actor `json:"actor"`

	// Action is what was done, such as "profile.updated" or
	// "service_account.key.revoked". Actions are dotted, from the
	// resource down.
	Action string `json:"action"`

	// Target is what it was done to.
	Target Target `json:"target,omitzero"`

	// Summary describes the change for people, such as "Unblocked
	// TikTok (tiktok); allowed example.com".
	Summary string `json:"summary,omitempty"`

	// Details are the change's facts, for programs: for a profile, such
	// as "services.removed": "tiktok" and "allow.added": "example.com".
	Details map[string]string `json:"details,omitempty"`
}

// Limits on what an event holds. [Event.Normalize] enforces them.
const (
	MaxDetails      = 32
	MaxKeyLength    = 64
	MaxValueLength  = 512
	MaxFieldLength  = 256 // of actors, actions, targets, and tenants
	MaxSummaryBytes = 512
)

// Normalize returns e within the limits above, truncating what's too long
// at a character boundary, and dropping details beyond [MaxDetails], in
// key order.
func (e Event) Normalize() Event {
	e.Tenant = truncate(e.Tenant, MaxFieldLength)
	e.Actor.ID = truncate(e.Actor.ID, MaxFieldLength)
	e.Actor.Name = truncate(e.Actor.Name, MaxFieldLength)
	e.Actor.Tenant = truncate(e.Actor.Tenant, MaxFieldLength)
	e.Actor.Via = truncate(e.Actor.Via, MaxFieldLength)
	e.Action = truncate(e.Action, MaxFieldLength)
	e.Target.Type = truncate(e.Target.Type, MaxFieldLength)
	e.Target.ID = truncate(e.Target.ID, MaxFieldLength)
	e.Summary = truncate(e.Summary, MaxSummaryBytes)
	if len(e.Details) > 0 {
		details := make(map[string]string, min(len(e.Details), MaxDetails))
		for _, k := range slices.Sorted(maps.Keys(e.Details)) {
			if len(details) == MaxDetails {
				break
			}
			if k = truncate(k, MaxKeyLength); k != "" {
				details[k] = truncate(e.Details[k], MaxValueLength)
			}
		}
		e.Details = details
	}
	return e
}

// truncate shortens s to at most n bytes, ending in "…" if it was cut, at
// a character boundary, and replaces invalid UTF-8.
func truncate(s string, n int) string {
	s = strings.ToValidUTF8(s, "�")
	if len(s) <= n {
		return s
	}
	cut := n - len("…")
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "…"
}

// Store keeps events. Implementations must be safe for concurrent use.
type Store interface {
	// Record adds e, normalized, assigning its ID.
	Record(ctx context.Context, e Event) error

	// List returns the events matching f, newest first.
	List(ctx context.Context, f Filter) (Page, error)
}

// Filter selects events.
type Filter struct {
	// Tenant, if AllTenants is false, matches only that tenant's events,
	// or for "", the operator's own. Servers set it from who's asking, so
	// tenants see only their own.
	Tenant     string
	AllTenants bool

	// Actor matches events whose actor has this ID or name.
	Actor string

	// Action matches events with this action, or under it: "profile"
	// matches "profile.updated" and "profile.created".
	Action string

	// Before matches events made before this time.
	Before time.Time

	// Limit is the most events in a page: [DefaultLimit] if zero, at most
	// [MaxLimit].
	Limit int

	// PageToken continues from a previous [Page.NextPageToken].
	PageToken string
}

// Page limits.
const (
	DefaultLimit = 100
	MaxLimit     = 1000
)

// Page is a page of events, newest first.
type Page struct {
	// Events are the matching events. It's never nil.
	Events []Event `json:"events"`

	// NextPageToken, if set, continues with older events.
	NextPageToken string `json:"next_page_token,omitempty"`
}

// ErrInvalidFilter reports filter parameters that can't be used.
var ErrInvalidFilter = errors.New("audit: invalid filter")

// ParseFilter reads the filter parameters actor, action, before (RFC
// 3339), limit, and page_token. Tenant parameters are the server's to
// apply, since they depend on who's asking.
func ParseFilter(v url.Values) (Filter, error) {
	f := Filter{Actor: v.Get("actor"), Action: v.Get("action"), PageToken: v.Get("page_token")}
	if len(f.Actor) > MaxFieldLength || len(f.Action) > MaxFieldLength {
		return Filter{}, fmt.Errorf("%w: actor and action are at most %d bytes", ErrInvalidFilter, MaxFieldLength)
	}
	if s := v.Get("before"); s != "" {
		t, err := time.Parse(time.RFC3339Nano, s)
		if err != nil {
			return Filter{}, fmt.Errorf("%w: before must be an RFC 3339 time, such as 2026-11-02T15:04:05Z", ErrInvalidFilter)
		}
		f.Before = t
	}
	if s := v.Get("limit"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 1 || n > MaxLimit {
			return Filter{}, fmt.Errorf("%w: limit must be between 1 and %d", ErrInvalidFilter, MaxLimit)
		}
		f.Limit = n
	}
	if f.PageToken != "" {
		if _, err := DecodePageToken(f.PageToken); err != nil {
			return Filter{}, err
		}
	}
	return f, nil
}

// PageLimit returns how many events a page of f holds.
func (f Filter) PageLimit() int {
	if f.Limit <= 0 {
		return DefaultLimit
	}
	return min(f.Limit, MaxLimit)
}

// MatchesAction reports whether action is f's action, or under it.
func (f Filter) MatchesAction(action string) bool {
	return f.Action == "" || action == f.Action || strings.HasPrefix(action, f.Action+".")
}

// pageToken is the decoded form of a page token: where the last page
// ended. It reveals nothing a caller couldn't see, and filters still
// apply to whatever it names, so a forged one can't widen what's seen.
type pageToken struct {
	V      int    `json:"v"`
	Before uint64 `json:"b"`
}

const pageTokenVersion = 1

// EncodePageToken returns a token continuing before the event with
// sequence number seq.
func EncodePageToken(seq uint64) string {
	b, _ := json.Marshal(pageToken{V: pageTokenVersion, Before: seq})
	return base64.RawURLEncoding.EncodeToString(b)
}

// DecodePageToken returns the sequence number a page token continues
// before.
func DecodePageToken(s string) (uint64, error) {
	invalid := fmt.Errorf("%w: invalid page_token", ErrInvalidFilter)
	if len(s) > 128 {
		return 0, invalid
	}
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return 0, invalid
	}
	var t pageToken
	if err := json.Unmarshal(b, &t, json.RejectUnknownMembers(true)); err != nil || t.V != pageTokenVersion || t.Before == 0 {
		return 0, invalid
	}
	return t.Before, nil
}

// EncodeID returns the ID of the event with sequence number seq.
func EncodeID(seq uint64) string { return "evt_" + strconv.FormatUint(seq, 10) }
