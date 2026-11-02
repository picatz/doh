// Package alerts tells people when something on their network needs them:
// a threat was blocked, a new device appeared, lookups are failing, or a
// blocklist didn't load.
//
// An [Engine] watches the query log's entries as they're written, through
// a bounded queue that never slows down answering: when it's full,
// entries are dropped and counted. It turns them into alerts, coalescing
// repeats (the same thing at most once an hour) and summarizing bursts
// ("12 more threats blocked on kids-ipad in the last hour"), and delivers
// them to each scope's destinations: webhooks signed as the
// [Standard Webhooks] specification describes, or [ntfy] topics, for push
// notifications on phones.
//
// Alerts have a scope: a tenant, whose alerts only ever concern its own
// profiles' queries, or the server's operator (the empty scope), whose
// alerts cover everything outside tenants, the whole server's failing
// lookups, and blocklists that fail to load.
//
// Each scope's settings, destinations, and the devices it has seen are
// kept in one file, readable only by its owner. Windows, coalescing, and
// recent deliveries are kept in memory. Delivery is best effort: each
// alert is tried a few times, with backoff, and failures are recorded for
// people to see.
//
// [Standard Webhooks]: https://www.standardwebhooks.com/
// [ntfy]: https://docs.ntfy.sh/publish/
package alerts

import (
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/picatz/doh/internal/policy"
)

// Kind is what an alert is about.
type Kind string

// Kinds of alert.
const (
	// KindThreat is a query blocked by a security protection: a look-alike
	// name, DNS tunneling, DNS rebinding, a newly registered domain, a
	// bypass service, or a list in the security category.
	KindThreat Kind = "threat"

	// KindNewDevice is a device, or client address, the scope hasn't seen
	// before.
	KindNewDevice Kind = "new-device"

	// KindFailing is lookups failing: at least [FailingMinErrors] errors,
	// and at least [FailingMinPercent] percent of queries, within
	// [FailingWindow].
	KindFailing Kind = "failing"

	// KindListFailed is a blocklist that failed to load. Only the
	// server's operator gets these.
	KindListFailed Kind = "list-failed"

	// KindTest is a test alert, sent when someone asks to check their
	// destinations. It can't be turned off.
	KindTest Kind = "test"
)

// Kinds are the kinds of alert that can be turned on and off, in the
// order they're presented.
var Kinds = []Kind{KindThreat, KindNewDevice, KindFailing, KindListFailed}

// Valid reports whether k is one of [Kinds].
func (k Kind) Valid() bool { return slices.Contains(Kinds, k) }

// OperatorOnly reports whether only the server's operator gets alerts of
// kind k.
func (k Kind) OperatorOnly() bool { return k == KindListFailed }

// label names k in a sentence, such as "new device".
func (k Kind) label() string {
	switch k {
	case KindNewDevice:
		return "new device"
	case KindFailing:
		return "failing lookups"
	case KindListFailed:
		return "blocklist"
	}
	return string(k)
}

// KindsFor returns the kinds of alert a scope can have: all of them for
// the operator (the empty scope), and all but the operator's own for a
// tenant.
func KindsFor(scope string) []Kind {
	if scope == "" {
		return slices.Clone(Kinds)
	}
	return slices.DeleteFunc(slices.Clone(Kinds), Kind.OperatorOnly)
}

// Detection thresholds and limits.
const (
	// CoalesceWindow is how long the same alert, such as the same threat
	// on the same device, is sent at most once.
	CoalesceWindow = time.Hour

	// BurstLimit is how many alerts of one kind about one subject, such
	// as threats on one device, are sent within [CoalesceWindow]; beyond
	// it, they're summarized when the window ends.
	BurstLimit = 3

	// LearningPeriod is how long after a scope starts seeing devices that
	// they're learned silently, so a new server, or one that has just
	// enabled alerts, doesn't report every device it already serves.
	LearningPeriod = time.Hour

	// MaxSeenDevices bounds the devices remembered per scope. Beyond it,
	// the least recently seen are forgotten, and alerted on again if they
	// come back.
	MaxSeenDevices = 2048

	// FailingWindow, FailingMinErrors, and FailingMinPercent are when
	// lookups count as failing: at least FailingMinErrors errors, and at
	// least FailingMinPercent percent of queries, within about
	// FailingWindow.
	FailingWindow     = 5 * time.Minute
	FailingMinErrors  = 20
	FailingMinPercent = 10

	// MaxDestinations bounds each scope's destinations.
	MaxDestinations = 5

	// RecentDeliveries is how many deliveries are remembered per scope.
	RecentDeliveries = 20

	// DefaultQueueSize is how many query log entries may wait to be
	// examined before more are dropped.
	DefaultQueueSize = 4096
)

// Errors.
var (
	ErrNotFound = errors.New("not found")
	ErrInvalid  = errors.New("invalid")
	ErrLimit    = errors.New("limit reached")
)

// Settings are a scope's alert settings.
type Settings struct {
	// Kinds are the kinds of alert sent, in [Kinds] order. Every kind the
	// scope can have is on by default.
	Kinds []Kind `json:"kinds"`

	// QuietHours, if set, holds every alert but threats while they last,
	// and sends what was held, summarized, once they end.
	QuietHours *QuietHours `json:"quiet_hours,omitempty"`

	// TimeZone is the IANA time zone quiet hours follow, such as
	// "America/New_York". Empty means UTC.
	TimeZone string `json:"time_zone,omitempty"`
}

// QuietHours are a daily period, such as overnight, when only threats
// are sent.
type QuietHours struct {
	// Start and End are times of day, as "22:00" and "07:00". A period
	// that ends before it starts runs past midnight.
	Start string `json:"start"`
	End   string `json:"end"`
}

// DefaultSettings returns the settings of a scope that hasn't changed
// them: every kind it can have on, and no quiet hours.
func DefaultSettings(scope string) Settings {
	return Settings{Kinds: KindsFor(scope)}
}

// normalize checks s for scope, returning it with its kinds deduplicated
// in [Kinds] order.
func (s Settings) normalize(scope string) (Settings, error) {
	var kinds []Kind
	for _, k := range s.Kinds {
		switch {
		case !k.Valid():
			return Settings{}, fmt.Errorf("%w: unknown kind of alert %q (want %s)", ErrInvalid, k, kindList(KindsFor(scope)))
		case k.OperatorOnly() && scope != "":
			return Settings{}, fmt.Errorf("%w: %s alerts are for the server's operator", ErrInvalid, k)
		}
		kinds = append(kinds, k)
	}
	out := Settings{Kinds: []Kind{}, TimeZone: s.TimeZone}
	for _, k := range Kinds {
		if slices.Contains(kinds, k) {
			out.Kinds = append(out.Kinds, k)
		}
	}

	if s.QuietHours != nil {
		start, err := policy.ParseClock(s.QuietHours.Start)
		if err != nil {
			return Settings{}, fmt.Errorf("%w: quiet hours start: %v", ErrInvalid, err)
		}
		end, err := policy.ParseClock(s.QuietHours.End)
		if err != nil {
			return Settings{}, fmt.Errorf("%w: quiet hours end: %v", ErrInvalid, err)
		}
		if start == end {
			return Settings{}, fmt.Errorf("%w: quiet hours must start and end at different times", ErrInvalid)
		}
		q := *s.QuietHours
		out.QuietHours = &q
	}
	if _, err := s.location(); err != nil {
		return Settings{}, err
	}
	return out, nil
}

// location returns the time zone s follows.
func (s Settings) location() (*time.Location, error) {
	if s.TimeZone == "" {
		return time.UTC, nil
	}
	loc, err := time.LoadLocation(s.TimeZone)
	if err != nil || s.TimeZone == "Local" {
		return nil, fmt.Errorf("%w: time_zone %q must be an IANA time zone, such as America/New_York", ErrInvalid, s.TimeZone)
	}
	return loc, nil
}

// enabled reports whether alerts of kind k are on.
func (s Settings) enabled(k Kind) bool { return k == KindTest || slices.Contains(s.Kinds, k) }

// Quiet reports whether t is within s's quiet hours.
func (s Settings) Quiet(t time.Time) bool {
	if s.QuietHours == nil {
		return false
	}
	loc, err := s.location()
	if err != nil {
		return false
	}
	start, err1 := policy.ParseClock(s.QuietHours.Start)
	end, err2 := policy.ParseClock(s.QuietHours.End)
	if err1 != nil || err2 != nil {
		return false
	}
	local := t.In(loc)
	m := local.Hour()*60 + local.Minute()
	if start < end {
		return m >= start && m < end
	}
	return m >= start || m < end // past midnight
}

// clone returns a deep copy of s.
func (s Settings) clone() Settings {
	s.Kinds = slices.Clone(s.Kinds)
	if s.QuietHours != nil {
		q := *s.QuietHours
		s.QuietHours = &q
	}
	return s
}

// DestinationType is how a destination receives alerts.
type DestinationType string

// Destination types.
const (
	// Webhook is a JSON POST, signed as the Standard Webhooks
	// specification describes.
	Webhook DestinationType = "webhook"

	// Ntfy is a plain-text POST to an ntfy topic, for push notifications.
	Ntfy DestinationType = "ntfy"
)

// Valid reports whether t is a known destination type.
func (t DestinationType) Valid() bool { return t == Webhook || t == Ntfy }

// Destination is where a scope's alerts are sent.
type Destination struct {
	// ID identifies the destination. It's generated, and safe to show.
	ID string `json:"id"`

	// Type is how it receives alerts.
	Type DestinationType `json:"type"`

	// URL is where alerts are posted, with any password replaced by
	// "xxxxx".
	URL string `json:"url"`

	// Name says what the destination is, such as "Mom's phone".
	Name string `json:"name,omitempty"`

	// Created is when it was added, and CreatedBy who added it.
	Created   time.Time `json:"created"`
	CreatedBy string    `json:"created_by,omitempty"`

	// LastSuccess is when an alert last reached it, and LastFailure and
	// LastError when and why one last didn't.
	LastSuccess time.Time `json:"last_success,omitzero"`
	LastFailure time.Time `json:"last_failure,omitzero"`
	LastError   string    `json:"last_error,omitempty"`
}

// NewDestination describes a destination to add.
type NewDestination struct {
	Type      DestinationType
	URL       string
	Name      string
	CreatedBy string
}

// Delivery is one attempt, with its retries, to send an alert to a
// destination.
type Delivery struct {
	// Time is when the delivery finished.
	Time time.Time `json:"time"`

	// Alert is the alert's ID, and Kind and Summary its kind and title.
	Alert   string `json:"alert"`
	Kind    Kind   `json:"kind"`
	Summary string `json:"summary"`

	// Destination is the destination's ID.
	Destination string `json:"destination"`

	// OK reports whether the destination accepted the alert, and Error
	// why not, if it didn't.
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`

	// Attempts is how many times it was tried.
	Attempts int `json:"attempts"`
}

// Alert is what's sent to destinations. It's the body of webhook
// deliveries, as JSON.
type Alert struct {
	// ID identifies the alert. It's the webhook-id of webhook deliveries,
	// the same across retries, so receivers can ignore duplicates.
	ID string `json:"id"`

	// Type is "alert." followed by the kind, such as "alert.threat", as
	// the Standard Webhooks specification suggests for event types.
	Type string `json:"type"`

	// Scope is the tenant the alert is for, or empty for the server's
	// operator.
	Scope string `json:"scope"`

	// Kind is what the alert is about.
	Kind Kind `json:"kind"`

	// Title and Body say what happened, why, and what to do, for people.
	Title string `json:"title"`
	Body  string `json:"body"`

	// Time is when it happened.
	Time time.Time `json:"time"`

	// Details are the facts behind the alert, for programs.
	Details Details `json:"details"`
}

// Details are the facts behind an [Alert]. Fields that don't apply are
// left out.
type Details struct {
	// Profile, Device, Hostname, and Client say who made the query: the
	// profile that answered it, the device's configured name, the name it
	// gives itself on the network, and its address.
	Profile  string `json:"profile,omitempty"`
	Device   string `json:"device,omitempty"`
	Hostname string `json:"hostname,omitempty"`
	Client   string `json:"client,omitempty"`

	// Name is the queried name, and Reason, List, and Detail why it was
	// blocked, as the query log has them.
	Name   string `json:"name,omitempty"`
	Reason string `json:"reason,omitempty"`
	List   string `json:"list,omitempty"`
	Detail string `json:"detail,omitempty"`

	// Queries and Errors count the queries in a failing window, and the
	// ones that failed.
	Queries int `json:"queries,omitempty"`
	Errors  int `json:"errors,omitempty"`

	// Error is the most recent error, for failing lookups and lists that
	// didn't load. Tenants' alerts leave it out.
	Error string `json:"error,omitempty"`

	// Count is how many alerts a summary stands for, and Names a few of
	// the names or devices they were about.
	Count int      `json:"count,omitempty"`
	Names []string `json:"names,omitempty"`

	// Link opens the web UI where the alert can be followed up, if the UI
	// has a published origin.
	Link string `json:"link,omitempty"`
}

// kindList joins kinds for an error message.
func kindList(kinds []Kind) string {
	s := ""
	for i, k := range kinds {
		if i > 0 {
			s += ", "
		}
		s += string(k)
	}
	return s
}
