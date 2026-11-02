package alerts

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/picatz/doh/internal/webpush"
)

// pushServices are the push services browsers subscribe through, by host
// name: Google's (Chrome, Edge on Android, and other Chromium browsers),
// Mozilla's, Apple's, and Microsoft's. A tenant's, or the operator's, push
// destinations may only be on these, so a browser's "subscription" can't
// point the server anywhere else.
var pushServices = []string{"fcm.googleapis.com", "updates.push.services.mozilla.com", "web.push.apple.com"}

// pushServiceSuffixes are the push services whose hosts vary, such as
// Apple's api.push.apple.com and Microsoft's wns2-*.notify.windows.com.
var pushServiceSuffixes = []string{".push.apple.com", ".notify.windows.com"}

// KnownPushService reports whether host is one of the push services
// browsers subscribe through.
func KnownPushService(host string) bool {
	host = strings.ToLower(host)
	for _, s := range pushServices {
		if host == s {
			return true
		}
	}
	for _, suffix := range pushServiceSuffixes {
		if label, ok := strings.CutSuffix(host, suffix); ok && validLabels(label) {
			return true
		}
	}
	return false
}

// validLabels reports whether s is DNS labels: letters, digits, and
// hyphens, separated by dots.
func validLabels(s string) bool {
	for label := range strings.SplitSeq(s, ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
				return false
			}
		}
	}
	return true
}

// checkPushEndpoint checks that u is a push endpoint doh may send to: an
// https URL, on the default port, on a known push service, with a path,
// and nothing else.
func checkPushEndpoint(u *url.URL) error {
	switch {
	case u.Scheme != "https" || u.Opaque != "" || u.User != nil:
		return fmt.Errorf("%w: a push endpoint is an https URL", ErrInvalid)
	case u.Port() != "" && u.Port() != "443":
		return fmt.Errorf("%w: a push endpoint uses the default https port", ErrInvalid)
	case !KnownPushService(u.Hostname()) || u.Hostname() != strings.ToLower(u.Hostname()):
		return fmt.Errorf("%w: %s isn't a browser push service doh sends to (Google's, Mozilla's, Apple's, or Microsoft's)", ErrInvalid, u.Hostname())
	case strings.Trim(u.Path, "/") == "" || u.Fragment != "":
		return fmt.Errorf("%w: a push endpoint names a subscription", ErrInvalid)
	}
	return nil
}

// pushURLView is how a push endpoint is shown: its push service, and
// "/…". The rest is the browser's to know.
func pushURLView(endpoint string) string {
	u, err := url.Parse(endpoint)
	if err != nil {
		return ""
	}
	return u.Scheme + "://" + u.Host + "/…"
}

// SubscriptionID returns how a push destination is identified to the
// browser that subscribed: the SHA-256 of its endpoint, as unpadded
// base64url.
func SubscriptionID(endpoint string) string {
	sum := sha256.Sum256([]byte(endpoint))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// pushKeys holds the server's VAPID key, loaded or made the first time
// it's needed.
type pushKeys struct {
	path string // where it's kept, or empty for memory only

	mu  sync.Mutex
	key *webpush.VAPIDKey
}

// get returns the key.
func (p *pushKeys) get() (*webpush.VAPIDKey, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.key != nil {
		return p.key, nil
	}
	var (
		k   *webpush.VAPIDKey
		err error
	)
	if p.path == "" {
		k, err = webpush.GenerateVAPIDKey()
	} else {
		k, err = webpush.LoadOrCreateVAPIDKey(p.path)
	}
	if err != nil {
		return nil, err
	}
	p.key = k
	return k, nil
}

// PushKey returns the server's VAPID public key, as unpadded base64url,
// for browsers to subscribe with. It's made the first time it's needed.
func (e *Engine) PushKey() (string, error) {
	k, err := e.push.get()
	if err != nil {
		return "", err
	}
	return k.PublicKeyString(), nil
}

// addPush adds, or renews, a browser's push subscription.
func (e *Engine) addPush(scope string, n NewDestination, name string) (Destination, error) {
	if n.Subscription == nil {
		return Destination{}, fmt.Errorf("%w: a push destination needs the browser's subscription", ErrInvalid)
	}
	sub := *n.Subscription
	sub.Endpoint = strings.TrimSpace(sub.Endpoint)
	u, _, err := sub.Decode()
	if err != nil {
		return Destination{}, fmt.Errorf("%w: %s", ErrInvalid, strings.TrimPrefix(err.Error(), "webpush: "))
	}
	if err := checkPushEndpoint(u); err != nil {
		return Destination{}, err
	}
	d := &destination{
		Destination: Destination{ID: newID(""), Type: Push, Name: name, Created: time.Now().UTC(), CreatedBy: n.CreatedBy, State: Active},
		url:         u.String(),
		p256dh:      strings.TrimRight(sub.Keys.P256DH, "="),
		auth:        strings.TrimRight(sub.Keys.Auth, "="),
	}
	return e.store.upsertPush(scope, d)
}

// pushMessage is what a push notification carries, as JSON, for the web
// UI's service worker to show.
type pushMessage struct {
	ID    string    `json:"id"`
	Kind  Kind      `json:"kind"`
	Title string    `json:"title"`
	Body  string    `json:"body"`
	Tag   string    `json:"tag"`
	URL   string    `json:"url,omitempty"`
	Time  time.Time `json:"time"`
}

// pushTag groups an alert's notifications, so a newer one about the same
// thing replaces the last on the screen: threats on one device, failing
// lookups, one new device, one list.
func pushTag(a Alert) string {
	subject := ""
	switch a.Kind {
	case KindThreat, KindNewDevice:
		subject = a.Details.Profile + "/" + firstOf(a.Details.Device, a.Details.Hostname, a.Details.Client)
		if a.Details.Count > 0 {
			subject += "/summary"
		}
	case KindListFailed:
		subject = a.Details.List
	}
	return "doh:" + string(a.Kind) + ":" + subject
}

// firstOf returns the first of values that isn't empty.
func firstOf(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// pushPayload returns a's notification, cut to fit one encrypted record.
func pushPayload(a Alert) ([]byte, error) {
	m := pushMessage{ID: a.ID, Kind: a.Kind, Title: truncate(a.Title, 200), Body: a.Body, Tag: pushTag(a), URL: a.Details.Link, Time: a.Time}
	m.Body = truncate(withoutLink(m.Body, m.URL), 1000)
	for {
		b, err := json.Marshal(m)
		if err != nil {
			return nil, err
		}
		if len(b) <= webpush.MaxPlaintext {
			return b, nil
		}
		if m.URL != "" && len(m.URL) > 1024 {
			m.URL = ""
			continue
		}
		m.Body = truncate(m.Body, utf8.RuneCountInString(m.Body)/2)
	}
}

// withoutLink returns body without the link it ends with, which a
// notification opens when it's tapped, so needn't show: "… See it: URL"
// becomes "…", and "… looking up: URL", "… looking up."
func withoutLink(body, link string) string {
	if link == "" {
		return body
	}
	rest, ok := strings.CutSuffix(body, link)
	if !ok {
		return body
	}
	rest = strings.TrimSpace(rest)
	for _, lead := range []string{"See it:", "See them:"} {
		if r, ok := strings.CutSuffix(rest, lead); ok {
			return strings.TrimSpace(r)
		}
	}
	if r, ok := strings.CutSuffix(rest, ":"); ok {
		return r + "."
	}
	return rest
}

// truncate cuts s to at most n runes, ending it with "…" if it's cut.
func truncate(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	return string(r[:max(n-1, 0)]) + "…"
}

// pushTTL is how long a push service keeps an alert for a browser that's
// offline: a day, or for failing lookups and tests, which are soon stale,
// an hour.
func pushTTL(k Kind) time.Duration {
	switch k {
	case KindFailing, KindTest:
		return time.Hour
	}
	return 24 * time.Hour
}

// pushUrgency is an alert's urgency (RFC 8030, Section 5.3): high for
// threats, so phones show them at once, and normal otherwise.
func pushUrgency(k Kind) string {
	if k == KindThreat {
		return "high"
	}
	return "normal"
}

// pushTopic is the Topic header (RFC 8030, Section 5.4) for an alert's
// tag: a push service holding an undelivered message with the same topic
// replaces it, as the browser would on screen. A topic is at most 32
// base64url characters.
func pushTopic(tag string) string {
	sum := sha256.Sum256([]byte(tag))
	return base64.RawURLEncoding.EncodeToString(sum[:])[:32]
}

// errGone reports a push subscription that has ended.
var errGone = errors.New("the browser's push subscription has ended; subscribe again from the web UI")

// pushRequest returns the request that sends a to the browser behind d,
// encrypted for it (RFC 8291) and signed with the server's VAPID key
// (RFC 8292).
func (e *Engine) pushRequest(ctx context.Context, d destination, a Alert) (*http.Request, error) {
	key, err := e.push.get()
	if err != nil {
		return nil, permanentError{err}
	}
	p256dh, err1 := webpush.DecodeKey(d.p256dh)
	auth, err2 := webpush.DecodeKey(d.auth)
	if err1 != nil || err2 != nil {
		return nil, permanentError{errors.New("the push subscription's keys are invalid")}
	}
	payload, err := pushPayload(a)
	if err != nil {
		return nil, permanentError{err}
	}
	body, err := webpush.Encrypt(webpush.Keys{P256DH: p256dh, Auth: auth}, payload)
	if err != nil {
		return nil, permanentError{err}
	}
	authorization, err := key.Authorization(d.url, e.pushSubject, time.Now())
	if err != nil {
		return nil, permanentError{err}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.url, bytes.NewReader(body))
	if err != nil {
		return nil, permanentError{err}
	}
	req.Header = http.Header{
		"User-Agent":       {userAgent},
		"Content-Type":     {"application/octet-stream"},
		"Content-Encoding": {"aes128gcm"},
		"Authorization":    {authorization},
		"Ttl":              {strconv.Itoa(int(pushTTL(a.Kind).Seconds()))},
		"Urgency":          {pushUrgency(a.Kind)},
		"Topic":            {pushTopic(pushTag(a))},
	}
	return req, nil
}

// retryAfterError is a failure that may be retried, but no sooner than
// after.
type retryAfterError struct {
	err   error
	after time.Duration
}

func (e retryAfterError) Error() string { return e.err.Error() }
func (e retryAfterError) Unwrap() error { return e.err }

// maxRetryAfter bounds how long a delivery waits when a destination asks
// it to; asked to wait longer, it gives up.
const maxRetryAfter = 2 * time.Minute

// retryAfter parses a Retry-After header (RFC 9110, Section 10.2.3): a
// number of seconds, or a date. It returns 0 if there's none.
func retryAfter(h string, now time.Time) time.Duration {
	h = strings.TrimSpace(h)
	if h == "" {
		return 0
	}
	if n, err := strconv.ParseInt(h, 10, 64); err == nil {
		if n < 0 {
			return 0
		}
		return time.Duration(min(n, int64(24*time.Hour/time.Second))) * time.Second
	}
	if t, err := http.ParseTime(h); err == nil {
		return max(t.Sub(now), 0)
	}
	return 0
}
