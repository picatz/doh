package alerts

import (
	"cmp"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/picatz/doh/internal/querylog"
	"github.com/picatz/doh/internal/ratelimit"
)

// ErrNoDestinations reports a test of a scope with nowhere to send it.
var ErrNoDestinations = errors.New("no destinations")

// Internal limits.
const (
	// tickInterval is how often bursts, quiet hours, and the store are
	// checked.
	tickInterval = time.Minute

	// deliveryQueue bounds the deliveries waiting to be sent, and
	// deliveryWorkers how many are sent at once.
	deliveryQueue   = 256
	deliveryWorkers = 2

	// maxCoalesced bounds the alerts remembered for coalescing. Beyond
	// it, new alerts are counted toward their burst's summary instead of
	// sent.
	maxCoalesced = 10_000

	// maxBurstNames is how many names a burst's summary lists.
	maxBurstNames = 3

	// maxHeld bounds the alerts of one kind held during quiet hours;
	// beyond it, they're only counted.
	maxHeld = maxHeldListed
)

// defaultBackoff is how long to wait before each retry of a delivery.
var defaultBackoff = []time.Duration{2 * time.Second, 10 * time.Second, 30 * time.Second}

// Options configures an [Engine].
type Options struct {
	// Path is the file settings, destinations, and seen devices are kept
	// in, which needn't exist yet. If empty, they're kept in memory only.
	Path string

	// Logger reports delivery failures and dropped entries. If nil,
	// nothing is logged.
	Logger *slog.Logger

	// Origin is the web UI's published origin, such as
	// "https://admin.dns.example.com", for links in alerts. If empty,
	// alerts have no links.
	Origin string

	// ProfileName names a profile for people, such as "Kids' tablets"
	// for "kids". If nil, or if it returns "", profiles are named by ID.
	ProfileName func(id string) string

	// LookupNetIP resolves destinations' host names. If nil, the system's
	// resolver is used. Tenants' destinations are refused unless every
	// address it returns is public.
	LookupNetIP func(ctx context.Context, host string) ([]netip.Addr, error)

	// Canary reports whether a name is a canary: one software looks up to
	// ask whether it may route around the resolver, such as Firefox's
	// use-application-dns.net, so blocking it is an answer, not a threat.
	// The server passes filter.Canary. If nil, every bypass block is a
	// threat.
	Canary func(name string) bool

	// QueueSize is how many query log entries may wait to be examined
	// before more are dropped. It defaults to [DefaultQueueSize].
	QueueSize int

	// Mail, if set, is how alerts are sent by email. Without it, email
	// addresses can't be added.
	Mail *MailConfig

	// PushKeyPath is the file the server's VAPID key, which signs Web
	// Push messages, is kept in, generated the first time it's needed.
	// If empty, the key is kept in memory, and browsers must subscribe
	// again after a restart.
	PushKeyPath string

	// PushSubject is how push services may reach the server's operator,
	// as a mailto: or https: URL, sent in every VAPID token. It may be
	// empty, though some push services prefer one.
	PushSubject string
}

// Engine turns query log entries and server events into alerts, and
// delivers them. It's safe for concurrent use.
type Engine struct {
	store  *store
	logger *slog.Logger
	words  writer
	canary func(string) bool

	entries chan querylog.Entry
	lists   chan listFailure
	dropped atomic.Uint64

	jobs                         chan job
	tenantClient, operatorClient *http.Client
	loopbackClient               *http.Client
	send                         func(ctx context.Context, scope string, d destination, a Alert) error
	backoff                      []time.Duration

	mailer      *mailer
	push        *pushKeys
	pushSubject string

	// Rate limits on confirmation emails, by scope and by address, on
	// wrong confirmation codes, by scope, and on alert emails, by
	// address.
	confirmScopeRate, confirmAddressRate *ratelimit.Limiter
	confirmTries, emailRate              *ratelimit.Limiter

	ctx       context.Context
	cancel    context.CancelFunc
	wg        sync.WaitGroup
	closeOnce sync.Once
	closeErr  error

	// Owned by run.
	windows       map[string]*window
	lastSent      map[coalesceKey]time.Time
	bursts        map[burstKey]*burst
	held          map[string]map[Kind]*heldAlerts
	reportedDrops uint64
}

// listFailure is a blocklist that failed to load.
type listFailure struct {
	time time.Time
	name string
	err  error
}

// job is an alert to deliver to a destination.
type job struct {
	scope string
	dest  destination
	alert Alert
}

// coalesceKey identifies alerts that are sent at most once per
// [CoalesceWindow].
type coalesceKey struct {
	scope string
	kind  Kind
	key   string
}

// burstKey identifies alerts that are counted together for bursts.
type burstKey struct {
	scope string
	kind  Kind
	group string
}

// burst counts the alerts of a burstKey within a window.
type burst struct {
	start   time.Time
	sent    int
	held    int
	names   []string
	subject string // what the alerts are about, such as a device
	link    string
}

// heldAlerts are alerts of one kind held during quiet hours.
type heldAlerts struct {
	alerts []Alert // the first maxHeld
	total  int
}

// New returns an engine that keeps its state at opts.Path, and starts it.
// Close it to stop it and save its state.
func New(opts Options) (*Engine, error) {
	e, err := newEngine(opts)
	if err != nil {
		return nil, err
	}
	e.start()
	return e, nil
}

// newEngine returns an engine that isn't started yet.
func newEngine(opts Options) (*Engine, error) {
	s, err := openStore(opts.Path)
	if err != nil {
		return nil, err
	}
	var m *mailer
	if opts.Mail != nil {
		if m, err = newMailer(*opts.Mail); err != nil {
			return nil, err
		}
	}
	if opts.PushSubject != "" && !strings.HasPrefix(opts.PushSubject, "mailto:") && !strings.HasPrefix(opts.PushSubject, "https://") {
		return nil, errors.New("alerts: the push subject is a mailto: or https: URL")
	}
	lookup := lookupFunc(defaultLookup)
	if opts.LookupNetIP != nil {
		lookup = opts.LookupNetIP
	}
	ctx, cancel := context.WithCancel(context.Background())
	e := &Engine{
		store:  s,
		logger: cmp.Or(opts.Logger, slog.New(slog.DiscardHandler)),
		words:  writer{origin: opts.Origin, profileName: opts.ProfileName},
		canary: opts.Canary,

		entries: make(chan querylog.Entry, cmp.Or(opts.QueueSize, DefaultQueueSize)),
		lists:   make(chan listFailure, 16),

		jobs:           make(chan job, deliveryQueue),
		tenantClient:   newClient(publicOnly, lookup, false),
		operatorClient: newClient(anyAddr, lookup, true),
		loopbackClient: newClient(loopbackOnly, lookup, false),
		backoff:        defaultBackoff,

		mailer:      m,
		push:        &pushKeys{path: opts.PushKeyPath},
		pushSubject: opts.PushSubject,

		confirmScopeRate:   perHour(ConfirmEmailsPerScope),
		confirmAddressRate: &ratelimit.Limiter{Rate: ConfirmEmailsPerAddress / (24 * time.Hour).Seconds(), Burst: ConfirmEmailsPerAddress},
		confirmTries:       perHour(ConfirmAttemptsPerScope),
		emailRate:          perHour(EmailsPerAddress),

		ctx:    ctx,
		cancel: cancel,

		windows:  make(map[string]*window),
		lastSent: make(map[coalesceKey]time.Time),
		bursts:   make(map[burstKey]*burst),
		held:     make(map[string]map[Kind]*heldAlerts),
	}
	e.send = e.post
	return e, nil
}

// start starts examining entries and delivering alerts.
func (e *Engine) start() {
	e.wg.Go(e.run)
	for range deliveryWorkers {
		e.wg.Go(e.worker)
	}
}

// Close stops the engine, abandoning deliveries in progress, and saves
// its state.
func (e *Engine) Close() error {
	e.closeOnce.Do(func() {
		e.cancel()
		e.wg.Wait()
		e.closeErr = e.store.flush()
	})
	return e.closeErr
}

// Observe examines a query log entry for alerts, later. It never blocks:
// if too many entries are waiting, e is dropped, and counted.
func (e *Engine) Observe(entry querylog.Entry) {
	select {
	case e.entries <- entry:
	default:
		e.dropped.Add(1)
	}
}

// ListFailed reports that the blocklist named name failed to load, for an
// alert to the operator. It never blocks.
func (e *Engine) ListFailed(name string, err error) {
	select {
	case e.lists <- listFailure{time: time.Now(), name: name, err: err}:
	default:
		e.dropped.Add(1)
	}
}

// Dropped returns how many entries and events have been dropped because
// too many were waiting.
func (e *Engine) Dropped() uint64 { return e.dropped.Load() }

// Get returns scope's settings, its destinations (without secrets), and
// its recent deliveries, newest first.
func (e *Engine) Get(scope string) (Settings, []Destination, []Delivery) {
	return e.store.view(scope)
}

// SetSettings replaces scope's settings, returning them as kept.
func (e *Engine) SetSettings(scope string, s Settings) (Settings, error) {
	s, err := s.normalize(scope)
	if err != nil {
		return Settings{}, err
	}
	if err := e.store.setSettings(scope, s); err != nil {
		return Settings{}, err
	}
	return s.clone(), nil
}

// perHour returns a limiter allowing n events an hour per key, all at
// once if need be.
func perHour(n int) *ratelimit.Limiter {
	return &ratelimit.Limiter{Rate: float64(n) / time.Hour.Seconds(), Burst: n}
}

// maxNameLength bounds destinations' names, in characters.
const maxNameLength = 64

// AvailableTypes returns the destination types scopes can add: email only
// if the server has a mail server.
func (e *Engine) AvailableTypes() []DestinationType {
	return slices.DeleteFunc(slices.Clone(DestinationTypes), func(t DestinationType) bool { return t == Email && e.mailer == nil })
}

// AddDestination adds a destination to scope, returning it and, for a
// webhook, its signing secret, which is shown only this once.
//
// An email address starts pending: doh sends it a code, and nothing else
// until the code is given to [Engine.Confirm] or the page it links to.
// Adding a pending address again sends a new code. A push destination is
// a browser's subscription; subscribing the same browser again renews
// it.
func (e *Engine) AddDestination(ctx context.Context, scope string, n NewDestination) (Destination, string, error) {
	if !n.Type.Valid() {
		return Destination{}, "", fmt.Errorf("%w: a destination's type is one of %s", ErrInvalid, typeList(DestinationTypes))
	}
	name := strings.TrimSpace(n.Name)
	if utf8.RuneCountInString(name) > maxNameLength || !utf8.ValidString(name) || strings.ContainsFunc(name, func(r rune) bool { return r < ' ' || r == 0x7f }) {
		return Destination{}, "", fmt.Errorf("%w: name a destination with at most %d printable characters", ErrInvalid, maxNameLength)
	}
	switch n.Type {
	case Email:
		d, err := e.addEmail(ctx, scope, n, name)
		return d, "", err
	case Push:
		d, err := e.addPush(scope, n, name)
		return d, "", err
	}
	u, err := checkURL(scope, n.Type, strings.TrimSpace(n.URL))
	if err != nil {
		return Destination{}, "", err
	}

	d := &destination{
		Destination: Destination{ID: newID(""), Type: n.Type, Name: name, Created: time.Now().UTC(), CreatedBy: n.CreatedBy, State: Active},
		url:         u.String(),
	}
	if n.Type == Webhook {
		d.secret = newSecret()
	}
	if err := e.store.addDestination(scope, d); err != nil {
		return Destination{}, "", err
	}
	return d.view(), d.secret, nil
}

// RemoveDestination removes scope's destination with id.
func (e *Engine) RemoveDestination(scope, id string) error {
	return e.store.removeDestination(scope, id)
}

// ForgetScope removes everything kept for scope, such as when a tenant is
// deleted.
func (e *Engine) ForgetScope(scope string) error { return e.store.forget(scope) }

// Test sends a test alert to each of scope's destinations, once each and
// at once, whatever the settings, and returns how each went.
func (e *Engine) Test(ctx context.Context, scope string) ([]Delivery, error) {
	dests := e.store.destinations(scope)
	if len(dests) == 0 {
		return nil, fmt.Errorf("%w: add one first", ErrNoDestinations)
	}
	a := e.stamp(scope, e.words.test(time.Now()))

	results := make([]Delivery, len(dests))
	var wg sync.WaitGroup
	for i, d := range dests {
		wg.Go(func() {
			ctx, cancel := context.WithTimeout(ctx, requestTimeout)
			defer cancel()
			results[i] = e.result(a, d, e.send(ctx, scope, d, a), 1)
			e.store.record(scope, results[i])
		})
	}
	wg.Wait()
	return results, nil
}

// run examines entries and events, and keeps time, until the engine is
// closed.
func (e *Engine) run() {
	ticker := time.NewTicker(tickInterval)
	defer ticker.Stop()
	for {
		select {
		case <-e.ctx.Done():
			return
		case entry := <-e.entries:
			e.observe(&entry)
		case f := <-e.lists:
			e.raise(f.time, event{alert: e.words.listFailed(f.time, f.name, f.err), key: f.name})
		case now := <-ticker.C:
			e.tick(now)
		}
	}
}

// event is a candidate alert.
type event struct {
	scope string
	alert Alert

	// key coalesces repeats: alerts of the same kind and key are sent at
	// most once per CoalesceWindow.
	key string

	// group, subject, and link count bursts: alerts of the same kind and
	// group beyond BurstLimit in a window are summarized as about subject,
	// linking to link, and named by sample.
	group, subject, link, sample string
}

// observe examines a query log entry.
func (e *Engine) observe(entry *querylog.Entry) {
	now := entry.Time
	if now.IsZero() {
		now = time.Now()
	}

	// The operator's window covers the whole server: failing lookups are
	// how it's run. Each tenant's covers its own queries.
	e.count("", entry, now)
	if entry.Tenant != "" {
		e.count(entry.Tenant, entry, now)
	}

	if entry.Profile == "" {
		return // refused: no profile, so no one's device
	}
	scope := entry.Tenant
	device := deviceKey(entry)

	if isThreat(entry, e.canary) {
		target := cmp.Or(entry.Rule, entry.Name)
		if entry.Reason == reasonRebinding {
			target = entry.Name // the rule is the address it answered
		}
		q := deviceQuery(entry)
		q.Set("status", "blocked")
		e.raise(now, event{
			scope:   scope,
			alert:   e.words.threat(entry),
			key:     device + "\x00" + target,
			group:   device,
			subject: deviceLabel(entry),
			link:    e.words.link("logs", q),
			sample:  entry.Name,
		})
	}

	if device != "" {
		if isNew, learning := e.store.seeDevice(scope, device, now); isNew && !learning {
			e.raise(now, event{
				scope:  scope,
				alert:  e.words.newDevice(entry),
				key:    device,
				link:   e.words.link("logs", nil),
				sample: deviceLabel(entry),
			})
		}
	}
}

// deviceKey identifies the device that sent entry: its configured name in
// its profile, or its address.
func deviceKey(entry *querylog.Entry) string {
	switch {
	case entry.Device != "":
		return "device:" + entry.Profile + "/" + entry.Device
	case entry.Client != "":
		return "client:" + entry.Client
	}
	return ""
}

// window counts queries and errors in one-minute buckets over
// FailingWindow.
type window struct {
	buckets [int(FailingWindow / time.Minute)]bucket
	lastErr string
	last    time.Time
}

type bucket struct {
	minute          int64
	queries, errors int
}

// add counts a query at now.
func (w *window) add(now time.Time, failed bool) {
	m := now.Unix() / 60
	b := &w.buckets[m%int64(len(w.buckets))]
	if b.minute != m {
		*b = bucket{minute: m}
	}
	b.queries++
	if failed {
		b.errors++
	}
	w.last = now
}

// sums returns the queries and errors within the window ending at now.
func (w *window) sums(now time.Time) (queries, errors int) {
	m := now.Unix() / 60
	for _, b := range w.buckets {
		if m-b.minute < int64(len(w.buckets)) && b.minute <= m {
			queries += b.queries
			errors += b.errors
		}
	}
	return queries, errors
}

// count adds entry to scope's window, alerting if lookups are failing.
func (e *Engine) count(scope string, entry *querylog.Entry, now time.Time) {
	w := e.windows[scope]
	if w == nil {
		w = new(window)
		e.windows[scope] = w
	}
	failed := entry.Status == querylog.StatusError
	w.add(now, failed)
	if !failed {
		return
	}
	w.lastErr = entry.Rule
	queries, errs := w.sums(now)
	if errs >= FailingMinErrors && errs*100 >= queries*FailingMinPercent {
		e.raise(now, event{scope: scope, alert: e.words.failing(scope, now, errs, queries, w.lastErr)})
	}
}

// raise sends ev's alert, unless its kind is off or there's nowhere to
// send it, it was sent within CoalesceWindow, or its burst is over
// BurstLimit, when it's counted for the burst's summary.
func (e *Engine) raise(now time.Time, ev event) {
	settings, ok := e.store.settings(ev.scope)
	kind := ev.alert.Kind
	if !ok || !settings.enabled(kind) {
		return
	}

	ck := coalesceKey{ev.scope, kind, ev.key}
	if t, ok := e.lastSent[ck]; ok && now.Sub(t) < CoalesceWindow {
		return
	}
	if len(e.lastSent) >= maxCoalesced {
		e.pruneCoalesced(now)
	}
	full := len(e.lastSent) >= maxCoalesced
	if !full {
		e.lastSent[ck] = now
	}

	bk := burstKey{ev.scope, kind, ev.group}
	b := e.bursts[bk]
	if b != nil && now.Sub(b.start) >= CoalesceWindow {
		e.closeBurst(bk, b, now)
		b = nil
	}
	if b == nil {
		b = &burst{start: now, subject: ev.subject, link: ev.link}
		e.bursts[bk] = b
	}
	if b.sent < BurstLimit && !full {
		b.sent++
		e.dispatch(now, ev.scope, ev.alert, settings)
		return
	}
	b.held++
	if len(b.names) < maxBurstNames && ev.sample != "" && !slices.Contains(b.names, ev.sample) {
		b.names = append(b.names, ev.sample)
	}
}

// closeBurst ends a burst's window, sending a summary of what it held
// back.
func (e *Engine) closeBurst(bk burstKey, b *burst, now time.Time) {
	delete(e.bursts, bk)
	if b.held == 0 {
		return
	}
	settings, ok := e.store.settings(bk.scope)
	if !ok || !settings.enabled(bk.kind) {
		return
	}
	e.dispatch(now, bk.scope, e.words.burst(bk.kind, b.subject, b.held, b.names, b.link, now), settings)
}

// pruneCoalesced forgets alerts sent longer than CoalesceWindow ago.
func (e *Engine) pruneCoalesced(now time.Time) {
	maps.DeleteFunc(e.lastSent, func(_ coalesceKey, t time.Time) bool { return now.Sub(t) >= CoalesceWindow })
}

// dispatch sends an alert to scope's destinations, or during quiet hours,
// holds it, unless it's a threat.
func (e *Engine) dispatch(now time.Time, scope string, a Alert, settings Settings) {
	if a.Kind != KindThreat && a.Kind != KindTest && settings.Quiet(now) {
		byKind := e.held[scope]
		if byKind == nil {
			byKind = make(map[Kind]*heldAlerts)
			e.held[scope] = byKind
		}
		h := byKind[a.Kind]
		if h == nil {
			h = new(heldAlerts)
			byKind[a.Kind] = h
		}
		if len(h.alerts) < maxHeld {
			h.alerts = append(h.alerts, a)
		}
		h.total++
		return
	}
	e.enqueue(scope, e.stamp(scope, a))
}

// stamp gives a an ID and its scope.
func (e *Engine) stamp(scope string, a Alert) Alert {
	a.ID = newID("msg_")
	a.Type = "alert." + string(a.Kind)
	a.Scope = scope
	if a.Time.IsZero() {
		a.Time = time.Now()
	}
	a.Time = a.Time.UTC()
	return a
}

// enqueue queues a for each of scope's destinations. If the queue is
// full, the delivery fails at once.
func (e *Engine) enqueue(scope string, a Alert) {
	for _, d := range e.store.destinations(scope) {
		select {
		case e.jobs <- job{scope: scope, dest: d, alert: a}:
		default:
			e.store.record(scope, e.result(a, d, errors.New("too many alerts were waiting to be sent"), 0))
		}
	}
}

// tick ends bursts, releases what quiet hours held, forgets what's
// expired, and saves the store.
func (e *Engine) tick(now time.Time) {
	for bk, b := range e.bursts {
		if now.Sub(b.start) >= CoalesceWindow {
			e.closeBurst(bk, b, now)
		}
	}
	e.pruneCoalesced(now)
	maps.DeleteFunc(e.windows, func(_ string, w *window) bool { return now.Sub(w.last) > FailingWindow })

	for scope, byKind := range e.held {
		settings, ok := e.store.settings(scope)
		if ok && settings.Quiet(now) {
			continue
		}
		delete(e.held, scope)
		if !ok {
			continue
		}
		for _, kind := range Kinds {
			h := byKind[kind]
			switch {
			case h == nil:
			case h.total == 1:
				e.enqueue(scope, e.stamp(scope, h.alerts[0]))
			default:
				e.enqueue(scope, e.stamp(scope, e.words.quiet(kind, h.alerts, h.total, now)))
			}
		}
	}

	if err := e.store.flush(); err != nil {
		e.logger.Warn("alerts: saving", slog.Any("error", err))
	}
	if d := e.dropped.Load(); d > e.reportedDrops {
		e.logger.Warn("alerts: entries dropped because too many were waiting", slog.Uint64("dropped", d-e.reportedDrops))
		e.reportedDrops = d
	}
}

// worker delivers queued alerts until the engine is closed.
func (e *Engine) worker() {
	for {
		select {
		case <-e.ctx.Done():
			return
		case j := <-e.jobs:
			e.deliver(j)
		}
	}
}

// deliver sends a queued alert, retrying with backoff if it fails in a
// way that might not last, and records how it went.
func (e *Engine) deliver(j job) {
	var err error
	attempts := 0
	for {
		attempts++
		ctx, cancel := context.WithTimeout(e.ctx, requestTimeout)
		err = e.send(ctx, j.scope, j.dest, j.alert)
		cancel()
		if err == nil || isPermanent(err) || attempts > len(e.backoff) {
			break
		}
		wait := e.backoff[attempts-1]
		var ra retryAfterError
		if errors.As(err, &ra) {
			if ra.after > maxRetryAfter {
				err = fmt.Errorf("%w, and asked doh to wait %s before trying again", err, ra.after)
				break
			}
			wait = max(wait, ra.after)
		}
		select {
		case <-time.After(wait):
		case <-e.ctx.Done():
			return // closing: abandoned
		}
	}
	if e.ctx.Err() != nil {
		return
	}
	e.store.record(j.scope, e.result(j.alert, j.dest, err, attempts))
	if err != nil {
		attrs := []slog.Attr{slog.String("destination", j.dest.ID), slog.String("kind", string(j.alert.Kind)), slog.Int("attempts", attempts), slog.Any("error", err)}
		if j.scope != "" {
			attrs = append(attrs, slog.String("tenant", j.scope))
		}
		e.logger.LogAttrs(e.ctx, slog.LevelWarn, "alerts: delivery failed", attrs...)
	}
}

// result describes a delivery of a to d that ended with err.
func (e *Engine) result(a Alert, d destination, err error, attempts int) Delivery {
	del := Delivery{Time: time.Now().UTC(), Alert: a.ID, Kind: a.Kind, Summary: a.Title, Destination: d.ID, OK: err == nil, Attempts: attempts}
	if err != nil {
		del.Error = err.Error()
	}
	return del
}

// newID returns a random identifier: prefix and 16 hex characters, 64
// bits.
func newID(prefix string) string {
	var b [8]byte
	_, _ = rand.Read(b[:]) // never fails
	return fmt.Sprintf("%s%x", prefix, b)
}
