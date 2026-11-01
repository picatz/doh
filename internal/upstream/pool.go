package upstream

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// Pool defaults.
const (
	// DefaultHedgeDelay is how long a [Pool] waits for an upstream before
	// also asking the next one.
	DefaultHedgeDelay = 300 * time.Millisecond

	// unhealthyAfter consecutive failures mark an upstream unhealthy.
	unhealthyAfter = 2

	// minBackoff and maxBackoff bound how long an unhealthy upstream is
	// tried last, doubling with each further failure.
	minBackoff = 5 * time.Second
	maxBackoff = 5 * time.Minute
)

// Pool is an [Exchanger] over several upstreams that answers from the
// fastest healthy one, in the spirit of Happy Eyeballs ([RFC 8305]):
//
//   - Upstreams are asked in order of preference: the configured order,
//     with unhealthy ones last.
//   - If an upstream hasn't answered after the hedge delay, or fails, the
//     next is asked too, without cancelling the first; the first answer
//     wins, and the rest are cancelled.
//   - An upstream that fails twice in a row is unhealthy: it's asked last
//     for a backoff that starts at five seconds and doubles with each
//     further failure, up to five minutes. Any answer makes it healthy
//     again.
//
// So one unreachable upstream costs a single hedge delay, not a timeout,
// and only until it's marked unhealthy.
//
// A response with any DNS response code counts as an answer; only
// transport failures count against an upstream. If every upstream fails,
// the error matches [ErrAllFailed] and includes each upstream's error.
//
// [RFC 8305]: https://www.rfc-editor.org/rfc/rfc8305.html
type Pool struct {
	members    []*member
	hedgeDelay time.Duration
}

// member is an upstream in a pool, with its health.
type member struct {
	Exchanger
	name string

	mu       sync.Mutex
	failures int       // consecutive
	until    time.Time // unhealthy until then
}

// PoolOption configures a [Pool].
type PoolOption func(*Pool)

// WithHedgeDelay sets how long the pool waits for an upstream before also
// asking the next one. It defaults to [DefaultHedgeDelay]; zero asks
// every upstream at once.
func WithHedgeDelay(d time.Duration) PoolOption {
	return func(p *Pool) { p.hedgeDelay = d }
}

// NewPool returns a pool over upstreams, named for [Pool.Health] by their
// String methods, in order of preference.
func NewPool(upstreams []Exchanger, opts ...PoolOption) *Pool {
	p := &Pool{hedgeDelay: DefaultHedgeDelay}
	for _, u := range upstreams {
		p.members = append(p.members, &member{Exchanger: u, name: fmt.Sprint(u)})
	}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

// Health describes an upstream's health in a [Pool].
type Health struct {
	// Name identifies the upstream, such as "https://dns.google/dns-query".
	Name string `json:"name"`

	// Healthy reports whether the upstream is asked in its configured
	// place.
	Healthy bool `json:"healthy"`

	// Failures is the number of consecutive failed exchanges.
	Failures int `json:"failures,omitempty"`

	// RetryAt is when an unhealthy upstream returns to its place, if it
	// hasn't answered sooner.
	RetryAt time.Time `json:"retry_at,omitzero"`
}

// Health describes each upstream, in configured order.
func (p *Pool) Health() []Health {
	now := time.Now()
	health := make([]Health, len(p.members))
	for i, m := range p.members {
		m.mu.Lock()
		health[i] = Health{Name: m.name, Healthy: !now.Before(m.until), Failures: m.failures}
		if !health[i].Healthy {
			health[i].RetryAt = m.until
		}
		m.mu.Unlock()
	}
	return health
}

// order returns the members in order of preference: healthy ones as
// configured, then unhealthy ones, soonest to recover first.
func (p *Pool) order() []*member {
	now := time.Now()
	order := slices.Clone(p.members)
	slices.SortStableFunc(order, func(a, b *member) int {
		ua, ub := a.unhealthyUntil(now), b.unhealthyUntil(now)
		switch {
		case ua.IsZero() && ub.IsZero():
			return 0
		case ua.IsZero():
			return -1
		case ub.IsZero():
			return 1
		default:
			return ua.Compare(ub)
		}
	})
	return order
}

// unhealthyUntil returns when m becomes healthy, or zero if it is.
func (m *member) unhealthyUntil(now time.Time) time.Time {
	m.mu.Lock()
	defer m.mu.Unlock()
	if now.Before(m.until) {
		return m.until
	}
	return time.Time{}
}

// record updates m's health after an exchange. Exchanges the pool
// cancelled because another upstream answered first don't count.
func (m *member) record(err error, cancelled bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	switch {
	case err == nil:
		m.failures, m.until = 0, time.Time{}
	case cancelled:
	default:
		m.failures++
		if m.failures >= unhealthyAfter {
			// Cap the exponent too, so the shift can't overflow.
			backoff := min(minBackoff<<min(m.failures-unhealthyAfter, 16), maxBackoff)
			m.until = time.Now().Add(backoff)
		}
	}
}

type result struct {
	resp *dns.Msg
	err  error
}

// Exchange sends query to the pool's upstreams as described for [Pool],
// returning the first answer.
func (p *Pool) Exchange(ctx context.Context, query *dns.Msg) (*dns.Msg, error) {
	order := p.order()
	if len(order) == 0 {
		return nil, fmt.Errorf("%w: no upstreams", ErrAllFailed)
	}

	// Once one upstream answers, cancel the rest, then wait for them to
	// stop, so none outlives the call. (Deferred calls run last first.)
	var wg sync.WaitGroup
	defer wg.Wait()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	results := make(chan result, len(order))

	start := func(m *member) {
		wg.Go(func() {
			resp, err := m.Exchange(ctx, query)
			m.record(err, err != nil && ctx.Err() != nil)
			if err != nil {
				err = fmt.Errorf("%s: %w", m.name, err)
			}
			results <- result{resp, err}
		})
	}

	hedge := time.NewTimer(p.hedgeDelay)
	defer hedge.Stop()

	next, running := 0, 0
	errs := []error{ErrAllFailed}
	startNext := func() {
		start(order[next])
		next++
		running++
		hedge.Reset(p.hedgeDelay)
	}
	startNext()

	for running > 0 {
		var hedged <-chan time.Time
		if next < len(order) {
			hedged = hedge.C
		}

		select {
		case r := <-results:
			running--
			if r.err == nil {
				return r.resp, nil
			}
			errs = append(errs, r.err)
			// A failure is reason enough to ask the next upstream now.
			if next < len(order) {
				startNext()
			}
		case <-hedged:
			startNext()
		case <-ctx.Done():
			cancel()
			return nil, errors.Join(append(errs, context.Cause(ctx))...)
		}
	}

	return nil, errors.Join(errs...)
}

// String describes the pool.
func (p *Pool) String() string {
	names := make([]string, len(p.members))
	for i, m := range p.members {
		names[i] = m.name
	}
	return fmt.Sprintf("pool%v", names)
}
