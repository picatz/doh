package upstream

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/miekg/dns"
)

// fake is an upstream that answers after delay, or fails.
type fake struct {
	name  string
	delay time.Duration
	fail  atomic.Bool
	calls atomic.Int32
}

func (f *fake) String() string { return f.name }

func (f *fake) Exchange(ctx context.Context, query *dns.Msg) (*dns.Msg, error) {
	f.calls.Add(1)
	select {
	case <-time.After(f.delay):
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if f.fail.Load() {
		return nil, errors.New(f.name + " is down")
	}
	resp := new(dns.Msg).SetReply(query)
	resp.Answer = append(resp.Answer, &dns.TXT{Hdr: dns.RR_Header{Name: query.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET}, Txt: []string{f.name}})
	return resp, nil
}

// answeredBy returns which fake answered resp.
func answeredBy(t *testing.T, resp *dns.Msg) string {
	t.Helper()
	if resp == nil || len(resp.Answer) != 1 {
		t.Fatalf("unexpected response %v", resp)
	}
	return resp.Answer[0].(*dns.TXT).Txt[0]
}

func txtQuery() *dns.Msg { return new(dns.Msg).SetQuestion("example.com.", dns.TypeTXT) }

func TestPool_PrefersFirst(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		a, b := &fake{name: "a", delay: 10 * time.Millisecond}, &fake{name: "b", delay: time.Millisecond}
		p := NewPool([]Exchanger{a, b})

		resp, err := p.Exchange(t.Context(), txtQuery())
		if err != nil || answeredBy(t, resp) != "a" {
			t.Fatalf("Exchange = %v, %v; want a's answer", resp, err)
		}
		if b.calls.Load() != 0 {
			t.Error("b was asked though a answered within the hedge delay")
		}
	})
}

func TestPool_HedgesSlowUpstream(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		a, b := &fake{name: "a", delay: time.Hour}, &fake{name: "b", delay: 50 * time.Millisecond}
		p := NewPool([]Exchanger{a, b})

		start := time.Now()
		resp, err := p.Exchange(t.Context(), txtQuery())
		if err != nil || answeredBy(t, resp) != "b" {
			t.Fatalf("Exchange = %v, %v; want b's answer", resp, err)
		}
		if got, want := time.Since(start), DefaultHedgeDelay+50*time.Millisecond; got != want {
			t.Errorf("answered after %v, want the hedge delay plus b's %v", got, want)
		}

		// a was cancelled when b answered, which doesn't count against it.
		if h := p.Health(); !h[0].Healthy || h[0].Failures != 0 {
			t.Errorf("a's health after being outpaced = %+v", h[0])
		}
	})
}

func TestPool_FailsOverImmediately(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		a, b := &fake{name: "a"}, &fake{name: "b", delay: time.Millisecond}
		a.fail.Store(true)
		p := NewPool([]Exchanger{a, b})

		start := time.Now()
		resp, err := p.Exchange(t.Context(), txtQuery())
		if err != nil || answeredBy(t, resp) != "b" {
			t.Fatalf("Exchange = %v, %v", resp, err)
		}
		if time.Since(start) >= DefaultHedgeDelay {
			t.Error("a failure waited for the hedge delay before asking b")
		}
	})
}

func TestPool_BacksOffUnhealthyUpstream(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		a, b := &fake{name: "a"}, &fake{name: "b", delay: time.Millisecond}
		a.fail.Store(true)
		p := NewPool([]Exchanger{a, b})

		var failed time.Time // when a last failed: it fails at once
		for range unhealthyAfter {
			failed = time.Now()
			if _, err := p.Exchange(t.Context(), txtQuery()); err != nil {
				t.Fatal(err)
			}
		}
		h := p.Health()
		if h[0].Healthy || h[0].RetryAt != failed.Add(minBackoff) || !h[1].Healthy {
			t.Fatalf("health after %d failures = %+v", unhealthyAfter, h)
		}

		// While unhealthy, a is asked last: b answers without waiting.
		calls := a.calls.Load()
		if resp, _ := p.Exchange(t.Context(), txtQuery()); answeredBy(t, resp) != "b" || a.calls.Load() != calls {
			t.Error("unhealthy upstream was still asked first")
		}

		// After the backoff, a is tried first again; another failure
		// doubles its backoff.
		time.Sleep(minBackoff)
		failed = time.Now()
		p.Exchange(t.Context(), txtQuery())
		if h := p.Health(); h[0].RetryAt != failed.Add(2*minBackoff) {
			t.Errorf("backoff after another failure = %v, want %v", h[0].RetryAt.Sub(failed), 2*minBackoff)
		}

		// Once it answers again, it's healthy and preferred.
		time.Sleep(2 * minBackoff)
		a.fail.Store(false)
		if resp, _ := p.Exchange(t.Context(), txtQuery()); answeredBy(t, resp) != "a" {
			t.Error("recovered upstream wasn't preferred")
		}
		if h := p.Health(); !h[0].Healthy || h[0].Failures != 0 {
			t.Errorf("recovered health = %+v", h[0])
		}
	})
}

func TestPool_BackoffIsBounded(t *testing.T) {
	m := &member{}
	for range 64 {
		m.record(errors.New("down"), false)
	}
	if d := time.Until(m.until); d > maxBackoff || d < maxBackoff-time.Second {
		t.Errorf("backoff after many failures = %v, want %v", d, maxBackoff)
	}
}

func TestPool_AllFail(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		a, b := &fake{name: "a"}, &fake{name: "b"}
		a.fail.Store(true)
		b.fail.Store(true)

		_, err := NewPool([]Exchanger{a, b}).Exchange(t.Context(), txtQuery())
		if !errors.Is(err, ErrAllFailed) || err.Error() == "" {
			t.Fatalf("Exchange = %v, want ErrAllFailed", err)
		}
		for _, name := range []string{"a is down", "b is down"} {
			if !strings.Contains(err.Error(), name) {
				t.Errorf("error %q doesn't include %q", err, name)
			}
		}
	})
}

func TestPool_RespectsDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		a, b := &fake{name: "a", delay: time.Hour}, &fake{name: "b", delay: time.Hour}
		p := NewPool([]Exchanger{a, b})

		ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
		defer cancel()
		start := time.Now()
		if _, err := p.Exchange(ctx, txtQuery()); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("Exchange = %v, want the deadline", err)
		}
		if time.Since(start) != 2*time.Second {
			t.Errorf("gave up after %v", time.Since(start))
		}
		// Every exchange has finished: synctest would report leaks.
	})
}
