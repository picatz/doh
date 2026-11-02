// Package ratelimit limits how often each key, such as a client address,
// may do something, with a token bucket per key.
package ratelimit

import (
	"sync"
	"time"
)

// Limiter allows each key up to Burst events at once, refilled at Rate
// per second. It's safe for concurrent use.
//
// It tracks at most MaxKeys keys, forgetting full buckets first; when every
// tracked bucket is in use, new keys are refused rather than tracked, so a
// flood of keys can't exhaust memory.
type Limiter struct {
	// Rate is the number of events per second each key regains.
	Rate float64

	// Burst is the most events a key may have in reserve.
	Burst int

	// MaxKeys bounds the keys tracked. If zero, 10,000 are.
	MaxKeys int

	mu      sync.Mutex
	buckets map[string]*bucket
}

type bucket struct {
	tokens float64
	last   time.Time
}

// Allow reports whether key may do something now, using up one event if
// so.
func (l *Limiter) Allow(key string) bool {
	now := time.Now()

	l.mu.Lock()
	defer l.mu.Unlock()

	if l.buckets == nil {
		l.buckets = make(map[string]*bucket)
	}

	b, ok := l.buckets[key]
	if !ok {
		if len(l.buckets) >= l.maxKeys() && !l.forgetFull(now) {
			return false
		}
		b = &bucket{tokens: float64(l.Burst), last: now}
		l.buckets[key] = b
	}

	b.tokens = min(float64(l.Burst), b.tokens+now.Sub(b.last).Seconds()*l.Rate)
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// Limited reports whether key has used up its events, without using one.
// With Allow, it limits only some events, such as failures: check
// Limited first, and call Allow when one happens.
func (l *Limiter) Limited(key string) bool {
	now := time.Now()

	l.mu.Lock()
	defer l.mu.Unlock()

	b, ok := l.buckets[key]
	return ok && b.tokens+now.Sub(b.last).Seconds()*l.Rate < 1
}

func (l *Limiter) maxKeys() int {
	if l.MaxKeys > 0 {
		return l.MaxKeys
	}
	return 10_000
}

// forgetFull forgets buckets that have refilled completely, since they
// behave like new ones, reporting whether it forgot any. l.mu must be held.
func (l *Limiter) forgetFull(now time.Time) bool {
	forgot := false
	for k, b := range l.buckets {
		if b.tokens+now.Sub(b.last).Seconds()*l.Rate >= float64(l.Burst) {
			delete(l.buckets, k)
			forgot = true
		}
	}
	return forgot
}
