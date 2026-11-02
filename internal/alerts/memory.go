package alerts

import (
	"context"
	"errors"
	"maps"
	"sync"
	"time"
)

// Memory is what an [Engine] remembers between alerts: the devices each
// scope has seen, so a restart doesn't report them as new, and the alerts
// it sent recently, so a restart doesn't repeat them within
// [CoalesceWindow]. [NewMemory] keeps it in memory; the server's state
// database keeps it on disk, and a shared one lets replicas agree.
// Implementations must be safe for concurrent use.
type Memory interface {
	// SeeDevice records that scope saw device at now, reporting whether
	// device is new to scope, and since when scope has been seeing
	// devices, which the first call for a scope sets to now. It keeps at
	// most [MaxSeenDevices] per scope, forgetting the least recently seen.
	SeeDevice(ctx context.Context, scope, device string, now time.Time) (isNew bool, since time.Time, err error)

	// Claim records that an alert of kind with key is sent to scope at
	// now, unless one was sent within window, when it reports false. Of
	// two concurrent claims, at most one succeeds. Beyond [MaxClaims]
	// remembered, it fails with [ErrMemoryFull].
	Claim(ctx context.Context, scope, kind, key string, now time.Time, window time.Duration) (bool, error)

	// Forget removes everything remembered about scope.
	Forget(ctx context.Context, scope string) error
}

// DeviceImporter is implemented by a [Memory] that can take the devices an
// older alerts file kept, so upgrading doesn't report them as new.
type DeviceImporter interface {
	// ImportDevices adds devices scope saw, when each was last seen, and
	// since when scope has seen devices, keeping what's newer of what it
	// already has.
	ImportDevices(ctx context.Context, scope string, since time.Time, seen map[string]time.Time) error
}

// MaxClaims bounds the alerts a [Memory] remembers as sent. Beyond it,
// new alerts are counted toward their burst's summary instead of sent.
const MaxClaims = 10_000

// ErrMemoryFull reports a [Memory] remembering [MaxClaims] alerts sent
// within their windows.
var ErrMemoryFull = errors.New("alerts: too many recent alerts remembered")

// memory is a [Memory] kept in memory.
type memory struct {
	mu     sync.Mutex
	scopes map[string]*memoryScope
	sent   map[coalesceKey]time.Time
}

type memoryScope struct {
	since   time.Time
	devices map[string]time.Time
}

// NewMemory returns a [Memory] kept in memory, so a restart forgets it.
func NewMemory() Memory {
	return &memory{scopes: make(map[string]*memoryScope), sent: make(map[coalesceKey]time.Time)}
}

func (m *memory) scope(scope string, now time.Time) *memoryScope {
	sc := m.scopes[scope]
	if sc == nil {
		sc = &memoryScope{since: now.UTC(), devices: make(map[string]time.Time)}
		m.scopes[scope] = sc
	}
	return sc
}

func (m *memory) SeeDevice(_ context.Context, scope, device string, now time.Time) (bool, time.Time, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	sc := m.scope(scope, now)
	_, known := sc.devices[device]
	if !known && len(sc.devices) >= MaxSeenDevices {
		oldest, _ := minByValue(sc.devices)
		delete(sc.devices, oldest)
	}
	sc.devices[device] = now.UTC()
	return !known, sc.since, nil
}

func (m *memory) ImportDevices(_ context.Context, scope string, since time.Time, seen map[string]time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	sc := m.scope(scope, since)
	if since.Before(sc.since) {
		sc.since = since.UTC()
	}
	for d, t := range seen {
		if cur, ok := sc.devices[d]; !ok || t.After(cur) {
			sc.devices[d] = t.UTC()
		}
	}
	for len(sc.devices) > MaxSeenDevices {
		oldest, _ := minByValue(sc.devices)
		delete(sc.devices, oldest)
	}
	return nil
}

func (m *memory) Claim(_ context.Context, scope, kind, key string, now time.Time, window time.Duration) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	ck := coalesceKey{scope, Kind(kind), key}
	if t, ok := m.sent[ck]; ok && now.Sub(t) < window {
		return false, nil
	}
	if len(m.sent) >= MaxClaims {
		maps.DeleteFunc(m.sent, func(_ coalesceKey, t time.Time) bool { return now.Sub(t) >= window })
	}
	if len(m.sent) >= MaxClaims {
		return false, ErrMemoryFull
	}
	m.sent[ck] = now
	return true, nil
}

func (m *memory) Forget(_ context.Context, scope string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.scopes, scope)
	maps.DeleteFunc(m.sent, func(k coalesceKey, _ time.Time) bool { return k.scope == scope })
	return nil
}
