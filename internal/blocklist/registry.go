package blocklist

import (
	"cmp"
	"context"
	"log/slog"
	"maps"
	"math/rand/v2"
	"slices"
	"sync"
	"time"
)

// Registry loads each source once, however many profiles use it, and keeps
// the lists fresh, so memory grows with the number of distinct lists rather
// than with profiles. It's safe for concurrent use.
type Registry struct {
	loader *Loader
	logger *slog.Logger

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// wake is signaled when a load finishes, so Refresh reschedules.
	wake chan struct{}

	mu       sync.Mutex
	entries  map[Source]*registryEntry
	onFail   func(Source, error)
	schedule *RefreshSchedule // set while Refresh runs
}

type registryEntry struct {
	list    *List
	version *Version  // of list, to skip reloading it unchanged
	loaded  time.Time // when list was last loaded or found unchanged
	err     error
	loading chan struct{} // closed when the current load finishes; nil if idle
	next    time.Time     // when Refresh next reloads it; zero if unscheduled
}

// ListStatus describes a list in a [Registry].
type ListStatus struct {
	Name     string `json:"name"`
	Location string `json:"location"`
	Rules    int    `json:"rules"`

	// Category is the preset's category, if the list is a preset's.
	Category string `json:"category,omitempty"`

	// Loaded is when the list was last loaded, or checked and found
	// unchanged.
	Loaded time.Time `json:"loaded,omitzero"`

	// Next is when the list will next be checked for changes.
	Next time.Time `json:"next,omitzero"`

	Loading bool   `json:"loading,omitempty"`
	Error   string `json:"error,omitempty"`
}

// RefreshSchedule says how often a [Registry] checks each list for
// changes. Security lists' publishers update them several times a day,
// so they're checked more often than others by default; conditional
// requests make checking an unchanged list cheap.
type RefreshSchedule struct {
	// Every is how often lists are checked, unless their category has its
	// own interval. If zero, [DefaultRefresh] is used.
	Every time.Duration

	// Categories are intervals for lists in a preset category, such as
	// [CategorySecurity], overriding Every.
	Categories map[string]time.Duration

	// Jitter spreads checks by up to this fraction of each interval,
	// either way, so many servers (and lists) don't all ask at once. It
	// must be from 0 to 0.5.
	Jitter float64
}

// Default refresh intervals.
const (
	// DefaultRefresh is how often lists are checked by default.
	DefaultRefresh = 24 * time.Hour

	// DefaultSecurityRefresh is how often security lists are checked by
	// default: their sources publish several times a day.
	DefaultSecurityRefresh = 2 * time.Hour

	// DefaultRefreshJitter is the default [RefreshSchedule.Jitter].
	DefaultRefreshJitter = 0.1
)

// DefaultRefreshSchedule returns the default schedule: security lists
// every two hours, others daily, with 10% jitter.
func DefaultRefreshSchedule() RefreshSchedule {
	return RefreshSchedule{
		Every:      DefaultRefresh,
		Categories: map[string]time.Duration{CategorySecurity: DefaultSecurityRefresh},
		Jitter:     DefaultRefreshJitter,
	}
}

// Interval returns how often src is checked, before jitter.
func (s RefreshSchedule) Interval(src Source) time.Duration {
	if d, ok := s.Categories[Category(src)]; ok && d > 0 {
		return d
	}
	return cmp.Or(s.Every, DefaultRefresh)
}

// next returns when to check src next, after now.
func (s RefreshSchedule) next(src Source, now time.Time) time.Time {
	d := s.Interval(src)
	if j := min(max(s.Jitter, 0), 0.5); j > 0 {
		d += time.Duration((rand.Float64()*2 - 1) * j * float64(d))
	}
	return now.Add(d)
}

// NewRegistry returns a registry that loads lists with loader.
func NewRegistry(loader *Loader, logger *slog.Logger) *Registry {
	ctx, cancel := context.WithCancel(context.Background())
	return &Registry{
		loader:  loader,
		logger:  cmp.Or(logger, slog.New(slog.DiscardHandler)),
		ctx:     ctx,
		cancel:  cancel,
		wake:    make(chan struct{}, 1),
		entries: make(map[Source]*registryEntry),
	}
}

// OnFailure sets f to be called, from the goroutine that loaded it, each
// time a list fails to load, other than because the registry is closing.
// f must not block for long or call back into the registry.
func (r *Registry) OnFailure(f func(src Source, err error)) {
	r.mu.Lock()
	r.onFail = f
	r.mu.Unlock()
}

// Sync makes sources the registry's lists: it starts loading any that
// are new in the background, and forgets any no longer used. Lists are
// empty until loaded; [Registry.Wait] waits for them.
func (r *Registry) Sync(sources []Source) {
	r.mu.Lock()
	defer r.mu.Unlock()

	want := make(map[Source]bool, len(sources))
	for _, src := range sources {
		want[src] = true
		if _, ok := r.entries[src]; !ok {
			e := &registryEntry{}
			r.entries[src] = e
			r.startLoad(src, e)
		}
	}

	for src := range r.entries {
		if !want[src] {
			delete(r.entries, src)
		}
	}
}

// startLoad loads src into e in the background. r.mu must be held.
func (r *Registry) startLoad(src Source, e *registryEntry) {
	if e.loading != nil {
		return
	}
	done := make(chan struct{})
	e.loading = done

	have := e.version
	if e.list == nil {
		have = nil // nothing to keep, so load whatever there is
	}

	r.wg.Go(func() {
		defer close(done)
		defer r.poke()

		list, version, err := r.loader.reloadSource(r.ctx, src, have)

		r.mu.Lock()
		defer r.mu.Unlock()
		e.loading = nil
		if r.schedule != nil {
			e.next = r.schedule.next(src, time.Now())
		}
		if err != nil {
			e.err = err
			if r.ctx.Err() == nil {
				r.logger.Warn("blocklist: loading failed", slog.String("source", src.Name), slog.Any("error", err))
				if r.onFail != nil {
					r.onFail(src, err)
				}
			}
			return
		}
		e.loaded, e.err, e.version = time.Now(), nil, version
		if list == nil {
			r.logger.Debug("blocklist: unchanged", slog.String("source", src.Name))
			return
		}
		e.list = list
		r.logger.Info("blocklist: loaded", slog.String("source", src.Name), slog.Int("rules", list.Len()))
	})
}

// poke wakes Refresh, if it's running, to reschedule.
func (r *Registry) poke() {
	select {
	case r.wake <- struct{}{}:
	default:
	}
}

// Wait waits until sources have finished loading, or ctx is done,
// returning an error only if ctx ends first.
func (r *Registry) Wait(ctx context.Context, sources ...Source) error {
	for _, src := range sources {
		r.mu.Lock()
		var loading chan struct{}
		if e, ok := r.entries[src]; ok {
			loading = e.loading
		}
		r.mu.Unlock()

		if loading == nil {
			continue
		}
		select {
		case <-loading:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

// List returns the loaded list for src, or nil if it isn't loaded.
func (r *Registry) List(src Source) *List {
	r.mu.Lock()
	defer r.mu.Unlock()
	if e, ok := r.entries[src]; ok {
		return e.list
	}
	return nil
}

// Err returns the error from the last attempt to load src, if it failed.
func (r *Registry) Err(src Source) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if e, ok := r.entries[src]; ok {
		return e.err
	}
	return nil
}

// Status describes every list, sorted by name.
func (r *Registry) Status() []ListStatus {
	r.mu.Lock()
	defer r.mu.Unlock()

	status := make([]ListStatus, 0, len(r.entries))
	for _, src := range slices.SortedFunc(maps.Keys(r.entries), func(a, b Source) int {
		return cmp.Or(cmp.Compare(a.Name, b.Name), cmp.Compare(a.Location, b.Location))
	}) {
		e := r.entries[src]
		st := ListStatus{
			Name: src.Name, Location: publicName(src.Location), Rules: e.list.Len(), Category: Category(src),
			Loaded: e.loaded, Next: e.next, Loading: e.loading != nil,
		}
		if e.err != nil {
			st.Error = e.err.Error()
		}
		status = append(status, st)
	}
	return status
}

// Refresh checks each list for changes on schedule until ctx is done,
// keeping a list's current rules if reloading it fails. Each list is
// checked an interval (with jitter) after its last load finished, whether
// it succeeded or not, so lists added later, and lists that fail, are
// checked on their own cadence. A list that hasn't changed since it was
// loaded costs one conditional request, or a stat for a file, and isn't
// parsed again.
//
// Only one Refresh should run at a time.
func (r *Registry) Refresh(ctx context.Context, schedule RefreshSchedule) error {
	r.mu.Lock()
	r.schedule = &schedule
	now := time.Now()
	for src, e := range r.entries {
		if e.loading == nil {
			e.next = schedule.next(src, now)
		}
	}
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		r.schedule = nil
		r.mu.Unlock()
	}()

	timer := time.NewTimer(time.Hour)
	defer timer.Stop()
	for {
		timer.Reset(r.refreshDue(schedule))
		select {
		case <-ctx.Done():
			return nil
		case <-timer.C:
		case <-r.wake:
		}
	}
}

// refreshDue starts loading every idle list that's due, schedules lists
// added since the last call, and returns how long until the next is due.
func (r *Registry) refreshDue(schedule RefreshSchedule) time.Duration {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	wait := schedule.Interval(Source{})
	for src, e := range r.entries {
		switch {
		case e.loading != nil:
			continue // rescheduled when it finishes
		case e.next.IsZero():
			e.next = schedule.next(src, now)
		case !now.Before(e.next):
			r.startLoad(src, e)
			continue
		}
		wait = min(wait, e.next.Sub(now))
	}
	return max(wait, time.Second)
}

// Reload reloads every list now and waits for them, or for ctx to be
// done. Lists that fail to reload keep their current rules.
func (r *Registry) Reload(ctx context.Context) error {
	r.mu.Lock()
	sources := make([]Source, 0, len(r.entries))
	for src, e := range r.entries {
		r.startLoad(src, e)
		sources = append(sources, src)
	}
	r.mu.Unlock()
	return r.Wait(ctx, sources...)
}

// Close stops any loads in progress and waits for them to finish.
func (r *Registry) Close() {
	r.cancel()
	r.wg.Wait()
}
