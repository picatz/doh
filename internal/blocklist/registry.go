package blocklist

import (
	"cmp"
	"context"
	"log/slog"
	"maps"
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

	mu      sync.Mutex
	entries map[Source]*registryEntry
}

type registryEntry struct {
	list    *List
	loaded  time.Time
	err     error
	loading chan struct{} // closed when the current load finishes; nil if idle
}

// ListStatus describes a list in a [Registry].
type ListStatus struct {
	Name     string    `json:"name"`
	Location string    `json:"location"`
	Rules    int       `json:"rules"`
	Loaded   time.Time `json:"loaded,omitzero"`
	Loading  bool      `json:"loading,omitempty"`
	Error    string    `json:"error,omitempty"`
}

// NewRegistry returns a registry that loads lists with loader.
func NewRegistry(loader *Loader, logger *slog.Logger) *Registry {
	ctx, cancel := context.WithCancel(context.Background())
	return &Registry{
		loader:  loader,
		logger:  cmp.Or(logger, slog.New(slog.DiscardHandler)),
		ctx:     ctx,
		cancel:  cancel,
		entries: make(map[Source]*registryEntry),
	}
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

	r.wg.Go(func() {
		defer close(done)

		list, err := r.loader.LoadSource(r.ctx, src)

		r.mu.Lock()
		defer r.mu.Unlock()
		e.loading = nil
		if err != nil {
			e.err = err
			if r.ctx.Err() == nil {
				r.logger.Warn("blocklist: loading failed", slog.String("source", src.Name), slog.Any("error", err))
			}
			return
		}
		e.list, e.loaded, e.err = list, time.Now(), nil
		r.logger.Info("blocklist: loaded", slog.String("source", src.Name), slog.Int("rules", list.Len()))
	})
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
		st := ListStatus{Name: src.Name, Location: publicName(src.Location), Rules: e.list.Len(), Loaded: e.loaded, Loading: e.loading != nil}
		if e.err != nil {
			st.Error = e.err.Error()
		}
		status = append(status, st)
	}
	return status
}

// Refresh reloads every list each interval until ctx is done, keeping a
// list's current rules if reloading it fails.
func (r *Registry) Refresh(ctx context.Context, interval time.Duration) error {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			_ = r.Reload(ctx)
		}
	}
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
