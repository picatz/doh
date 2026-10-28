package serve

import (
	"context"
	"encoding/json"
	"errors"
	"expvar"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/pprof"
	"net/netip"
	"os"
	"runtime/debug"
	"runtime/metrics"
	"runtime/trace"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/picatz/doh/internal/upstream"
)

// Admin endpoint paths, served only on the admin listener.
const (
	MetricsPath        = "/metrics"
	VarsPath           = "/debug/vars"
	PprofPath          = "/debug/pprof/"
	FlightRecorderPath = "/debug/flightrecorder"
)

// slowQuerySnapshotInterval is the minimum time between flight recorder
// snapshots saved for slow queries, so a burst of slow queries doesn't
// flood the trace directory.
const slowQuerySnapshotInterval = time.Minute

// telemetry holds a server's counters. They're kept per server, rather
// than published globally with [expvar.Publish], so multiple servers (such
// as in tests) don't collide, and so the admin listener exposes only what
// the server chooses.
type telemetry struct {
	queries     expvar.Map // by transport: https, udp, tcp
	responses   expvar.Map // by response code, such as NOERROR
	upstreams   expvar.Map // by upstream: *upstreamMetrics
	slowQueries expvar.Int

	recorder *flightRecorder
}

// upstreamMetrics are the counters for one upstream.
type upstreamMetrics struct {
	queries expvar.Int
	errors  expvar.Int
	seconds expvar.Float // total time spent waiting for responses
}

// String implements [expvar.Var], encoding the counters as a JSON object.
func (m *upstreamMetrics) String() string {
	return fmt.Sprintf(`{"queries": %s, "errors": %s, "seconds": %s}`, m.queries.String(), m.errors.String(), m.seconds.String())
}

func newTelemetry() *telemetry {
	t := &telemetry{}
	t.queries.Init()
	t.responses.Init()
	t.upstreams.Init()
	return t
}

// observe records a query answered over transport in d, with resp or err.
func (t *telemetry) observe(ctx context.Context, transport string, d time.Duration, resp *dns.Msg, err error) {
	t.queries.Add(transport, 1)

	rcode := dns.RcodeServerFailure
	if err == nil {
		rcode = resp.Rcode
	}
	t.responses.Add(dns.RcodeToString[rcode], 1)

	if t.recorder != nil && t.recorder.slow > 0 && d >= t.recorder.slow {
		t.slowQueries.Add(1)
		t.recorder.snapshotSlow(ctx, d)
	}
}

// instrument wraps e to record its queries under name.
func (t *telemetry) instrument(name string, e upstream.Exchanger) upstream.Exchanger {
	m := &upstreamMetrics{}
	t.upstreams.Set(name, m)
	return &instrumented{Exchanger: e, metrics: m}
}

// instrumented is an [upstream.Exchanger] that records its queries.
type instrumented struct {
	upstream.Exchanger
	metrics *upstreamMetrics
}

func (i *instrumented) Exchange(ctx context.Context, query *dns.Msg) (*dns.Msg, error) {
	start := time.Now()
	resp, err := i.Exchanger.Exchange(ctx, query)

	i.metrics.queries.Add(1)
	i.metrics.seconds.Add(time.Since(start).Seconds())
	if err != nil {
		i.metrics.errors.Add(1)
	}

	return resp, err
}

// adminHandler returns the handler for the admin listener.
func (s *Server) adminHandler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET "+HealthPath, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = io.WriteString(w, "ok\n")
	})

	mux.HandleFunc("GET "+MetricsPath, s.serveMetrics)
	mux.HandleFunc("GET "+VarsPath, s.serveVars)

	// Mount pprof explicitly: importing net/http/pprof also registers its
	// handlers on http.DefaultServeMux, which this server never serves.
	mux.HandleFunc("GET "+PprofPath, pprof.Index)
	mux.HandleFunc("GET "+PprofPath+"cmdline", pprof.Cmdline)
	mux.HandleFunc("GET "+PprofPath+"profile", pprof.Profile)
	mux.HandleFunc("GET "+PprofPath+"symbol", pprof.Symbol)
	mux.HandleFunc("GET "+PprofPath+"trace", pprof.Trace)

	mux.HandleFunc("GET "+FlightRecorderPath, func(w http.ResponseWriter, r *http.Request) {
		if s.telemetry.recorder == nil {
			http.Error(w, "flight recorder disabled; enable it with --flight-recorder", http.StatusNotFound)
			return
		}

		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", `attachment; filename="`+traceFileName(time.Now())+`"`)
		if _, err := s.telemetry.recorder.fr.WriteTo(w); err != nil {
			s.logger.WarnContext(r.Context(), "writing flight recorder snapshot", slog.Any("error", err))
		}
	})

	return mux
}

// serveVars writes the server's counters, runtime metrics, and build
// information as JSON, in the style of expvar.
//
// Unlike [expvar.Handler], it omits the process command line, and only
// includes variables this server owns.
func (s *Server) serveVars(w http.ResponseWriter, r *http.Request) {
	runtimeJSON, err := json.Marshal(runtimeMetrics())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	buildJSON, err := json.Marshal(buildInfo())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	t := s.telemetry
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	fmt.Fprintf(w, `{"doh": {"queries": %s, "responses": %s, "upstreams": %s, "slow_queries": %s}, "runtime": %s, "build": %s}`+"\n",
		t.queries.String(), t.responses.String(), t.upstreams.String(), t.slowQueries.String(), runtimeJSON, buildJSON)
}

// serveMetrics writes the server's counters in the Prometheus text
// exposition format, so they can be scraped without extra dependencies.
func (s *Server) serveMetrics(w http.ResponseWriter, r *http.Request) {
	t := s.telemetry
	var b strings.Builder

	counter := func(name, help string, m *expvar.Map, label string) {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s counter\n", name, help, name)
		m.Do(func(kv expvar.KeyValue) {
			fmt.Fprintf(&b, "%s{%s=%s} %s\n", name, label, promLabel(kv.Key), kv.Value.String())
		})
	}

	counter("doh_queries_total", "Queries received, by transport.", &t.queries, "transport")
	counter("doh_responses_total", "Responses sent, by DNS response code.", &t.responses, "rcode")

	upstreamCounter := func(name, help string, value func(*upstreamMetrics) string) {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s counter\n", name, help, name)
		t.upstreams.Do(func(kv expvar.KeyValue) {
			fmt.Fprintf(&b, "%s{upstream=%s} %s\n", name, promLabel(kv.Key), value(kv.Value.(*upstreamMetrics)))
		})
	}

	upstreamCounter("doh_upstream_queries_total", "Queries sent to each upstream.", func(m *upstreamMetrics) string { return m.queries.String() })
	upstreamCounter("doh_upstream_errors_total", "Queries to each upstream that failed.", func(m *upstreamMetrics) string { return m.errors.String() })
	upstreamCounter("doh_upstream_seconds_total", "Time spent waiting for each upstream.", func(m *upstreamMetrics) string { return m.seconds.String() })

	fmt.Fprintf(&b, "# HELP doh_slow_queries_total Queries slower than the slow query threshold.\n# TYPE doh_slow_queries_total counter\ndoh_slow_queries_total %s\n", t.slowQueries.String())

	for _, sample := range runtimeMetrics() {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s gauge\n%s %v\n", sample.prom, sample.help, sample.prom, sample.prom, sample.Value)
	}

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	_, _ = io.WriteString(w, b.String())
}

// promLabel quotes a Prometheus label value, escaping backslashes, quotes,
// and newlines.
func promLabel(v string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(v) + `"`
}

// runtimeSample is a runtime metric exposed by the admin listener.
type runtimeSample struct {
	Name  string `json:"name"`
	Value any    `json:"value"`

	prom, help string
}

// exposedRuntimeMetrics are the runtime/metrics exposed by the admin
// listener, with their Prometheus names. Metrics this Go version doesn't
// support are skipped.
var exposedRuntimeMetrics = []struct{ name, prom, help string }{
	{"/sched/goroutines:goroutines", "go_goroutines", "Live goroutines."},
	{"/sched/gomaxprocs:threads", "go_gomaxprocs", "GOMAXPROCS, the number of threads running Go code at once."},
	{"/memory/classes/heap/objects:bytes", "go_heap_objects_bytes", "Memory occupied by live and unswept heap objects."},
	{"/memory/classes/total:bytes", "go_memory_total_bytes", "All memory mapped by the Go runtime."},
	{"/gc/cycles/total:gc-cycles", "go_gc_cycles_total", "Completed GC cycles."},
	{"/gc/heap/goal:bytes", "go_gc_heap_goal_bytes", "Heap size target for the end of the GC cycle."},
}

// runtimeMetrics reads the exposed runtime metrics.
func runtimeMetrics() []runtimeSample {
	samples := make([]metrics.Sample, len(exposedRuntimeMetrics))
	for i, m := range exposedRuntimeMetrics {
		samples[i].Name = m.name
	}
	metrics.Read(samples)

	var out []runtimeSample
	for i, sample := range samples {
		var value any
		switch sample.Value.Kind() {
		case metrics.KindUint64:
			value = sample.Value.Uint64()
		case metrics.KindFloat64:
			value = sample.Value.Float64()
		default:
			continue // unsupported by this Go version, or not a scalar
		}

		m := exposedRuntimeMetrics[i]
		out = append(out, runtimeSample{Name: m.name, Value: value, prom: m.prom, help: m.help})
	}

	return out
}

// buildInfo describes the running binary.
func buildInfo() map[string]string {
	info := map[string]string{}

	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return info
	}

	info["go"] = bi.GoVersion
	info["version"] = bi.Main.Version
	for _, s := range bi.Settings {
		if s.Key == "vcs.revision" || s.Key == "vcs.time" || s.Key == "vcs.modified" {
			info[s.Key] = s.Value
		}
	}

	return info
}

// ServeAdmin serves the admin endpoints on ln until ctx is done: metrics,
// expvar-style variables, pprof profiles, and flight recorder snapshots.
//
// These expose details about the process, so ln should only be reachable
// by operators, such as on a loopback address.
func (s *Server) ServeAdmin(ctx context.Context, ln net.Listener) error {
	if ap, err := netip.ParseAddrPort(ln.Addr().String()); err == nil && !ap.Addr().IsLoopback() {
		s.logger.Warn("admin endpoints expose profiles and process details; restrict access to the admin listener",
			slog.String("addr", ln.Addr().String()))
	}

	if s.telemetry.recorder != nil {
		if err := s.telemetry.recorder.start(); err != nil {
			ln.Close()
			return err
		}
		defer s.telemetry.recorder.stop()
	}

	srv := s.httpServer(s.adminHandler())
	// Profiles and traces take a while to collect, so don't cut them off.
	srv.WriteTimeout = 0

	s.logger.Info("serving admin",
		slog.String("metrics", "http://"+ln.Addr().String()+MetricsPath),
		slog.String("vars", "http://"+ln.Addr().String()+VarsPath),
		slog.String("pprof", "http://"+ln.Addr().String()+PprofPath),
		slog.Bool("flight_recorder", s.telemetry.recorder != nil),
	)

	errc := make(chan error, 1)
	go func() {
		if err := srv.Serve(ln); !errors.Is(err, http.ErrServerClosed) {
			errc <- err
		}
	}()

	var err error
	select {
	case <-ctx.Done():
	case err = <-errc:
	}

	s.logger.Info("shutting down admin", slog.Any("cause", context.Cause(ctx)))

	shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownTimeout)
	defer cancel()

	return errors.Join(err, srv.Shutdown(shutdownCtx))
}

// flightRecorder keeps a moving window of execution trace data using
// [trace.FlightRecorder], snapshotting it on demand or after slow queries.
type flightRecorder struct {
	fr     *trace.FlightRecorder
	logger *slog.Logger

	// slow is the latency at which a query triggers a snapshot into dir.
	slow time.Duration
	dir  *os.Root

	mu   sync.Mutex
	last time.Time // when the last slow query snapshot was taken
}

func newFlightRecorder(config AdminConfig, logger *slog.Logger) (*flightRecorder, error) {
	r := &flightRecorder{
		fr: trace.NewFlightRecorder(trace.FlightRecorderConfig{
			MinAge:   10 * time.Second,
			MaxBytes: 16 << 20,
		}),
		logger: logger,
		slow:   time.Duration(config.SlowQuery),
	}

	if config.TraceDir != "" {
		if err := os.MkdirAll(config.TraceDir, 0o750); err != nil {
			return nil, fmt.Errorf("serve: trace dir: %w", err)
		}

		// Confine snapshot writes to the trace directory.
		root, err := os.OpenRoot(config.TraceDir)
		if err != nil {
			return nil, fmt.Errorf("serve: trace dir: %w", err)
		}
		r.dir = root
	}

	return r, nil
}

func (r *flightRecorder) start() error {
	if err := r.fr.Start(); err != nil {
		return fmt.Errorf("serve: starting flight recorder: %w", err)
	}
	return nil
}

func (r *flightRecorder) stop() {
	r.fr.Stop()
	if r.dir != nil {
		r.dir.Close()
	}
}

// snapshotSlow saves a snapshot for a query that took d, unless one was
// saved recently or there's no trace directory.
func (r *flightRecorder) snapshotSlow(ctx context.Context, d time.Duration) {
	if r.dir == nil || !r.fr.Enabled() {
		return
	}

	r.mu.Lock()
	now := time.Now()
	if now.Sub(r.last) < slowQuerySnapshotInterval {
		r.mu.Unlock()
		return
	}
	r.last = now
	r.mu.Unlock()

	// Write in the background, so the slow query isn't slowed further.
	go func() {
		name := traceFileName(now)

		f, err := r.dir.Create(name)
		if err != nil {
			r.logger.Warn("saving flight recorder snapshot", slog.Any("error", err))
			return
		}
		defer f.Close()

		if _, err := r.fr.WriteTo(f); err != nil {
			r.logger.Warn("saving flight recorder snapshot", slog.Any("error", err))
			return
		}

		r.logger.InfoContext(ctx, "saved flight recorder snapshot for slow query",
			slog.Duration("duration", d),
			slog.String("file", r.dir.Name()+string(os.PathSeparator)+name),
		)
	}()
}

// traceFileName names a flight recorder snapshot taken at t.
func traceFileName(t time.Time) string {
	return "doh-" + t.UTC().Format("20060102T150405.000Z") + ".trace"
}
