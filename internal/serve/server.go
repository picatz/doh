package serve

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"github.com/picatz/doh/internal/serviceaccount"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/miekg/dns"
	"github.com/picatz/doh/internal/blocklist"
	"github.com/picatz/doh/internal/cache"
	"github.com/picatz/doh/internal/federation"
	"github.com/picatz/doh/internal/filter"
	"github.com/picatz/doh/internal/hostnames"
	"github.com/picatz/doh/internal/policy"
	"github.com/picatz/doh/internal/querylog"
	"github.com/picatz/doh/internal/ratelimit"
	"github.com/picatz/doh/internal/rdap"
	"github.com/picatz/doh/internal/signin"
	"github.com/picatz/doh/internal/upstream"
	"github.com/picatz/doh/pkg/doh"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/sync/errgroup"
)

// HealthPath is the liveness endpoint, which always responds 200 OK.
const HealthPath = "/healthz"

// shutdownTimeout bounds how long in-flight requests may take to finish
// once the server is asked to stop.
const shutdownTimeout = 10 * time.Second

// Server is a DNS-over-HTTPS server that forwards queries to upstream
// resolvers, applying a policy of profiles to its clients.
type Server struct {
	config  Config
	logger  *slog.Logger
	started time.Time

	// exchanger forwards queries to the configured upstreams, and
	// forwardZones to the upstreams of particular domains.
	exchanger    upstream.Exchanger
	upstreams    *upstream.Pool // the exchanger, for its health
	forwardZones map[string]*forwardZone

	telemetry *telemetry

	// engine applies the current policy. It's replaced whenever the
	// policy changes.
	engine atomic.Pointer[filter.Engine]

	// policyMu serializes policy changes.
	policyMu sync.Mutex

	// store loads and saves the policy, if profiles are enabled.
	store *policyStore

	// lists holds the blocklists the policy uses, baseline holds those
	// from the Blocklist settings, and state outlives policy changes.
	lists    *blocklist.Registry
	baseline filter.Baseline
	state    *filter.State
	ages     *rdap.Ages
	exempt   []string

	// cache holds upstream answers, unless disabled.
	cache *cache.Cache

	// qlog is the query log, unless disabled.
	qlog *querylog.Log

	// hostnames learns devices' names for the query log, unless disabled.
	hostnames *hostnames.Directory

	// tokens authorize admin API requests, and signin signs browsers in
	// to the web UI, once the admin listener knows its address.
	tokens        tokens
	accounts      *serviceaccount.Store
	signin        atomic.Pointer[signin.Service]
	signinLimiter *ratelimit.Limiter
	setupLinks    *setupLinks

	// federation verifies workloads' identity tokens for token exchange,
	// and exchangeLimiter slows down clients whose exchanges fail.
	federation      federation.Verifier
	exchangeLimiter *ratelimit.Limiter

	trustedProxies []netip.Prefix

	// listeners records the addresses served on, by kind, for status.
	listenersMu sync.Mutex
	listeners   map[string]string

	handler   http.Handler
	tlsConfig *tls.Config

	// reloader serves certificates from files, if configured.
	reloader *certReloader

	// acmeHTTP serves ACME HTTP-01 challenges, if enabled.
	acmeHTTP http.Handler
}

// New returns a server for config, logging to logger.
//
// Blocklists named by the Blocklist settings are loaded before New
// returns, failing if none can be; lists named only by profiles load in
// the background, so a slow download doesn't hold up serving.
func New(config Config, logger *slog.Logger) (*Server, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	config = config.withDefaults()

	s := &Server{
		config:    config,
		logger:    logger,
		started:   time.Now(),
		telemetry: newTelemetry(),
		state:     filter.NewState(),
		listeners: make(map[string]string),

		signinLimiter:   newSigninLimiter(),
		exchangeLimiter: newExchangeLimiter(),
		setupLinks:      newSetupLinks(),
	}

	if config.Admin.flightRecorder() {
		recorder, err := newFlightRecorder(config.Admin, logger)
		if err != nil {
			return nil, err
		}
		s.telemetry.recorder = recorder
	}

	if err := s.configureUpstreams(); err != nil {
		return nil, err
	}

	for _, p := range config.TrustedProxies {
		prefix, _ := policy.ParsePrefix(p) // validated
		s.trustedProxies = append(s.trustedProxies, prefix)
	}

	if !config.Cache.Disabled {
		s.cache = cache.New(config.Cache.Size)
	}

	if err := s.configurePolicy(context.Background()); err != nil {
		s.lists.Close()
		return nil, err
	}

	if err := s.configureQueryLog(); err != nil {
		s.lists.Close()
		return nil, err
	}

	if err := s.configureHostnames(); err != nil {
		s.Close()
		return nil, err
	}

	if err := s.configureTokens(); err != nil {
		s.Close()
		return nil, err
	}
	if err := s.configureServiceAccounts(); err != nil {
		s.Close()
		return nil, err
	}

	handler := func(w http.ResponseWriter, r *http.Request, query *dns.Msg) (*dns.Msg, error) {
		profile, device := r.PathValue("profile"), r.PathValue("device")
		if profile == "" {
			profile, device, _ = s.profileFromHost(requestHost(r))
		}
		return s.resolve(r.Context(), request{
			transport: "doh",
			query:     query,
			client:    s.clientAddr(r),
			profile:   profile,
			device:    device,
		})
	}

	dohHandler := doh.NewHandler(handler, doh.WithLogger(logger))
	mux := http.NewServeMux()
	// Setup links' pages, opened on the device being set up.
	mux.HandleFunc("GET "+setupPath+"{code}", s.setupPage)
	mux.HandleFunc("GET "+setupPath+"{code}/{file}", s.setupPage)
	mux.Handle("GET "+config.Path, s.hostProfileGate(dohHandler))
	mux.Handle("POST "+config.Path, s.hostProfileGate(dohHandler))
	base := strings.TrimSuffix(config.Path, "/")
	for _, pattern := range []string{base + "/{profile}", base + "/{profile}/{device}"} {
		mux.Handle("GET "+pattern, s.profilePath(dohHandler))
		mux.Handle("POST "+pattern, s.profilePath(dohHandler))
	}
	mux.HandleFunc("GET "+HealthPath, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("ok\n"))
	})
	s.handler = logRequests(logger, mux)

	if err := s.configureTLS(); err != nil {
		s.Close()
		return nil, err
	}

	return s, nil
}

// profilePath serves DoH requests whose path names a profile, and
// optionally a device, rejecting unknown profiles and malformed device
// names with 404 Not Found, so they can't pollute the query log.
func (s *Server) profilePath(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.engine.Load().Profile(r.PathValue("profile")) == nil {
			http.Error(w, "unknown profile", http.StatusNotFound)
			return
		}
		if device := r.PathValue("device"); device != "" && !policy.ValidID(device) {
			http.Error(w, "invalid device name: use lower-case letters, digits, and hyphens", http.StatusNotFound)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// hostProfileGate serves DoH requests to the bare path, rejecting requests to
// a host name under the hostname that names no profile with 404 Not Found.
func (s *Server) hostProfileGate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if profile, _, ok := s.profileFromHost(requestHost(r)); ok && s.engine.Load().Profile(profile) == nil {
			http.Error(w, "unknown profile", http.StatusNotFound)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// requestHost returns the host name a DoH request was made to: the TLS
// server name, or behind a TLS-terminating proxy, the Host header.
func requestHost(r *http.Request) string {
	if r.TLS != nil && r.TLS.ServerName != "" {
		return r.TLS.ServerName
	}
	return r.Host
}

// Close releases the server's resources: background list loads, and the
// query log. ListenAndServe closes the server when it returns.
func (s *Server) Close() error {
	s.lists.Close()
	s.hostnames.Close()
	if s.ages != nil {
		if err := s.ages.Save(); err != nil {
			s.logger.Warn("saving registration cache", slog.Any("error", err))
		}
	}
	if s.qlog != nil {
		return s.qlog.Close()
	}
	return nil
}

// configureUpstreams sets up exchangers that fail over across the
// configured upstreams, and those of each forward zone.
func (s *Server) configureUpstreams() error {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.ForceAttemptHTTP2 = true

	opts := upstream.Options{
		HTTPClient: &http.Client{Transport: transport, CheckRedirect: upstream.CheckRedirect},
		Timeout:    time.Duration(s.config.Timeout),
	}

	pool := func(urls []string) (*upstream.Pool, error) {
		var exchangers []upstream.Exchanger
		for _, u := range urls {
			e, err := upstream.Parse(u, opts)
			if err != nil {
				return nil, err
			}
			exchangers = append(exchangers, s.telemetry.instrument(fmt.Sprint(e), e))

			// Never filter the upstreams' own names, in case this server
			// is the resolver that resolves them.
			if host := upstreamHost(u); host != "" {
				s.exempt = append(s.exempt, host)
			}
		}
		return upstream.NewPool(exchangers), nil
	}

	var err error
	if s.upstreams, err = pool(s.config.Upstreams); err != nil {
		return err
	}
	s.exchanger = s.upstreams

	s.forwardZones = make(map[string]*forwardZone, len(s.config.Forward))
	for domain, urls := range s.config.Forward {
		domain, _ = policy.NormalizeDomain(domain) // validated
		e, err := pool(urls)
		if err != nil {
			return err
		}
		s.forwardZones[domain] = &forwardZone{domain: domain, exchanger: e}
	}

	return nil
}

// upstreamHost returns the host name of an upstream URL, or "" if it's an
// address.
func upstreamHost(raw string) string {
	if !strings.Contains(raw, "://") {
		raw = "udp://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	if _, err := netip.ParseAddr(u.Hostname()); err == nil {
		return ""
	}
	return u.Hostname()
}

// configureTLS sets up certificates from files or ACME, unless the server
// is configured for plaintext.
func (s *Server) configureTLS() error {
	if s.config.Plaintext || !s.config.servesDoH() {
		return nil
	}

	minVersion, err := s.config.TLS.minVersion()
	if err != nil {
		return err
	}

	config := &tls.Config{
		MinVersion: minVersion,
		NextProtos: []string{"h2", "http/1.1"},
	}

	if acmeConfig := s.config.TLS.ACME; len(acmeConfig.Domains) > 0 {
		manager := &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: s.acmeHostPolicy(acmeConfig.Domains),
			Cache:      autocert.DirCache(acmeConfig.CacheDir),
			Email:      acmeConfig.Email,
		}
		if acmeConfig.DirectoryURL != "" {
			manager.Client = &acme.Client{DirectoryURL: acmeConfig.DirectoryURL}
		}

		// The host policy applies to cached certificates too, so names
		// removed from the configured domains, or of deleted profiles, are
		// refused.
		config.GetCertificate = manager.GetCertificate
		// Answer TLS-ALPN-01 challenges (RFC 8737) on the TLS listener.
		config.NextProtos = append(config.NextProtos, acme.ALPNProto)

		if acmeConfig.HTTPListen != "" {
			s.acmeHTTP = manager.HTTPHandler(nil)
		}
	} else {
		reloader, err := newCertReloader(s.config.TLS.CertFile, s.config.TLS.KeyFile, s.logger)
		if err != nil {
			return err
		}
		config.GetCertificate = reloader.GetCertificate
		s.reloader = reloader
	}

	s.tlsConfig = config
	return nil
}

// Handler returns the server's HTTP handler, serving the DoH endpoint and
// the health check.
func (s *Server) Handler() http.Handler { return s.handler }

// ListenAndServe listens on the configured addresses and serves until ctx
// is done, then shuts down gracefully. If any listener fails, all of them
// are shut down.
func (s *Server) ListenAndServe(ctx context.Context) error {
	defer s.Close()

	var (
		ln     net.Listener
		pc     net.PacketConn
		dnsLn  net.Listener
		opened []io.Closer
		err    error
	)

	closeAll := func() {
		for _, c := range opened {
			c.Close()
		}
	}

	if s.config.servesDoH() {
		if ln, err = net.Listen("tcp", s.config.Listen); err != nil {
			return listenError("serve", s.config.Listen, err)
		}
		opened = append(opened, ln)
	}

	var dotLn net.Listener
	if s.config.DoTListen != "" {
		if dotLn, err = net.Listen("tcp", s.config.DoTListen); err != nil {
			closeAll()
			return listenError("serve: dot", s.config.DoTListen, err)
		}
		opened = append(opened, dotLn)
	}

	var doqPC net.PacketConn
	if s.config.DoQListen != "" {
		if doqPC, err = net.ListenPacket("udp", s.config.DoQListen); err != nil {
			closeAll()
			return listenError("serve: doq", s.config.DoQListen, err)
		}
		opened = append(opened, doqPC)
	}

	var adminLn net.Listener
	if s.config.Admin.Listen != "" {
		if adminLn, err = net.Listen("tcp", s.config.Admin.Listen); err != nil {
			closeAll()
			return listenError("serve: admin", s.config.Admin.Listen, err)
		}
		opened = append(opened, adminLn)
	}

	if s.config.DNSListen != "" {
		if pc, err = net.ListenPacket("udp", s.config.DNSListen); err != nil {
			closeAll()
			return listenError("serve: dns", s.config.DNSListen, err)
		}
		opened = append(opened, pc)

		// Bind TCP to the port UDP got, so that with port 0 both share an
		// ephemeral port, and clients can retry truncated answers over TCP.
		if dnsLn, err = net.Listen("tcp", pc.LocalAddr().String()); err != nil {
			closeAll()
			return listenError("serve: dns", s.config.DNSListen, err)
		}
	}

	stopTelemetry, err := s.startTelemetry()
	if err != nil {
		closeAll()
		return err
	}
	// Deferred, so it runs after every listener below has drained.
	defer stopTelemetry()

	g, ctx := errgroup.WithContext(ctx)
	if ln != nil {
		g.Go(func() error { return s.Serve(ctx, ln) })
	} else {
		s.logger.Info("DoH disabled: no TLS certificate or plaintext configured, serving plain DNS only")
	}
	if pc != nil {
		g.Go(func() error { return s.ServeDNS(ctx, pc, dnsLn) })
	}
	if dotLn != nil {
		g.Go(func() error { return s.ServeDoT(ctx, dotLn) })
	}
	if doqPC != nil {
		g.Go(func() error { return s.ServeDoQ(ctx, doqPC) })
	}
	g.Go(func() error { return s.lists.Refresh(ctx, time.Duration(s.config.Blocklist.Refresh)) })
	if s.store != nil {
		g.Go(func() error { return s.store.watch(ctx, s.applyPolicy) })
	}
	if adminLn != nil {
		g.Go(func() error { return s.ServeAdmin(ctx, adminLn) })
	}

	return g.Wait()
}

// setListener records an address served on, for status.
func (s *Server) setListener(kind string, addr net.Addr) {
	s.listenersMu.Lock()
	s.listeners[kind] = addr.String()
	s.listenersMu.Unlock()
}

// listenerAddr returns the address served on for kind ("doh", "dns",
// "dot", or "admin"), or "" if it isn't served.
func (s *Server) listenerAddr(kind string) string {
	s.listenersMu.Lock()
	defer s.listenersMu.Unlock()
	return s.listeners[kind]
}

// listenError explains common reasons a listener can't be opened, such as
// on the privileged DNS port 53.
func listenError(prefix, addr string, err error) error {
	switch {
	case errors.Is(err, syscall.EACCES):
		return fmt.Errorf("%s: %w (ports below 1024 need privileges: run as root, or allow the binary with `sudo setcap cap_net_bind_service=+ep $(command -v doh)`)", prefix, err)
	case errors.Is(err, syscall.EADDRINUSE):
		return fmt.Errorf("%s: %w (another server is using %s; on Linux, systemd-resolved often holds port 53: listen on a specific address such as 192.168.1.10:53, or set DNSStubListener=no in /etc/systemd/resolved.conf)", prefix, err, addr)
	default:
		return fmt.Errorf("%s: %w", prefix, err)
	}
}

// Serve serves on ln until ctx is done, then shuts down gracefully,
// waiting for in-flight requests to finish.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	if !s.config.servesDoH() {
		ln.Close()
		return errors.New("serve: DoH needs a TLS certificate, an ACME domain, or plaintext")
	}

	servers := []*http.Server{s.httpServer(s.handler)}

	if s.tlsConfig != nil {
		servers[0].TLSConfig = s.tlsConfig
		ln = tls.NewListener(ln, s.tlsConfig)
	}

	listeners := []net.Listener{ln}

	if s.acmeHTTP != nil {
		acmeLn, err := net.Listen("tcp", s.config.TLS.ACME.HTTPListen)
		if err != nil {
			ln.Close()
			return fmt.Errorf("serve: acme http listener: %w", err)
		}

		servers = append(servers, s.httpServer(s.acmeHTTP))
		listeners = append(listeners, acmeLn)
	}

	s.setListener("doh", ln.Addr())

	errc := make(chan error, len(servers))
	for i, srv := range servers {
		s.logger.Info("serving",
			slog.String("addr", listeners[i].Addr().String()),
			slog.Bool("tls", s.tlsConfig != nil && i == 0),
			slog.String("path", s.config.Path),
		)

		go func() {
			if err := srv.Serve(listeners[i]); !errors.Is(err, http.ErrServerClosed) {
				errc <- err
			}
		}()
	}

	var err error
	select {
	case <-ctx.Done():
	case err = <-errc:
	}

	s.logger.Info("shutting down", slog.Any("cause", context.Cause(ctx)))

	shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownTimeout)
	defer cancel()

	for _, srv := range servers {
		err = errors.Join(err, srv.Shutdown(shutdownCtx))
	}

	return err
}

// httpServer returns an HTTP server for handler with conservative timeouts.
func (s *Server) httpServer(handler http.Handler) *http.Server {
	return &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      time.Duration(s.config.Timeout) + 5*time.Second,
		IdleTimeout:       2 * time.Minute,
		ErrorLog:          slog.NewLogLogger(s.logger.Handler(), slog.LevelDebug),
	}
}

// logRequests logs each request at debug level.
func logRequests(logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !logger.Enabled(r.Context(), slog.LevelDebug) {
			next.ServeHTTP(w, r)
			return
		}

		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)

		attrs := []slog.Attr{
			slog.String("method", r.Method),
			slog.String("path", r.URL.Path),
			slog.String("proto", r.Proto),
			slog.String("remote", r.RemoteAddr),
			slog.Int("status", rec.status),
			slog.Duration("duration", time.Since(start)),
		}
		if r.TLS != nil {
			attrs = append(attrs,
				slog.String("tls", tls.VersionName(r.TLS.Version)),
				slog.String("cipher_suite", tls.CipherSuiteName(r.TLS.CipherSuite)),
			)
		}

		logger.LogAttrs(r.Context(), slog.LevelDebug, "request", attrs...)
	})
}

// statusRecorder records the status code written to a response.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

func (r *statusRecorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }

// certReloaderInterval is how often certificate files are checked for
// changes, at most.
const certReloaderInterval = 10 * time.Second

// certReloader serves a certificate from files, reloading it when either
// file changes so renewed certificates are picked up without a restart.
type certReloader struct {
	certFile, keyFile string
	logger            *slog.Logger

	mu       sync.Mutex
	cert     *tls.Certificate
	modTimes [2]time.Time // of certFile and keyFile, when cert was loaded
	checked  time.Time
}

// newCertReloader loads the certificate, failing if it can't be read.
func newCertReloader(certFile, keyFile string, logger *slog.Logger) (*certReloader, error) {
	r := &certReloader{certFile: certFile, keyFile: keyFile, logger: logger}

	modTimes, err := r.statFiles()
	if err != nil {
		return nil, fmt.Errorf("serve: %w", err)
	}

	if err := r.load(modTimes); err != nil {
		return nil, err
	}

	return r, nil
}

// GetCertificate implements [tls.Config.GetCertificate].
func (r *certReloader) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if now := time.Now(); now.Sub(r.checked) >= certReloaderInterval {
		r.checked = now

		// Reload when either file's modification time changes in any
		// direction, since a replacement may carry an older timestamp.
		modTimes, err := r.statFiles()
		switch {
		case err != nil:
			r.logger.Warn("checking certificate files", slog.Any("error", err))
		case !modTimes[0].Equal(r.modTimes[0]) || !modTimes[1].Equal(r.modTimes[1]):
			// Keep serving the previous certificate if the new one is
			// invalid, such as when only one file has been replaced so far.
			if err := r.load(modTimes); err != nil {
				r.logger.Warn("reloading certificate", slog.Any("error", err))
			} else {
				r.logger.Info("reloaded certificate", slog.String("cert_file", r.certFile))
			}
		}
	}

	return r.cert, nil
}

// load reads the certificate files, recording modTimes on success.
func (r *certReloader) load(modTimes [2]time.Time) error {
	cert, err := tls.LoadX509KeyPair(r.certFile, r.keyFile)
	if err != nil {
		return fmt.Errorf("serve: loading certificate: %w", err)
	}

	r.cert, r.modTimes = &cert, modTimes
	return nil
}

// statFiles returns the modification times of the certificate and key.
func (r *certReloader) statFiles() ([2]time.Time, error) {
	var modTimes [2]time.Time

	for i, name := range []string{r.certFile, r.keyFile} {
		info, err := os.Stat(name)
		if err != nil {
			return modTimes, err
		}
		modTimes[i] = info.ModTime()
	}

	return modTimes, nil
}
