package serve

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/miekg/dns"
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
// resolvers.
type Server struct {
	config Config
	logger *slog.Logger

	// exchanger forwards queries to the configured upstreams.
	exchanger upstream.Exchanger

	telemetry *telemetry

	// blocker answers queries for blocked names, if configured.
	blocker *blocker

	handler   http.Handler
	tlsConfig *tls.Config

	// reloader serves certificates from files, if configured.
	reloader *certReloader

	// acmeHTTP serves ACME HTTP-01 challenges, if enabled.
	acmeHTTP http.Handler
}

// New returns a server for config, logging to logger.
func New(config Config, logger *slog.Logger) (*Server, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	config = config.withDefaults()

	s := &Server{config: config, logger: logger, telemetry: newTelemetry()}

	if config.Admin.flightRecorder() {
		recorder, err := newFlightRecorder(config.Admin, logger)
		if err != nil {
			return nil, err
		}
		s.telemetry.recorder = recorder
	}

	exchanger, err := s.upstreams()
	if err != nil {
		return nil, err
	}
	s.exchanger = exchanger

	if config.Blocklist.enabled() {
		blocker, err := newBlocker(context.Background(), config.Blocklist, logger)
		if err != nil {
			return nil, err
		}
		s.blocker = blocker
	}

	handler := func(w http.ResponseWriter, r *http.Request, query *dns.Msg) (*dns.Msg, error) {
		return s.resolve(r.Context(), "doh", query)
	}

	mux := doh.NewServerMux(handler, doh.WithPath(config.Path), doh.WithLogger(logger))
	mux.HandleFunc("GET "+HealthPath, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("ok\n"))
	})
	s.handler = logRequests(logger, mux)

	if err := s.configureTLS(); err != nil {
		return nil, err
	}

	return s, nil
}

// resolve answers query, received over transport, using the upstreams
// within the configured timeout.
func (s *Server) resolve(ctx context.Context, transport string, query *dns.Msg) (*dns.Msg, error) {
	ctx, cancel := context.WithTimeout(ctx, time.Duration(s.config.Timeout))
	defer cancel()

	start := time.Now()

	if s.blocker != nil {
		if resp, v := s.blocker.answer(query); resp != nil {
			s.telemetry.blocked.Add(v.Source, 1)
			s.telemetry.observe(ctx, transport, time.Since(start), resp, nil)
			return resp, nil
		}
	}

	resp, err := s.exchanger.Exchange(ctx, query)
	s.telemetry.observe(ctx, transport, time.Since(start), resp, err)

	return resp, err
}

// upstreams returns an exchanger that fails over across the configured
// upstreams.
func (s *Server) upstreams() (upstream.Exchanger, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.ForceAttemptHTTP2 = true

	opts := upstream.Options{
		HTTPClient: &http.Client{Transport: transport, CheckRedirect: upstream.CheckRedirect},
		Timeout:    time.Duration(s.config.Timeout),
	}

	var failover upstream.Failover
	for _, u := range s.config.Upstreams {
		e, err := upstream.Parse(u, opts)
		if err != nil {
			return nil, err
		}
		failover = append(failover, s.telemetry.instrument(fmt.Sprint(e), e))
	}

	return failover, nil
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
			HostPolicy: autocert.HostWhitelist(acmeConfig.Domains...),
			Cache:      autocert.DirCache(acmeConfig.CacheDir),
			Email:      acmeConfig.Email,
		}
		if acmeConfig.DirectoryURL != "" {
			manager.Client = &acme.Client{DirectoryURL: acmeConfig.DirectoryURL}
		}

		// The host policy applies to cached certificates too, so names
		// removed from the configured domains are refused.
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
	if s.blocker != nil {
		g.Go(func() error { return s.blocker.refresh(ctx, time.Duration(s.config.Blocklist.Refresh)) })
	}
	if adminLn != nil {
		g.Go(func() error { return s.ServeAdmin(ctx, adminLn) })
	}

	return g.Wait()
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
