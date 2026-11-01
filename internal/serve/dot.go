package serve

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/picatz/doh/internal/policy"
)

// dotIdleTimeout is how long an idle DNS-over-TLS connection is kept open,
// so clients can reuse it for later queries rather than paying for a new
// handshake each time ([RFC 7858, Section 3.4]).
//
// [RFC 7858, Section 3.4]: https://www.rfc-editor.org/rfc/rfc7858.html#section-3.4
const dotIdleTimeout = 2 * time.Minute

// ServeDoT serves DNS-over-TLS ([RFC 7858]) on ln until ctx is done, then
// shuts down gracefully. The TLS server name the client asked for selects
// its profile and device, as described for [Config.Hostname].
//
// [RFC 7858]: https://www.rfc-editor.org/rfc/rfc7858.html
func (s *Server) ServeDoT(ctx context.Context, ln net.Listener) error {
	if s.tlsConfig == nil {
		ln.Close()
		return errors.New("serve: DoT needs a TLS certificate or an ACME domain")
	}

	queryCtx := context.WithoutCancel(ctx)

	// DoT only speaks DNS; don't offer HTTP's protocols.
	config := s.tlsConfig.Clone()
	config.NextProtos = []string{"dot"}

	handler := dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		var serverName string
		if cs, ok := w.(dns.ConnectionStater); ok {
			if state := cs.ConnectionState(); state != nil {
				serverName = state.ServerName
			}
		}

		resp := s.answerDoT(queryCtx, addrOf(w.RemoteAddr()), serverName, req)
		if err := w.WriteMsg(resp); err != nil {
			s.logger.Debug("dot: writing response", slog.Any("error", err))
		}
	})

	srv := &dns.Server{
		Listener:     tls.NewListener(ln, config),
		Handler:      handler,
		ReadTimeout:  readTimeout,
		WriteTimeout: readTimeout,
		IdleTimeout:  func() time.Duration { return dotIdleTimeout },
	}

	started := make(chan struct{})
	srv.NotifyStartedFunc = func() { close(started) }
	errc := make(chan error, 1)
	go func() { errc <- srv.ActivateAndServe() }()

	select {
	case <-started:
	case err := <-errc:
		return err
	}

	s.setListener("dot", ln.Addr())
	s.logger.Info("serving dot", slog.String("addr", ln.Addr().String()), slog.String("hostname", s.config.Hostname))

	var err error
	select {
	case <-ctx.Done():
	case err = <-errc:
	}

	s.logger.Info("shutting down dot", slog.Any("cause", context.Cause(ctx)))
	return errors.Join(err, shutdownDNS([]*dns.Server{srv}))
}

// answerDoT answers a DNS-over-TLS query, selecting the profile by the TLS
// server name, if it names one.
func (s *Server) answerDoT(ctx context.Context, client netip.Addr, serverName string, req *dns.Msg) *dns.Msg {
	profile, device, ok := s.profileFromHost(serverName)
	if ok && s.engine.Load().Profile(profile) == nil {
		// A name under the hostname that isn't a profile: refuse rather
		// than silently falling back to another profile's rules.
		return refuseUnknownProfile(req)
	}
	return s.answerQuery(ctx, request{transport: "dot", query: req, client: client, profile: profile, device: device})
}

// refuseUnknownProfile answers a query whose host name names no profile.
func refuseUnknownProfile(req *dns.Msg) *dns.Msg {
	resp := new(dns.Msg).SetRcode(req, dns.RcodeRefused)
	if opt := req.IsEdns0(); opt != nil {
		resp.SetEdns0(dns.DefaultMsgSize, opt.Do())
		resp.IsEdns0().Option = append(resp.IsEdns0().Option, &dns.EDNS0_EDE{InfoCode: dns.ExtendedErrorCodeProhibited, ExtraText: "unknown profile"})
	}
	return resp
}

// profileFromHost returns the profile and device a host name selects:
// "kids.{hostname}" selects profile kids, and "tablet--kids.{hostname}"
// also names the device tablet. ok reports whether host is a name under
// the configured hostname; if it is the hostname itself, or isn't under
// it, no profile is selected.
func (s *Server) profileFromHost(host string) (profile, device string, ok bool) {
	hostname := s.config.Hostname
	if hostname == "" || host == "" {
		return "", "", false
	}

	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))

	label, rest, found := strings.Cut(host, ".")
	if !found || rest != hostname {
		return "", "", false
	}

	if d, p, found := strings.Cut(label, policy.IDSeparator); found {
		if !policy.ValidID(d) || !policy.ValidID(p) {
			return label, "", true // not a valid profile, so it won't be found
		}
		return p, d, true
	}
	return label, "", true
}

// profileHost returns the host name that selects profile and device, or
// "" if there's no hostname or the name would be too long for a label.
func (s *Server) profileHost(profile, device string) string {
	if s.config.Hostname == "" {
		return ""
	}
	label := profile
	if device != "" {
		label = device + policy.IDSeparator + profile
	}
	if len(label) > 63 {
		return ""
	}
	return label + "." + s.config.Hostname
}

// acmeHostPolicy allows certificates for the configured ACME domains and,
// under the hostname, for names that select an existing profile, so
// clients can't make the server request certificates for arbitrary names.
func (s *Server) acmeHostPolicy(domains []string) func(context.Context, string) error {
	allowed := make(map[string]bool, len(domains))
	for _, d := range domains {
		allowed[strings.ToLower(strings.TrimSuffix(d, "."))] = true
	}

	return func(_ context.Context, host string) error {
		host = strings.ToLower(strings.TrimSuffix(host, "."))
		if allowed[host] {
			return nil
		}
		if profile, _, ok := s.profileFromHost(host); ok && s.engine.Load().Profile(profile) != nil {
			return nil
		}
		return fmt.Errorf("acme: host %q is not configured, and doesn't name a profile", host)
	}
}
