package serve

import (
	"cmp"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/picatz/doh/internal/api"
	"github.com/picatz/doh/internal/ratelimit"
	"github.com/picatz/doh/internal/signin"
)

// configureSignin starts browser sign-in for the admin listener at addr:
// at the configured origins, or for a loopback listener, at localhost.
// Without an origin, browsers can only use the API with a token.
func (s *Server) configureSignin(addr net.Addr) error {
	if s.config.DataDir == "" && !s.tokens.enabled() {
		return nil // no API to sign in to
	}

	origins := s.config.Admin.Origins
	if len(origins) == 0 {
		ap, err := netip.ParseAddrPort(addr.String())
		if err != nil || !ap.Addr().IsLoopback() {
			s.logger.Info("admin: browser sign-in is off; set --admin-origin to the URL the web UI is opened at")
			return nil
		}
		// Passkeys need a host name, and browsers treat localhost as
		// secure even over HTTP.
		origins = []string{"http://localhost:" + strconv.Itoa(int(ap.Port()))}
	}

	config := signin.Config{Origins: origins, Logger: s.logger}
	if s.config.DataDir != "" {
		config.Path = filepath.Join(s.config.DataDir, "people.json")
	}
	svc, err := signin.New(config)
	if err != nil {
		return err
	}
	s.signin.Store(svc)
	return nil
}

// uiURL returns where the web UI is opened.
func (s *Server) uiURL() string {
	if len(s.config.Admin.Origins) > 0 {
		return s.config.Admin.Origins[0] + "/"
	}
	if svc := s.signin.Load(); svc != nil {
		return "http://" + net.JoinHostPort(svc.RPID(), portOf(s.listenerAddr("admin"))) + "/"
	}
	return "http://" + s.listenerAddr("admin") + "/"
}

func portOf(addr string) string {
	_, port, _ := net.SplitHostPort(addr)
	return port
}

// newSigninLimiter bounds sign-in attempts per client: a burst of a few dozen,
// then one every two seconds. That's far more than people need, and keeps
// anyone from filling the server's pending ceremonies or guessing at scale.
func newSigninLimiter() *ratelimit.Limiter {
	return &ratelimit.Limiter{Rate: 0.5, Burst: 30}
}

// signinHandler serves the sign-in endpoints, if browser sign-in is on,
// limiting how often each client may try to sign in.
func (s *Server) signinHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		svc := s.signin.Load()
		if svc == nil {
			writeError(w, http.StatusNotFound, "browser sign-in is off; set --admin-origin to the URL the web UI is opened at")
			return
		}
		if isSigninAttempt(r) && !s.signinLimiter.Allow(s.clientAddr(r).String()) {
			w.Header().Set("Retry-After", "2")
			writeError(w, http.StatusTooManyRequests, "too many sign-in attempts; wait a moment")
			return
		}
		svc.Handler().ServeHTTP(w, r)
	})
}

// isSigninAttempt reports whether r tries to sign in: using a link, or
// beginning or finishing a passkey sign-in. Only these are rate limited, so
// people who are signed in, perhaps sharing an address behind NAT, never
// use up others' attempts.
func isSigninAttempt(r *http.Request) bool {
	if r.Method != http.MethodPost {
		return false
	}
	p := strings.TrimPrefix(r.URL.Path, signin.Prefix)
	return p == "/link" || p == "/passkey/login" || strings.HasPrefix(p, "/passkey/login/")
}

func (s *Server) apiSigninLink(w http.ResponseWriter, r *http.Request) {
	svc := s.signin.Load()
	if svc == nil {
		writeError(w, http.StatusNotFound, "browser sign-in is off; set --admin-origin to the URL the web UI is opened at")
		return
	}

	var req api.SigninLinkRequest
	if r.ContentLength != 0 && !decode(w, r, &req) {
		return
	}
	role := signin.Role(cmp.Or(req.Role, string(signin.RoleAdmin)))

	// A tenant's admins invite people to their own tenant; the operator
	// may invite anyone to any tenant.
	who := principalOf(r)
	switch {
	case !who.operator() && req.Tenant != "" && req.Tenant != who.tenant:
		writeError(w, http.StatusForbidden, "you can only invite people to your own tenant")
		return
	case !who.operator():
		req.Tenant = who.tenant
	case req.Tenant != "" && s.engine.Load().Policy().Tenant(req.Tenant) == nil:
		writeError(w, http.StatusNotFound, "no tenant "+strconv.Quote(req.Tenant))
		return
	}

	code, expires, err := svc.NewLink(role, req.Tenant)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, api.SigninLink{
		URL:             s.uiURL() + "#signin=" + code,
		Expires:         expires,
		PasskeyRequired: svc.HasPasskeys(req.Tenant),
	})
}

func (s *Server) apiPeople(w http.ResponseWriter, r *http.Request) {
	people := []signin.Person{}
	if svc := s.signin.Load(); svc != nil {
		who := principalOf(r)
		people = slices.DeleteFunc(svc.People(), func(p signin.Person) bool { return !who.seesPerson(p) })
	}
	writeJSON(w, http.StatusOK, api.People{People: people})
}

func (s *Server) apiDeletePerson(w http.ResponseWriter, r *http.Request) {
	s.deleteSignin(w, r, func(svc *signin.Service) error { return svc.DeletePerson(r.PathValue("id")) })
}

func (s *Server) apiDeletePasskey(w http.ResponseWriter, r *http.Request) {
	s.deleteSignin(w, r, func(svc *signin.Service) error { return svc.DeletePasskey(r.PathValue("id"), r.PathValue("passkey")) })
}

func (s *Server) deleteSignin(w http.ResponseWriter, r *http.Request, del func(*signin.Service) error) {
	svc := s.signin.Load()
	if svc == nil {
		writeError(w, http.StatusNotFound, "not found")
		return
	}

	// Only people the caller can see can be removed; anyone else looks
	// like they don't exist.
	who := principalOf(r)
	id := r.PathValue("id")
	if !slices.ContainsFunc(svc.People(), func(p signin.Person) bool { return p.ID == id && who.seesPerson(p) }) {
		writeError(w, http.StatusNotFound, "not found")
		return
	}

	switch err := del(svc); {
	case errors.Is(err, signin.ErrNotFound):
		writeError(w, http.StatusNotFound, "not found")
	case err != nil:
		s.logger.Error("admin: removing sign-in", slog.Any("error", err))
		writeError(w, http.StatusInternalServerError, "removing failed")
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}

// canonicalHost redirects UI page loads at a loopback IP address to
// localhost when passkeys are for localhost, since browsers only offer
// passkeys at their relying party's host. Browsers keep the URL fragment,
// such as a sign-in link's code, across the redirect.
func (s *Server) canonicalHost(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		svc := s.signin.Load()
		if svc == nil || svc.RPID() != "localhost" || (r.Method != http.MethodGet && r.Method != http.MethodHead) {
			next.ServeHTTP(w, r)
			return
		}
		host, port, err := net.SplitHostPort(r.Host)
		if a, perr := netip.ParseAddr(host); err == nil && perr == nil && a.IsLoopback() {
			u := *r.URL
			u.Scheme, u.Host = "http", net.JoinHostPort("localhost", port)
			http.Redirect(w, r, u.String(), http.StatusFound)
			return
		}
		next.ServeHTTP(w, r)
	})
}
