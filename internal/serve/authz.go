package serve

import (
	"context"
	"net/http"
	"net/netip"
	"slices"

	"github.com/picatz/doh/internal/policy"
	"github.com/picatz/doh/internal/signin"
)

// principal is who's making an admin API request: what they may do, and
// for whom.
//
// API tokens belong to the server's operator. Signed-in browsers act for
// their person's tenant, or as the operator if the person has none. The
// operator manages every tenant; a tenant's people see and change only
// their tenant's profiles, query log, people, and setup, and other
// tenants' profiles look like they don't exist.
type principal struct {
	role   role
	tenant string // "" for the operator
}

// operator reports whether p is the server's operator.
func (p principal) operator() bool { return p.tenant == "" }

// sees reports whether p may see and, with an admin role, change pr.
func (p principal) sees(pr *policy.Profile) bool {
	return pr != nil && (p.operator() || pr.Tenant == p.tenant)
}

// seesPerson reports whether p may see, and as an admin remove, person.
func (p principal) seesPerson(person signin.Person) bool {
	return p.operator() || person.Tenant == p.tenant
}

type principalKey struct{}

// principalOf returns the principal authorize attached to r.
func principalOf(r *http.Request) principal {
	p, _ := r.Context().Value(principalKey{}).(principal)
	return p
}

// withPrincipal attaches p to r.
func withPrincipal(r *http.Request, p principal) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), principalKey{}, p))
}

// sessionPrincipal returns the principal of r's signed-in browser
// session, if it has a complete one.
func (s *Server) sessionPrincipal(r *http.Request) (principal, bool) {
	svc := s.signin.Load()
	if svc == nil {
		return principal{}, false
	}
	sess, ok := svc.Session(r)
	if !ok || sess.Pending {
		return principal{}, false
	}
	p := principal{role: roleReader, tenant: sess.Tenant}
	if sess.Role == signin.RoleAdmin {
		p.role = roleAdmin
	}
	return p, true
}

// operatorOnly refuses requests from anyone but the operator.
func operatorOnly(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !principalOf(r).operator() {
			writeError(w, http.StatusForbidden, "only the server's operator can do this")
			return
		}
		next(w, r)
	}
}

// visibleProfiles returns the profiles of pol that p sees.
func visibleProfiles(pol *policy.Policy, p principal) []policy.Profile {
	return slices.DeleteFunc(slices.Clone(pol.Profiles), func(pr policy.Profile) bool { return !p.sees(&pr) })
}

// requireOperator wraps an admin handler that reveals details of the
// whole process, such as profiling.
//
// On a loopback admin listener that isn't published for browser sign-in,
// only the machine's own users can reach it, so it stays open, and tools
// such as "go tool pprof" work without credentials. Once the UI is
// published with --admin-origin, these need the operator's credentials.
func (s *Server) requireOperator(next http.Handler) http.Handler {
	guarded := s.authorize(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !principalOf(r).operator() {
			writeError(w, http.StatusForbidden, "only the server's operator can do this")
			return
		}
		next.ServeHTTP(w, r)
	}))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.adminPrivate() {
			next.ServeHTTP(w, r)
			return
		}
		guarded.ServeHTTP(w, r)
	})
}

// adminPrivate reports whether the admin listener is reachable only from
// this machine: bound to a loopback address, and not published for
// browser sign-in at another origin.
func (s *Server) adminPrivate() bool {
	if len(s.config.Admin.Origins) > 0 {
		return false
	}
	ap, err := netip.ParseAddrPort(s.listenerAddr("admin"))
	return err == nil && ap.Addr().IsLoopback()
}
