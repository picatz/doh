package serve

import (
	"cmp"
	"errors"
	"log/slog"
	"net/http"
	"path/filepath"
	"slices"
	"strconv"
	"time"

	"github.com/picatz/doh/internal/api"
	"github.com/picatz/doh/internal/audit"
	"github.com/picatz/doh/internal/serviceaccount"
)

// ServiceAccountsFile is where service accounts are kept in the data
// directory.
const ServiceAccountsFile = "service-accounts.json"

// defaultKeyLifetime is how long a key lasts when its request doesn't say.
const defaultKeyLifetime = 90 * 24 * time.Hour

// configureServiceAccounts opens the service account store: in the data
// directory, or in memory without one.
func (s *Server) configureServiceAccounts() error {
	path := ""
	if s.config.DataDir != "" {
		path = filepath.Join(s.config.DataDir, ServiceAccountsFile)
	}
	store, err := serviceaccount.Open(path)
	if err != nil {
		return err
	}
	s.accounts = store
	return nil
}

// seesAccount reports whether p may see, and as an admin change, a.
func (p principal) seesAccount(a serviceaccount.Account) bool {
	return p.operator() || a.Tenant == p.tenant
}

func (s *Server) apiServiceAccounts(w http.ResponseWriter, r *http.Request) {
	who := principalOf(r)
	accounts := slices.DeleteFunc(s.accounts.Accounts(), func(a serviceaccount.Account) bool { return !who.seesAccount(a) })
	writeJSON(w, http.StatusOK, api.ServiceAccounts{ServiceAccounts: accounts})
}

func (s *Server) apiServiceAccount(w http.ResponseWriter, r *http.Request) {
	if a, ok := s.visibleAccount(w, r); ok {
		writeJSON(w, http.StatusOK, a)
	}
}

// visibleAccount returns the account r names, if the caller sees it,
// writing 404 otherwise: other tenants' accounts look like they don't
// exist.
func (s *Server) visibleAccount(w http.ResponseWriter, r *http.Request) (serviceaccount.Account, bool) {
	a, ok := s.accounts.Account(r.PathValue("id"))
	if !ok || !principalOf(r).seesAccount(a) {
		writeError(w, http.StatusNotFound, "no service account "+strconv.Quote(r.PathValue("id")))
		return serviceaccount.Account{}, false
	}
	return a, true
}

func (s *Server) apiCreateServiceAccount(w http.ResponseWriter, r *http.Request) {
	var req api.ServiceAccountRequest
	if !decode(w, r, &req) {
		return
	}

	// A tenant's admins make service accounts for their own tenant; the
	// operator may make them for any tenant, or for itself.
	who := principalOf(r)
	switch {
	case !who.operator() && req.Tenant != "" && req.Tenant != who.tenant:
		writeError(w, http.StatusForbidden, "you can only create service accounts for your own tenant")
		return
	case !who.operator():
		req.Tenant = who.tenant
	case req.Tenant != "" && s.engine.Load().Policy().Tenant(req.Tenant) == nil:
		writeError(w, http.StatusNotFound, "no tenant "+strconv.Quote(req.Tenant))
		return
	}

	a, err := s.accounts.Create(serviceaccount.NewAccount{
		Name:      req.Name,
		Tenant:    req.Tenant,
		Role:      serviceaccount.Role(cmp.Or(req.Role, string(serviceaccount.RoleReader))),
		CreatedBy: who.by,
	})
	if s.writeAccountError(w, err) {
		return
	}
	s.audit(r, change{action: "service_account.created", message: "service account created", tenant: a.Tenant, target: audit.Target{Type: "service_account", ID: a.ID},
		summary: "Created service account " + a.Name + " (" + string(a.Role) + ")",
		details: details("account", a.ID, "name", a.Name, "role", string(a.Role))})
	writeJSON(w, http.StatusCreated, a)
}

func (s *Server) apiDeleteServiceAccount(w http.ResponseWriter, r *http.Request) {
	a, ok := s.visibleAccount(w, r)
	if !ok {
		return
	}
	if s.writeAccountError(w, s.accounts.Delete(a.ID)) {
		return
	}
	s.audit(r, change{action: "service_account.deleted", message: "service account deleted", tenant: a.Tenant, target: audit.Target{Type: "service_account", ID: a.ID},
		summary: "Deleted service account " + a.Name, details: details("account", a.ID, "name", a.Name)})
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) apiAddKey(w http.ResponseWriter, r *http.Request) {
	a, ok := s.visibleAccount(w, r)
	if !ok {
		return
	}
	var req api.KeyRequest
	if r.ContentLength != 0 && !decode(w, r, &req) {
		return
	}
	expires := cmp.Or(req.Expires, time.Now().Add(defaultKeyLifetime))

	k, secret, err := s.accounts.AddKey(a.ID, expires, binding(req.JKT)...)
	if s.writeAccountError(w, err) {
		return
	}
	s.audit(r, change{action: "service_account.key.added", message: "service account key added", tenant: a.Tenant, target: audit.Target{Type: "service_account", ID: a.ID},
		summary: "Added key " + k.ID + " to service account " + a.Name,
		details: details("account", a.ID, "key", k.ID, "expires", k.Expires.UTC().Format(time.RFC3339), "jkt", k.JKT)})
	writeJSON(w, http.StatusCreated, api.NewKey{Account: a.ID, Key: k, Secret: secret})
}

func (s *Server) apiRotateKey(w http.ResponseWriter, r *http.Request) {
	a, ok := s.visibleAccount(w, r)
	if !ok {
		return
	}
	var req api.RotateKeyRequest
	if r.ContentLength != 0 && !decode(w, r, &req) {
		return
	}
	now := time.Now()
	expires := cmp.Or(req.Expires, now.Add(defaultKeyLifetime))
	grace := time.Duration(0)
	if !req.PreviousExpires.IsZero() {
		grace = max(0, req.PreviousExpires.Sub(now).Round(time.Second))
	}

	k, secret, err := s.accounts.RotateKey(a.ID, r.PathValue("key"), expires, grace, binding(req.JKT)...)
	if s.writeAccountError(w, err) {
		return
	}
	s.audit(r, change{action: "service_account.key.rotated", message: "service account key rotated", tenant: a.Tenant, target: audit.Target{Type: "service_account", ID: a.ID},
		summary: "Rotated key " + r.PathValue("key") + " of service account " + a.Name + " to " + k.ID,
		details: details("account", a.ID, "previous", r.PathValue("key"), "key", k.ID, "grace", grace.String(), "jkt", k.JKT)})
	writeJSON(w, http.StatusCreated, api.NewKey{Account: a.ID, Key: k, Secret: secret})
}

func (s *Server) apiDeleteKey(w http.ResponseWriter, r *http.Request) {
	a, ok := s.visibleAccount(w, r)
	if !ok {
		return
	}
	if s.writeAccountError(w, s.accounts.DeleteKey(a.ID, r.PathValue("key"))) {
		return
	}
	s.audit(r, change{action: "service_account.key.revoked", message: "service account key revoked", tenant: a.Tenant, target: audit.Target{Type: "service_account", ID: a.ID},
		summary: "Revoked key " + r.PathValue("key") + " of service account " + a.Name,
		details: details("account", a.ID, "key", r.PathValue("key"))})
	w.WriteHeader(http.StatusNoContent)
}

// binding returns the options that bind a new key to the DPoP key with
// thumbprint jkt, if it's set.
func binding(jkt string) []serviceaccount.CredentialOption {
	if jkt == "" {
		return nil
	}
	return []serviceaccount.CredentialOption{serviceaccount.BoundTo(jkt)}
}

// writeAccountError writes err, if there is one, as an API error, and
// reports whether it did.
func (s *Server) writeAccountError(w http.ResponseWriter, err error) bool {
	switch {
	case err == nil:
		return false
	case errors.Is(err, serviceaccount.ErrNotFound):
		writeError(w, http.StatusNotFound, err.Error())
	case errors.Is(err, serviceaccount.ErrInvalid):
		writeError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, serviceaccount.ErrLimit):
		writeError(w, http.StatusConflict, err.Error())
	default:
		s.logger.Error("admin: service accounts", slog.Any("error", err))
		writeError(w, http.StatusInternalServerError, "saving service accounts failed")
	}
	return true
}
