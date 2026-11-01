package serve

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"

	"github.com/picatz/doh/internal/api"
	"github.com/picatz/doh/internal/policy"
)

func (s *Server) apiListTenants(w http.ResponseWriter, r *http.Request) {
	pol := s.engine.Load().Policy()
	who := principalOf(r)
	tenants := slices.DeleteFunc(slices.Clone(pol.Tenants), func(t policy.Tenant) bool {
		return !who.operator() && t.ID != who.tenant
	})
	if tenants == nil {
		tenants = []policy.Tenant{}
	}
	w.Header().Set("ETag", pol.ETag())
	writeJSON(w, http.StatusOK, api.Tenants{Tenants: tenants})
}

func (s *Server) apiCreateTenant(w http.ResponseWriter, r *http.Request) {
	var t policy.Tenant
	if !decode(w, r, &t) {
		return
	}
	next, ok := s.updatePolicy(w, r, func(p *policy.Policy) error {
		if p.Tenant(t.ID) != nil {
			return fmt.Errorf("tenant %q already exists", t.ID)
		}
		p.Tenants = append(p.Tenants, t)
		return nil
	})
	if ok {
		w.Header().Set("Location", api.Prefix+"/tenants/"+t.ID)
		writeJSON(w, http.StatusCreated, next.Tenant(t.ID))
	}
}

// apiPatchTenant applies a JSON merge patch ([RFC 7396]) to a tenant.
//
// [RFC 7396]: https://www.rfc-editor.org/rfc/rfc7396.html
func (s *Server) apiPatchTenant(w http.ResponseWriter, r *http.Request) {
	patch, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxAPIBody))
	if err != nil {
		writeError(w, http.StatusRequestEntityTooLarge, "request body too large")
		return
	}
	if !jsontext.Value(patch).IsValid() {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	id := r.PathValue("id")
	next, ok := s.updatePolicy(w, r, func(p *policy.Policy) error {
		t := p.Tenant(id)
		if t == nil {
			return fmt.Errorf("no tenant %q: %w", id, errNotFound)
		}
		doc, err := json.Marshal(t)
		if err != nil {
			return err
		}
		merged, err := mergePatch(doc, patch)
		if err != nil {
			return err
		}
		var patched policy.Tenant
		if err := json.Unmarshal(merged, &patched, json.RejectUnknownMembers(true)); err != nil {
			return fmt.Errorf("invalid tenant: %w", err)
		}
		if patched.ID != id {
			return errors.New("a tenant's id can't be changed")
		}
		*t = patched
		return nil
	})
	if ok {
		writeJSON(w, http.StatusOK, next.Tenant(id))
	}
}

// apiDeleteTenant removes a tenant that has no profiles left, and its
// people, ending their sessions.
func (s *Server) apiDeleteTenant(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	_, ok := s.updatePolicy(w, r, func(p *policy.Policy) error {
		i := slices.IndexFunc(p.Tenants, func(t policy.Tenant) bool { return t.ID == id })
		if i < 0 {
			return fmt.Errorf("no tenant %q: %w", id, errNotFound)
		}
		if n := len(slices.DeleteFunc(slices.Clone(p.Profiles), func(pr policy.Profile) bool { return pr.Tenant != id })); n > 0 {
			return fmt.Errorf("tenant %q still has %d profiles; delete or move them first", id, n)
		}
		p.Tenants = slices.Delete(p.Tenants, i, i+1)
		return nil
	})
	if !ok {
		return
	}

	if svc := s.signin.Load(); svc != nil {
		for _, person := range svc.People() {
			if person.Tenant == id {
				_ = svc.DeletePerson(person.ID)
			}
		}
	}
	w.WriteHeader(http.StatusNoContent)
}
