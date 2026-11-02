package serve

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"net/url"
	"path/filepath"
	"strconv"

	"github.com/picatz/doh/internal/alerts"
	"github.com/picatz/doh/internal/api"
	"github.com/picatz/doh/internal/blocklist"
	"github.com/picatz/doh/internal/filter"
)

// AlertsFile is where alert settings, destinations, and the devices each
// tenant has seen are kept in the data directory.
const AlertsFile = "alerts.json"

// configureAlerts starts the alerts engine: kept in the data directory,
// or in memory without one.
func (s *Server) configureAlerts() error {
	path := ""
	if s.config.DataDir != "" {
		path = filepath.Join(s.config.DataDir, AlertsFile)
	}
	var origin string
	if len(s.config.Admin.Origins) > 0 {
		origin = s.config.Admin.Origins[0]
	}
	engine, err := alerts.New(alerts.Options{
		Path:   path,
		Logger: s.logger,
		Origin: origin,
		ProfileName: func(id string) string {
			if engine := s.engine.Load(); engine != nil {
				if p := engine.Policy().Profile(id); p != nil {
					return p.Name
				}
			}
			return ""
		},
		Canary: filter.Canary,
	})
	if err != nil {
		return err
	}
	s.alerts = engine
	return nil
}

// listFailed reports a blocklist that failed to load, for the operator's
// alerts.
func (s *Server) listFailed(src blocklist.Source, err error) {
	if s.alerts != nil {
		s.alerts.ListFailed(src.Name, err)
	}
}

// alertsAccess wraps an alerts handler. Alerts send query names to their
// destinations, and a destination's URL, such as an ntfy topic, lets
// whoever knows it read them, so even reading them takes an admin, and
// service accounts can't, as they can't manage people.
func alertsAccess(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch who := principalOf(r); {
		case who.account != "":
			writeError(w, http.StatusForbidden, "service accounts can't manage alerts; use a person's sign-in, or the operator's token")
		case who.role != roleAdmin:
			writeError(w, http.StatusForbidden, "alerts send query names to their destinations, so managing them takes an admin")
		default:
			next(w, r)
		}
	}
}

// alertScope returns whose alerts r is about: the caller's tenant, or the
// operator's own, or, for the operator, the tenant ?tenant= names. Other
// tenants look like they don't exist.
func (s *Server) alertScope(w http.ResponseWriter, r *http.Request) (string, bool) {
	who := principalOf(r)
	tenant := r.URL.Query().Get("tenant")
	switch {
	case tenant == "" || tenant == who.tenant:
		return who.tenant, true
	case !who.operator(), s.engine.Load().Policy().Tenant(tenant) == nil:
		writeError(w, http.StatusNotFound, "no tenant "+strconv.Quote(tenant))
		return "", false
	}
	return tenant, true
}

// alertsView returns scope's alerts, as the API shows them.
func (s *Server) alertsView(scope string) api.Alerts {
	settings, dests, deliveries := s.alerts.Get(scope)
	return api.Alerts{Tenant: scope, Settings: settings, AvailableKinds: alerts.KindsFor(scope), Destinations: dests, Deliveries: deliveries}
}

func (s *Server) apiAlerts(w http.ResponseWriter, r *http.Request) {
	if scope, ok := s.alertScope(w, r); ok {
		writeJSON(w, http.StatusOK, s.alertsView(scope))
	}
}

func (s *Server) apiPatchAlerts(w http.ResponseWriter, r *http.Request) {
	scope, ok := s.alertScope(w, r)
	if !ok {
		return
	}
	if ct := r.Header.Get("Content-Type"); ct != "" {
		if mt, _, _ := mime.ParseMediaType(ct); mt != api.MergePatchType && mt != "application/json" {
			w.Header().Set("Accept-Patch", api.MergePatchType)
			writeError(w, http.StatusUnsupportedMediaType, "send a JSON merge patch ("+api.MergePatchType+")")
			return
		}
	}
	patch, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxAPIBody))
	if err != nil {
		writeError(w, http.StatusRequestEntityTooLarge, "request body too large")
		return
	}
	if !jsontext.Value(patch).IsValid() {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	current, _, _ := s.alerts.Get(scope)
	doc, err := json.Marshal(current)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	merged, err := mergePatch(doc, patch)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	var next alerts.Settings
	if err := json.Unmarshal(merged, &next, json.RejectUnknownMembers(true)); err != nil {
		writeError(w, http.StatusBadRequest, "invalid alert settings: "+err.Error())
		return
	}

	// Quiet hours need a time zone: the scope's profiles' own, if one has
	// one, or UTC, said explicitly so no one is surprised.
	if next.QuietHours != nil && next.TimeZone == "" {
		next.TimeZone = "UTC"
		for _, pr := range s.engine.Load().Policy().Profiles {
			if pr.Tenant == scope && pr.TimeZone != "" {
				next.TimeZone = pr.TimeZone
				break
			}
		}
	}

	if _, err := s.alerts.SetSettings(scope, next); s.writeAlertsError(w, err) {
		return
	}
	s.audit(r, "alert settings changed", alertsAttrs(r, scope)...)
	writeJSON(w, http.StatusOK, s.alertsView(scope))
}

func (s *Server) apiAddAlertDestination(w http.ResponseWriter, r *http.Request) {
	scope, ok := s.alertScope(w, r)
	if !ok {
		return
	}
	var req api.AlertDestinationRequest
	if !decode(w, r, &req) {
		return
	}
	d, secret, err := s.alerts.AddDestination(scope, alerts.NewDestination{Type: req.Type, URL: req.URL, Name: req.Name, CreatedBy: principalOf(r).by})
	if s.writeAlertsError(w, err) {
		return
	}
	host := ""
	if u, err := url.Parse(d.URL); err == nil {
		host = u.Host
	}
	s.audit(r, "alert destination added", append(alertsAttrs(r, scope), slog.String("destination", d.ID), slog.String("type", string(d.Type)), slog.String("host", host))...)
	w.Header().Set("Location", api.Prefix+"/alerts/destinations/"+d.ID)
	writeJSON(w, http.StatusCreated, api.NewAlertDestination{Destination: d, Secret: secret})
}

func (s *Server) apiDeleteAlertDestination(w http.ResponseWriter, r *http.Request) {
	scope, ok := s.alertScope(w, r)
	if !ok {
		return
	}
	id := r.PathValue("id")
	if s.writeAlertsError(w, s.alerts.RemoveDestination(scope, id)) {
		return
	}
	s.audit(r, "alert destination removed", append(alertsAttrs(r, scope), slog.String("destination", id))...)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) apiTestAlerts(w http.ResponseWriter, r *http.Request) {
	scope, ok := s.alertScope(w, r)
	if !ok {
		return
	}
	deliveries, err := s.alerts.Test(r.Context(), scope)
	if s.writeAlertsError(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, api.AlertTest{Deliveries: deliveries})
}

// alertsAttrs describes whose alerts r changed, for the audit log, when
// it isn't the caller's own.
func alertsAttrs(r *http.Request, scope string) []slog.Attr {
	if scope != principalOf(r).tenant {
		return []slog.Attr{slog.String("alerts_tenant", scope)}
	}
	return nil
}

// writeAlertsError writes err, if there is one, as an API error, and
// reports whether it did.
func (s *Server) writeAlertsError(w http.ResponseWriter, err error) bool {
	switch {
	case err == nil:
		return false
	case errors.Is(err, alerts.ErrNotFound):
		writeError(w, http.StatusNotFound, err.Error())
	case errors.Is(err, alerts.ErrInvalid):
		writeError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, alerts.ErrLimit), errors.Is(err, alerts.ErrNoDestinations):
		writeError(w, http.StatusConflict, err.Error())
	default:
		s.logger.Error("admin: alerts", slog.Any("error", err))
		writeError(w, http.StatusInternalServerError, "saving alerts failed")
	}
	return true
}

// forgetTenantAlerts removes a deleted tenant's alerts.
func (s *Server) forgetTenantAlerts(tenant string) {
	if err := s.alerts.ForgetScope(tenant); err != nil {
		s.logger.Error("admin: removing a deleted tenant's alerts", slog.String("tenant", tenant), slog.Any("error", err))
	}
}
