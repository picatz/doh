package serve

import (
	"cmp"
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"net/mail"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/picatz/doh/internal/alerts"
	"github.com/picatz/doh/internal/api"
	"github.com/picatz/doh/internal/audit"
	"github.com/picatz/doh/internal/blocklist"
	"github.com/picatz/doh/internal/filter"
)

// AlertsFile is where alert settings and destinations are kept in the
// data directory. The devices each tenant has seen, which it kept before
// too, are in the state database.
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
	mail, err := s.config.Alerts.SMTP.mailConfig()
	if err != nil {
		return err
	}
	pushKey := ""
	if s.config.DataDir != "" {
		pushKey = filepath.Join(s.config.DataDir, PushKeyFile)
	}
	var memory alerts.Memory
	if s.stateDB != nil {
		memory = s.stateDB.AlertMemory()
	}
	engine, err := alerts.New(alerts.Options{
		Path:        path,
		Memory:      memory,
		Logger:      s.logger,
		Origin:      origin,
		Mail:        mail,
		PushKeyPath: pushKey,
		PushSubject: pushSubject(origin, s.config.Alerts.SMTP.From),
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

// PushKeyFile is where the VAPID key that signs Web Push messages is
// kept in the data directory, generated the first time a browser
// subscribes.
const PushKeyFile = "push-vapid.pem"

// pushSubject is how push services may reach the operator: the web UI's
// origin, if it's https, or the address alerts are emailed from.
func pushSubject(origin, from string) string {
	if strings.HasPrefix(origin, "https://") {
		return origin
	}
	if a, err := mail.ParseAddress(from); err == nil {
		return "mailto:" + a.Address
	}
	return ""
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
	return api.Alerts{Tenant: scope, Settings: settings, AvailableKinds: alerts.KindsFor(scope), AvailableTypes: s.alerts.AvailableTypes(),
		Destinations: dests, Deliveries: deliveries}
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
	s.audit(r, change{action: "alerts.settings.updated", message: "alert settings changed", tenant: scope,
		target: audit.Target{Type: "alerts"}, summary: "Changed alert settings", details: alertSettingsDetails(next)})
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
	d, secret, err := s.alerts.AddDestination(r.Context(), scope, alerts.NewDestination{
		Type: req.Type, URL: req.URL, Address: req.Address, Subscription: req.Subscription,
		Name: req.Name, CreatedBy: principalOf(r).by,
	})
	if s.writeAlertsError(w, err) {
		return
	}
	// The audit log names where alerts go, by host or email domain, not
	// whom: addresses and push endpoints are personal.
	host := ""
	if u, err := url.Parse(d.URL); err == nil {
		host = u.Host
		if u.Scheme == "mailto" {
			_, host, _ = strings.Cut(u.Opaque, "@")
		}
	}
	s.audit(r, change{action: "alerts.destination.added", message: "alert destination added", tenant: scope,
		target:  audit.Target{Type: "alert_destination", ID: d.ID},
		summary: "Added " + string(d.Type) + " alert destination " + cmp.Or(d.Name, host),
		details: details("destination", d.ID, "type", string(d.Type), "host", host, "name", d.Name, "state", string(d.State))})
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
	s.audit(r, change{action: "alerts.destination.removed", message: "alert destination removed", tenant: scope,
		target: audit.Target{Type: "alert_destination", ID: id}, summary: "Removed alert destination " + id, details: details("destination", id)})
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) apiConfirmAlerts(w http.ResponseWriter, r *http.Request) {
	scope, ok := s.alertScope(w, r)
	if !ok {
		return
	}
	var req api.AlertConfirmRequest
	if !decode(w, r, &req) {
		return
	}
	d, err := s.alerts.Confirm(scope, req.Code)
	if s.writeAlertsError(w, err) {
		return
	}
	s.audit(r, change{action: "alerts.destination.confirmed", message: "alert destination confirmed", tenant: scope,
		target:  audit.Target{Type: "alert_destination", ID: d.ID},
		summary: "Confirmed " + string(d.Type) + " alert destination " + cmp.Or(d.Name, d.ID),
		details: details("destination", d.ID, "type", string(d.Type))})
	writeJSON(w, http.StatusOK, d)
}

func (s *Server) apiPushKey(w http.ResponseWriter, r *http.Request) {
	key, err := s.alerts.PushKey()
	if err != nil {
		s.logger.Error("admin: alerts push key", slog.Any("error", err))
		writeError(w, http.StatusInternalServerError, "the push key couldn't be loaded")
		return
	}
	writeJSON(w, http.StatusOK, api.PushKey{PublicKey: key})
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

// alertSettingsDetails describes alert settings for the audit trail.
func alertSettingsDetails(s alerts.Settings) map[string]string {
	kinds := make([]string, len(s.Kinds))
	for i, k := range s.Kinds {
		kinds[i] = string(k)
	}
	quiet := ""
	if s.QuietHours != nil {
		quiet = s.QuietHours.Start + "-" + s.QuietHours.End
	}
	return details("kinds", strings.Join(kinds, ", "), "quiet_hours", quiet, "time_zone", s.TimeZone)
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
	case errors.Is(err, alerts.ErrLimit), errors.Is(err, alerts.ErrNoDestinations), errors.Is(err, alerts.ErrUnavailable):
		writeError(w, http.StatusConflict, err.Error())
	case errors.Is(err, alerts.ErrExpired):
		writeError(w, http.StatusGone, err.Error())
	case errors.Is(err, alerts.ErrRateLimited):
		w.Header().Set("Retry-After", "3600")
		writeError(w, http.StatusTooManyRequests, err.Error())
	case errors.Is(err, alerts.ErrNotSent):
		writeError(w, http.StatusBadGateway, err.Error())
	default:
		s.logger.Error("admin: alerts", slog.Any("error", err))
		writeError(w, http.StatusInternalServerError, "saving alerts failed")
	}
	return true
}

// forgetTenantAlerts removes a deleted tenant's alerts.
func (s *Server) forgetTenantAlerts(ctx context.Context, tenant string) {
	if err := s.alerts.ForgetScope(ctx, tenant); err != nil {
		s.logger.Error("admin: removing a deleted tenant's alerts", slog.String("tenant", tenant), slog.Any("error", err))
	}
}
