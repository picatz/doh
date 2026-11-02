package serve

import (
	"cmp"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/picatz/doh/internal/alerts"
	"github.com/picatz/doh/internal/audit"
	"github.com/picatz/doh/internal/httpsec"
	"github.com/picatz/doh/internal/ratelimit"
)

// The pages an alert email links to: one confirms an address, with the
// code it was sent, and one unsubscribes it, with its token. They're for
// whoever reads the email, who needn't be able to sign in, so the code or
// token is the only proof. Opening a link changes nothing: mail scanners
// and previews open links, so each page asks for a button press, a POST,
// first. A one-click unsubscribe (RFC 8058) POSTs directly.

// alertPageCSP is the policy of the alert pages: the setup page's, but
// with forms that post to themselves.
var alertPageCSP = strings.Replace(setupCSP, "form-action 'none'", "form-action 'self'", 1)

// newAlertPageLimiter bounds wrong codes and tokens per client: 20, then
// one every three minutes.
func newAlertPageLimiter() *ratelimit.Limiter {
	return &ratelimit.Limiter{Rate: 20.0 / 3600, Burst: 20}
}

// alertPageData fills the alerts-done template.
type alertPageData struct {
	Title, Text, Address string
}

// alertPage writes an alert page's headers, and reports whether the
// client may try another code.
func (s *Server) alertPage(w http.ResponseWriter, r *http.Request) bool {
	h := w.Header()
	httpsec.Page(h, r, alertPageCSP)
	h.Set("Cache-Control", "no-store")
	h.Set("X-Robots-Tag", "noindex")
	h.Set("Content-Type", "text/html; charset=utf-8")
	if s.alertPageLimiter.Limited(s.clientAddr(r).String()) {
		w.Header().Set("Retry-After", "180")
		w.WriteHeader(http.StatusTooManyRequests)
		_ = setupTemplate.ExecuteTemplate(w, "alerts-invalid", "Too many tries from here. Wait a few minutes, then try again.")
		return false
	}
	return true
}

// alertPageFailed records a wrong code or token, and says why it didn't
// work.
func (s *Server) alertPageFailed(w http.ResponseWriter, r *http.Request, err error) {
	s.alertPageLimiter.Allow(s.clientAddr(r).String())
	status, why := http.StatusNotFound, "It may have been used already, or have been mistyped. Ask whoever set up the alerts to add your address again."
	switch {
	case errors.Is(err, alerts.ErrExpired):
		status, why = http.StatusGone, "It has expired. Ask whoever set up the alerts to add your address again."
	case !errors.Is(err, alerts.ErrNotFound):
		s.logger.Error("alerts: page", slog.Any("error", err))
		status, why = http.StatusInternalServerError, "Something went wrong. Try again in a minute."
	}
	w.WriteHeader(status)
	_ = setupTemplate.ExecuteTemplate(w, "alerts-invalid", why)
}

// alertConfirmPage asks to confirm an address (GET), and confirms it
// (POST).
func (s *Server) alertConfirmPage(w http.ResponseWriter, r *http.Request) {
	if !s.alertPage(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		_ = setupTemplate.ExecuteTemplate(w, "alerts-confirm", nil)
		return
	}
	scope, d, err := s.alerts.ConfirmAny(r.PathValue("code"))
	if err != nil {
		s.alertPageFailed(w, r, err)
		return
	}
	s.auditBy(r, recipient("email link", scope), change{action: "alerts.destination.confirmed", message: "alert destination confirmed", tenant: scope,
		target:  audit.Target{Type: "alert_destination", ID: d.ID},
		summary: "Confirmed email alert destination " + cmp.Or(d.Name, d.ID) + " from its email",
		details: details("destination", d.ID, "type", string(d.Type))})
	_ = setupTemplate.ExecuteTemplate(w, "alerts-done", alertPageData{
		Title: "You're set", Text: "doh's alerts will come to", Address: strings.TrimPrefix(d.URL, "mailto:"),
	})
}

// alertUnsubscribePage asks to unsubscribe an address (GET), and
// unsubscribes it (POST, from the page or a mail client's one-click
// unsubscribe).
func (s *Server) alertUnsubscribePage(w http.ResponseWriter, r *http.Request) {
	if !s.alertPage(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		_ = setupTemplate.ExecuteTemplate(w, "alerts-unsubscribe", nil)
		return
	}
	scope, d, err := s.alerts.Unsubscribe(r.PathValue("token"))
	if err != nil {
		s.alertPageFailed(w, r, err)
		return
	}
	s.auditBy(r, recipient("unsubscribe link", scope), change{action: "alerts.destination.removed", message: "alert destination removed", tenant: scope,
		target:  audit.Target{Type: "alert_destination", ID: d.ID},
		summary: "Unsubscribed email alert destination " + cmp.Or(d.Name, d.ID) + " from its email",
		details: details("destination", d.ID, "type", string(d.Type))})
	_ = setupTemplate.ExecuteTemplate(w, "alerts-done", alertPageData{
		Title: "Unsubscribed", Text: "No more alerts will be sent to", Address: strings.TrimPrefix(d.URL, "mailto:"),
	})
}

// recipient is whoever followed a link sent to an alert address of
// scope's, by way of the link named by.
func recipient(by, scope string) principal {
	return principal{by: by, tenant: scope, actor: actorOf(audit.ActorRecipient, "", "email recipient", scope, "")}
}
