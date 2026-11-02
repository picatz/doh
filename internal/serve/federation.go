package serve

import (
	"errors"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/picatz/doh/internal/api"
	"github.com/picatz/doh/internal/ratelimit"
	"github.com/picatz/doh/internal/serviceaccount"
)

// maxExchangeBody bounds a token exchange request: room for an identity
// token, which is at most 16 KiB, and the other parameters.
const maxExchangeBody = 64 << 10

// newExchangeLimiter bounds failed token exchanges per client: a burst of
// twenty, then one every ten seconds. Automation that's set up right
// never fails, so this only slows down guessing and misconfigured loops.
func newExchangeLimiter() *ratelimit.Limiter {
	return &ratelimit.Limiter{Rate: 0.1, Burst: 20}
}

// OAuth 2.0 error codes ([RFC 6749, Section 5.2], [RFC 8693, Section
// 2.2.2]), and slow_down ([RFC 8628, Section 3.5]) for too many failures.
//
// [RFC 6749, Section 5.2]: https://www.rfc-editor.org/rfc/rfc6749.html#section-5.2
// [RFC 8693, Section 2.2.2]: https://www.rfc-editor.org/rfc/rfc8693.html#section-2.2.2
// [RFC 8628, Section 3.5]: https://www.rfc-editor.org/rfc/rfc8628.html#section-3.5
const (
	errInvalidRequest       = "invalid_request"
	errInvalidGrant         = "invalid_grant"
	errUnsupportedGrantType = "unsupported_grant_type"
	errInvalidTarget        = "invalid_target"
	errInvalidScope         = "invalid_scope"
	errSlowDown             = "slow_down"
	errServerError          = "server_error"
)

// writeOAuthError writes an [api.OAuthError].
func writeOAuthError(w http.ResponseWriter, status int, code, description string) {
	writeJSON(w, status, api.OAuthError{Error: code, Description: description})
}

// apiToken exchanges a workload's identity token for a service account's
// short-lived access token: an OAuth 2.0 token exchange
// ([RFC 8693, Section 2]). It needs no credential, since the identity
// token is the credential, so it's served outside [Server.authorize].
//
// Every refusal of the identity token itself, for whatever reason, is
// the same invalid_grant, so a caller can't learn which check failed, or
// whether an account exists; the reason is logged. Clients that fail too
// often are slowed down.
//
// [RFC 8693, Section 2]: https://www.rfc-editor.org/rfc/rfc8693.html#section-2
func (s *Server) apiToken(w http.ResponseWriter, r *http.Request) {
	// Token responses are never cached (RFC 6749, Section 5.1).
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")

	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeOAuthError(w, http.StatusMethodNotAllowed, errInvalidRequest, "send the token exchange as a POST")
		return
	}
	if !s.tokens.enabled() {
		writeError(w, http.StatusServiceUnavailable, "the admin API needs a data directory (--data-dir) or an admin token file")
		return
	}

	client := s.clientAddr(r).String()
	if s.exchangeLimiter.Limited(client) {
		w.Header().Set("Retry-After", "10")
		writeOAuthError(w, http.StatusTooManyRequests, errSlowDown, "too many failed token exchanges; wait a moment")
		return
	}
	fail := func(code, description, reason string, attrs ...slog.Attr) {
		s.exchangeLimiter.Allow(client)
		attrs = append(attrs, slog.String("reason", reason), slog.String("client", client))
		s.logger.LogAttrs(r.Context(), slog.LevelWarn, "admin: token exchange refused", attrs...)
		writeOAuthError(w, http.StatusBadRequest, code, description)
	}

	form, err := readExchangeForm(w, r)
	if err != nil {
		fail(errInvalidRequest, err.Error(), err.Error())
		return
	}

	// [RFC 8693, Section 2.1]: https://www.rfc-editor.org/rfc/rfc8693.html#section-2.1
	switch grant := form.Get("grant_type"); {
	case grant == "":
		fail(errInvalidRequest, "grant_type is required", "no grant type")
		return
	case grant != api.GrantTypeTokenExchange:
		fail(errUnsupportedGrantType, "only token exchange ("+api.GrantTypeTokenExchange+") is supported", "unsupported grant type", slog.String("grant_type", grant))
		return
	}
	subjectToken, subjectType := form.Get("subject_token"), form.Get("subject_token_type")
	switch {
	case subjectToken == "" || subjectType == "":
		fail(errInvalidRequest, "subject_token and subject_token_type are required", "no subject token")
		return
	case subjectType != api.TokenTypeJWT && subjectType != api.TokenTypeIDToken:
		fail(errInvalidRequest, "subject_token_type must be "+api.TokenTypeJWT+" or "+api.TokenTypeIDToken, "unsupported subject token type", slog.String("subject_token_type", subjectType))
		return
	case form.Has("actor_token") || form.Has("actor_token_type"):
		fail(errInvalidRequest, "delegation (actor_token) isn't supported", "actor token")
		return
	case form.Has("requested_token_type") && form.Get("requested_token_type") != api.TokenTypeAccessToken:
		fail(errInvalidRequest, "only "+api.TokenTypeAccessToken+" can be requested", "unsupported requested token type")
		return
	case form.Has("scope"):
		fail(errInvalidScope, "scopes aren't supported; a service account's role decides what it may do", "scope")
		return
	case form.Has("resource"):
		fail(errInvalidTarget, "name the service account to act as with audience, not resource", "resource")
		return
	}
	id := form.Get("audience")
	switch {
	case id == "":
		fail(errInvalidRequest, "audience is required: the ID of the service account to act as", "no audience")
		return
	case !serviceaccount.ValidAccountID(id):
		fail(errInvalidTarget, "audience must be a service account's ID", "malformed audience")
		return
	}

	// Unknown accounts, accounts whose tenant is gone, and identity tokens
	// no rule accepts are all the same refusal.
	refused := "the subject token wasn't accepted for this service account"
	account := slog.String("account", id)
	a, ok := s.accounts.Account(id)
	if !ok {
		fail(errInvalidGrant, refused, "no such service account", account)
		return
	}
	if a.Tenant != "" && s.engine.Load().Policy().Tenant(a.Tenant) == nil {
		fail(errInvalidGrant, refused, "the service account's tenant is gone", account)
		return
	}
	rule, claims, err := s.federation.Verify(r.Context(), a.Federation, subjectToken)
	if err != nil {
		fail(errInvalidGrant, refused, err.Error(), account)
		return
	}
	subject, _ := claims["sub"].(string)
	at, secret, err := s.accounts.IssueToken(a.ID, rule.ID, subject)
	switch {
	case errors.Is(err, serviceaccount.ErrNotFound):
		// The account or rule was removed meanwhile.
		fail(errInvalidGrant, refused, err.Error(), account)
		return
	case err != nil:
		s.logger.ErrorContext(r.Context(), "admin: issuing an access token", slog.Any("error", err))
		writeOAuthError(w, http.StatusInternalServerError, errServerError, "issuing the access token failed")
		return
	}

	s.logger.LogAttrs(r.Context(), slog.LevelInfo, "admin: access token issued", account, slog.String("rule", rule.ID),
		slog.String("issuer", rule.Issuer), slog.String("subject", subject), slog.Time("expires", at.Expires), slog.String("client", client))
	writeJSON(w, http.StatusOK, api.TokenResponse{
		AccessToken:     secret,
		IssuedTokenType: api.TokenTypeAccessToken,
		TokenType:       "Bearer",
		ExpiresIn:       int(at.Expires.Sub(at.Issued) / time.Second),
	})
}

// readExchangeForm reads a token exchange's form from r's body, which must be
// application/x-www-form-urlencoded, refusing repeated parameters
// ([RFC 6749, Section 3.2]).
//
// [RFC 6749, Section 3.2]: https://www.rfc-editor.org/rfc/rfc6749.html#section-3.2
func readExchangeForm(w http.ResponseWriter, r *http.Request) (url.Values, error) {
	if mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type")); mt != "application/x-www-form-urlencoded" {
		return nil, errors.New("send the parameters as application/x-www-form-urlencoded")
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxExchangeBody))
	if err != nil {
		return nil, errors.New("the request is too large")
	}
	form, err := url.ParseQuery(string(body))
	if err != nil {
		return nil, errors.New("the request isn't a valid form")
	}
	for name, values := range form {
		if len(values) > 1 {
			return nil, errors.New("the parameter " + strconv.Quote(name) + " is repeated")
		}
	}
	return form, nil
}

func (s *Server) apiTrustRules(w http.ResponseWriter, r *http.Request) {
	a, ok := s.visibleAccount(w, r)
	if !ok {
		return
	}
	rules := a.Federation
	if rules == nil {
		rules = []serviceaccount.TrustRule{}
	}
	writeJSON(w, http.StatusOK, api.TrustRules{Rules: rules})
}

func (s *Server) apiAddTrustRule(w http.ResponseWriter, r *http.Request) {
	a, ok := s.visibleAccount(w, r)
	if !ok {
		return
	}
	var req api.TrustRuleRequest
	if !decode(w, r, &req) {
		return
	}
	// The audience defaults to the server's own address, as browsers see
	// it; without one, the rule must say.
	if req.Audience == "" && len(s.config.Admin.Origins) > 0 {
		req.Audience = s.config.Admin.Origins[0]
	}

	rule, err := s.accounts.AddTrustRule(a.ID, serviceaccount.TrustRule{
		Issuer:        req.Issuer,
		JWKSURL:       req.JWKSURL,
		Audience:      req.Audience,
		Subject:       req.Subject,
		Claims:        req.Claims,
		TokenLifetime: req.TokenLifetime,
		CreatedBy:     principalOf(r).by,
	})
	if s.writeAccountError(w, err) {
		return
	}
	s.audit(r, "service account trust rule added", slog.String("account", a.ID), slog.String("rule", rule.ID),
		slog.String("issuer", rule.Issuer), slog.String("audience", rule.Audience), slog.String("subject", rule.Subject))
	w.Header().Set("Location", api.Prefix+"/service-accounts/"+a.ID+"/federation/"+rule.ID)
	writeJSON(w, http.StatusCreated, rule)
}

func (s *Server) apiDeleteTrustRule(w http.ResponseWriter, r *http.Request) {
	a, ok := s.visibleAccount(w, r)
	if !ok {
		return
	}
	if s.writeAccountError(w, s.accounts.DeleteTrustRule(a.ID, r.PathValue("rule"))) {
		return
	}
	s.audit(r, "service account trust rule removed", slog.String("account", a.ID), slog.String("rule", r.PathValue("rule")))
	w.WriteHeader(http.StatusNoContent)
}
