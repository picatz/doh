package serviceaccount

import (
	"cmp"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"maps"
	"net"
	"net/url"
	"slices"
	"strings"
	"time"
)

// Workload identity federation lets automation authenticate without a
// stored secret. A service account trusts tokens that an identity
// provider, such as GitHub Actions or Kubernetes, issues to a workload,
// as its trust rules describe. A workload exchanges such a token for a
// short-lived access token, which [Store.AuthenticateToken] accepts.
//
// This package keeps the rules, matches verified claims against them, and
// keeps the access tokens. Verifying a token's signature, and fetching
// the provider's keys, is left to the caller.

// Federation limits.
const (
	// MaxTrustRules bounds an account's trust rules.
	MaxTrustRules = 5

	// MaxRuleClaims bounds the extra claims a rule requires.
	MaxRuleClaims = 10

	// DefaultTokenLifetime is how long an access token lasts when its
	// rule doesn't say, and MinTokenLifetime and MaxTokenLifetime bound
	// what a rule may say.
	DefaultTokenLifetime = 15 * time.Minute
	MinTokenLifetime     = time.Minute
	MaxTokenLifetime     = time.Hour

	// MaxAccessTokens bounds the access tokens kept at once. Beyond it,
	// the oldest are forgotten, and stop working.
	MaxAccessTokens = 10_000

	// maxRuleField bounds the length of a rule's URLs, audience, subject,
	// and claim values; maxClaimName that of claim names.
	maxRuleField = 512
	maxClaimName = 64
)

// AccessTokenPrefix begins every access token, so a leaked one is easy to
// recognize and to scan for.
const AccessTokenPrefix = "doh_at_"

// reservedClaims are the registered claims a rule can't require through
// [TrustRule.Claims]: the issuer, audience, and subject have fields of
// their own, and the rest are checked by verification.
var reservedClaims = []string{"iss", "sub", "aud", "exp", "nbf", "iat", "jti"}

// TrustRule describes the identity tokens a service account accepts in
// exchange for an access token: those issued by Issuer, for Audience, to
// Subject, with Claims.
type TrustRule struct {
	// ID identifies the rule. It's generated, and safe to show.
	ID string `json:"id"`

	// Issuer is the identity provider's issuer identifier, such as
	// "https://token.actions.githubusercontent.com". A token's "iss"
	// must equal it exactly. It's an https URL; rules of the operator's
	// own accounts may also use http to a loopback address.
	Issuer string `json:"issuer"`

	// JWKSURL is where the provider publishes its signing keys. If empty,
	// it's found with OpenID Connect discovery, at Issuer's
	// /.well-known/openid-configuration, and must be on Issuer's host.
	JWKSURL string `json:"jwks_url,omitempty"`

	// Audience is what a token's "aud" must name, exactly. Providers let
	// a workload choose it, so it's best set to something that means
	// this server, such as its URL.
	Audience string `json:"audience"`

	// Subject is what a token's "sub" must equal. A trailing "*" after a
	// "/" or ":" matches anything non-empty in its place, such as
	// "repo:octo/app:ref:refs/heads/*"; the part before it must have at
	// least two separators, so it can't match every subject of a
	// provider's namespace, such as every repository with "repo:*".
	Subject string `json:"subject"`

	// Claims are other string claims a token must have, each equal
	// exactly, such as {"repository_id": "123456"}.
	Claims map[string]string `json:"claims,omitempty"`

	// TokenLifetime is how many seconds an access token lasts: 60 to
	// 3600. Zero means [DefaultTokenLifetime].
	TokenLifetime int `json:"token_lifetime,omitzero"`

	// Created is when the rule was added, and CreatedBy who added it.
	Created   time.Time `json:"created"`
	CreatedBy string    `json:"created_by,omitempty"`
}

// Lifetime returns how long r's access tokens last.
func (r TrustRule) Lifetime() time.Duration {
	if r.TokenLifetime == 0 {
		return DefaultTokenLifetime
	}
	return time.Duration(r.TokenLifetime) * time.Second
}

// Matches reports whether verified claims satisfy r's subject and
// claims. The issuer and audience are for verification to check.
func (r TrustRule) Matches(claims map[string]any) bool {
	sub, _ := claims["sub"].(string)
	if !r.matchSubject(sub) {
		return false
	}
	for name, want := range r.Claims {
		if got, ok := claims[name].(string); !ok || got != want {
			return false
		}
	}
	return true
}

// matchSubject reports whether sub is r's subject, or matches its
// trailing wildcard.
func (r TrustRule) matchSubject(sub string) bool {
	if prefix, ok := strings.CutSuffix(r.Subject, "*"); ok {
		rest, found := strings.CutPrefix(sub, prefix)
		return found && rest != ""
	}
	return sub != "" && sub == r.Subject
}

// validate checks a rule's fields. Loopback http URLs are allowed only if
// loopback is.
func (r TrustRule) validate(loopback bool) error {
	if err := checkURL("issuer", r.Issuer, loopback, false); err != nil {
		return err
	}
	if r.JWKSURL != "" {
		if err := checkURL("JWKS URL", r.JWKSURL, loopback, true); err != nil {
			return err
		}
	}
	if err := checkField("audience", r.Audience); err != nil {
		return err
	}
	if err := checkSubject(r.Subject); err != nil {
		return err
	}
	if len(r.Claims) > MaxRuleClaims {
		return fmt.Errorf("%w: a rule may require at most %d claims", ErrInvalid, MaxRuleClaims)
	}
	for name, value := range r.Claims {
		if name == "" || len(name) > maxClaimName || !printable(name) {
			return fmt.Errorf("%w: claim names are 1 to %d printable characters", ErrInvalid, maxClaimName)
		}
		if slices.Contains(reservedClaims, name) {
			return fmt.Errorf("%w: the %q claim can't be required this way; use the rule's issuer, audience, or subject", ErrInvalid, name)
		}
		if err := checkField("claim "+name, value); err != nil {
			return err
		}
	}
	if r.TokenLifetime != 0 && (r.TokenLifetime < int(MinTokenLifetime/time.Second) || r.TokenLifetime > int(MaxTokenLifetime/time.Second)) {
		return fmt.Errorf("%w: an access token lasts %d to %d seconds", ErrInvalid, int(MinTokenLifetime/time.Second), int(MaxTokenLifetime/time.Second))
	}
	return nil
}

// checkURL checks that raw is an absolute https URL, or http to a
// loopback host if loopback, without credentials or a fragment, and
// without a query unless query.
func checkURL(what, raw string, loopback, query bool) error {
	if raw == "" {
		return fmt.Errorf("%w: the %s is required", ErrInvalid, what)
	}
	if len(raw) > maxRuleField {
		return fmt.Errorf("%w: the %s is at most %d characters", ErrInvalid, what, maxRuleField)
	}
	u, err := url.Parse(raw)
	switch {
	case err != nil || u.Host == "" || u.Opaque != "":
		return fmt.Errorf("%w: the %s %q isn't an absolute URL", ErrInvalid, what, raw)
	case u.User != nil:
		return fmt.Errorf("%w: the %s can't include a user name or password", ErrInvalid, what)
	case u.Fragment != "" || strings.Contains(raw, "#"):
		return fmt.Errorf("%w: the %s can't include a fragment", ErrInvalid, what)
	case !query && (u.RawQuery != "" || u.ForceQuery):
		return fmt.Errorf("%w: the %s can't include a query", ErrInvalid, what)
	case u.Scheme == "https":
		return nil
	case u.Scheme == "http" && loopback && IsLoopback(u.Hostname()):
		return nil
	case u.Scheme == "http" && IsLoopback(u.Hostname()):
		return fmt.Errorf("%w: the %s must use https; only the operator's service accounts may use http to a loopback address", ErrInvalid, what)
	default:
		return fmt.Errorf("%w: the %s must use https", ErrInvalid, what)
	}
}

// IsLoopback reports whether host, without a port, is localhost or a
// loopback address.
func IsLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// checkField checks a required field of 1 to maxRuleField printable
// characters, without surrounding spaces, since it's compared exactly.
func checkField(what, v string) error {
	switch {
	case v == "":
		return fmt.Errorf("%w: the %s is required", ErrInvalid, what)
	case len(v) > maxRuleField || !printable(v):
		return fmt.Errorf("%w: the %s is 1 to %d printable characters", ErrInvalid, what, maxRuleField)
	case strings.TrimSpace(v) != v:
		return fmt.Errorf("%w: the %s can't begin or end with spaces", ErrInvalid, what)
	}
	return nil
}

// checkSubject checks a rule's subject, and its wildcard if it has one.
func checkSubject(sub string) error {
	if err := checkField("subject", sub); err != nil {
		return err
	}
	prefix, wild := strings.CutSuffix(sub, "*")
	switch {
	case strings.Contains(prefix, "*"):
		return fmt.Errorf("%w: a subject may have one \"*\", at its end", ErrInvalid)
	case !wild:
		return nil
	case !strings.HasSuffix(prefix, "/") && !strings.HasSuffix(prefix, ":"):
		return fmt.Errorf("%w: a subject's \"*\" must follow a \"/\" or \":\", such as repo:octo/app:ref:refs/heads/*", ErrInvalid)
	case strings.Count(prefix, "/")+strings.Count(prefix, ":") < 2:
		return fmt.Errorf("%w: the subject %q would match too much; name at least an owner, such as repo:octo/*", ErrInvalid, sub)
	}
	return nil
}

// printable reports whether s has no control characters.
func printable(s string) bool {
	return !strings.ContainsFunc(s, func(r rune) bool { return r < ' ' || r == 0x7f })
}

// AddTrustRule adds a trust rule to an account, and returns it with its
// ID. The rule's ID and creation time are set by the store.
func (s *Store) AddTrustRule(account string, r TrustRule) (TrustRule, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a := s.find(account)
	if a == nil {
		return TrustRule{}, fmt.Errorf("service account %q: %w", account, ErrNotFound)
	}
	// Only the operator's accounts may fetch from loopback addresses: a
	// tenant's rules could otherwise make the server probe its own
	// machine.
	if err := r.validate(a.Tenant == ""); err != nil {
		return TrustRule{}, err
	}
	if len(a.Federation) >= MaxTrustRules {
		return TrustRule{}, fmt.Errorf("%w: at most %d trust rules per service account; remove one first", ErrLimit, MaxTrustRules)
	}

	id, err := newRuleID()
	if err != nil {
		return TrustRule{}, err
	}
	r.ID, r.Created, r.Claims = id, s.now().UTC(), maps.Clone(r.Claims)
	before := a.Federation
	rules := append(slices.Clone(a.Federation), r)
	if err := s.commit(func() { a.Federation = rules }, func() { a.Federation = before }); err != nil {
		return TrustRule{}, err
	}
	return cloneRule(r), nil
}

// DeleteTrustRule removes a trust rule from an account, revoking the
// access tokens it issued at once.
func (s *Store) DeleteTrustRule(account, rule string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	a := s.find(account)
	if a == nil {
		return fmt.Errorf("service account %q: %w", account, ErrNotFound)
	}
	i := slices.IndexFunc(a.Federation, func(r TrustRule) bool { return r.ID == rule })
	if i < 0 {
		return fmt.Errorf("trust rule %q: %w", rule, ErrNotFound)
	}
	before := a.Federation
	rules := slices.Delete(slices.Clone(a.Federation), i, i+1)
	if err := s.commit(func() { a.Federation = rules }, func() { a.Federation = before }); err != nil {
		return err
	}
	s.pruneTokens()
	return nil
}

// AccessToken is a short-lived credential issued in exchange for a
// workload's identity token. Access tokens are kept only in memory, as
// SHA-256 digests, so they don't survive a restart.
type AccessToken struct {
	// Account is the service account it acts as, and Rule the trust rule
	// that issued it.
	Account string
	Rule    string

	// Issuer and Subject identify the workload it was issued to.
	Issuer  string
	Subject string

	// Issued and Expires are when it was issued, and when it stops
	// working.
	Issued  time.Time
	Expires time.Time
}

// IssueToken issues an access token for account under rule, to subject,
// lasting the rule's token lifetime, and returns it with its secret,
// which isn't kept.
//
// The caller has verified that the rule accepts the workload's token.
func (s *Store) IssueToken(account, rule, subject string) (AccessToken, string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return AccessToken{}, "", err
	}
	secret := AccessTokenPrefix + base64.RawURLEncoding.EncodeToString(b[:])

	s.mu.Lock()
	defer s.mu.Unlock()
	a := s.find(account)
	if a == nil {
		return AccessToken{}, "", fmt.Errorf("service account %q: %w", account, ErrNotFound)
	}
	i := slices.IndexFunc(a.Federation, func(r TrustRule) bool { return r.ID == rule })
	if i < 0 {
		return AccessToken{}, "", fmt.Errorf("trust rule %q: %w", rule, ErrNotFound)
	}
	r := a.Federation[i]

	now := s.now().UTC()
	t := &AccessToken{Account: a.ID, Rule: r.ID, Issuer: r.Issuer, Subject: subject, Issued: now, Expires: now.Add(r.Lifetime())}
	s.makeRoom(now)
	s.tokens[sha256.Sum256([]byte(secret))] = t
	return *t, secret, nil
}

// AuthenticateToken returns the account and access token a secret
// belongs to, if the token hasn't expired, and its account and rule
// still exist.
func (s *Store) AuthenticateToken(secret string) (Account, AccessToken, bool) {
	if !validAccessToken(secret) {
		return Account{}, AccessToken{}, false
	}
	sum := sha256.Sum256([]byte(secret))
	now := s.now()

	s.mu.Lock()
	defer s.mu.Unlock()
	t := s.tokens[sum]
	if t == nil {
		return Account{}, AccessToken{}, false
	}
	a := s.find(t.Account)
	if !now.Before(t.Expires) || a == nil || !slices.ContainsFunc(a.Federation, func(r TrustRule) bool { return r.ID == t.Rule }) {
		delete(s.tokens, sum)
		return Account{}, AccessToken{}, false
	}
	return s.view(a), *t, true
}

// makeRoom forgets expired access tokens, then the oldest, while the
// store has as many as it may keep. s.mu must be held.
func (s *Store) makeRoom(now time.Time) {
	limit := cmp.Or(s.maxTokens, MaxAccessTokens)
	if len(s.tokens) < limit {
		return
	}
	maps.DeleteFunc(s.tokens, func(_ [sha256.Size]byte, t *AccessToken) bool { return !now.Before(t.Expires) })
	for len(s.tokens) >= limit {
		var oldest [sha256.Size]byte
		var at time.Time
		for k, t := range s.tokens {
			if at.IsZero() || t.Issued.Before(at) {
				oldest, at = k, t.Issued
			}
		}
		delete(s.tokens, oldest)
	}
}

// pruneTokens forgets the access tokens whose account or rule is gone.
// s.mu must be held.
func (s *Store) pruneTokens() {
	live := make(map[[2]string]bool)
	for _, a := range s.accounts {
		for _, r := range a.Federation {
			live[[2]string{a.ID, r.ID}] = true
		}
	}
	maps.DeleteFunc(s.tokens, func(_ [sha256.Size]byte, t *AccessToken) bool { return !live[[2]string{t.Account, t.Rule}] })
}

// validAccessToken reports whether secret is shaped like an access token.
func validAccessToken(secret string) bool {
	rest, ok := strings.CutPrefix(secret, AccessTokenPrefix)
	if !ok || len(rest) != 43 {
		return false
	}
	_, err := base64.RawURLEncoding.DecodeString(rest)
	return err == nil
}

// IsAccessToken reports whether token looks like an access token, as
// opposed to another kind of credential.
func IsAccessToken(token string) bool { return strings.HasPrefix(token, AccessTokenPrefix) }

// newRuleID returns a random rule ID: 16 hex characters, 64 bits.
func newRuleID() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// cloneRule copies r, so callers can't change the store's claims.
func cloneRule(r TrustRule) TrustRule {
	r.Claims = maps.Clone(r.Claims)
	return r
}
