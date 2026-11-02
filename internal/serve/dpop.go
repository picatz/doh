package serve

import (
	"encoding/json/v2"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/picatz/doh/internal/serviceaccount"
	"github.com/picatz/jose/pkg/dpop"
	"github.com/picatz/jose/pkg/dpop/dpophttp"
	"github.com/picatz/jose/pkg/jwa"
	"github.com/picatz/jose/pkg/jws"
)

// DPoP ([RFC 9449]) binds a service account key, or an exchanged access
// token, to a key its client holds: each request carries a proof, a JWT
// signed by that key for the request's method and URL, so a copied
// credential is useless without the private key.
//
// [RFC 9449]: https://www.rfc-editor.org/rfc/rfc9449.html

// Proof limits ([RFC 9449, Section 11.1]).
//
// [RFC 9449, Section 11.1]: https://www.rfc-editor.org/rfc/rfc9449.html#section-11.1
const (
	// proofMaxAge is how long ago a proof's iat may be, and proofLeeway
	// how far ahead, for clocks that disagree. A proof is accepted once,
	// within that window.
	proofMaxAge = time.Minute
	proofLeeway = time.Minute

	// maxProofs bounds the proof IDs (jti) each replay cache remembers,
	// for proofMaxAge and proofLeeway. Beyond it, proofs are refused
	// until older ones expire, rather than letting one be replayed.
	maxProofs = 50_000
)

// proofAlgorithms are the algorithms proofs may be signed with: never
// none or HMAC, which [dpop.Verifier] always refuses too.
var proofAlgorithms = []jwa.Algorithm{jwa.ES256, jwa.EdDSA, jwa.RS256}

// dpopChallenge is the DPoP authentication challenge
// ([RFC 9449, Section 7.1]), without an error.
//
// [RFC 9449, Section 7.1]: https://www.rfc-editor.org/rfc/rfc9449.html#section-7.1
var dpopChallenge = func() string {
	algs := make([]string, len(proofAlgorithms))
	for i, a := range proofAlgorithms {
		algs[i] = string(a)
	}
	return `DPoP realm="doh", algs="` + strings.Join(algs, " ") + `"`
}()

// Error codes for refused credentials ([RFC 6750, Section 3.1] and
// [RFC 9449, Section 7.1]).
//
// [RFC 6750, Section 3.1]: https://www.rfc-editor.org/rfc/rfc6750.html#section-3.1
// [RFC 9449, Section 7.1]: https://www.rfc-editor.org/rfc/rfc9449.html#section-7.1
const (
	errInvalidToken = "invalid_token"
	errInvalidProof = dpop.ErrorInvalidProof
)

// newProofVerifier returns a verifier of DPoP proofs, remembering those it
// accepts in replay, which must be its own.
func newProofVerifier(replay dpop.ReplayCache) *dpop.Verifier {
	return &dpop.Verifier{
		Algorithms: proofAlgorithms,
		MaxAge:     proofMaxAge,
		Leeway:     proofLeeway,
		Replay:     replay,
	}
}

// refusal is why a credential was refused: an error code, and the
// authentication scheme whose challenge carries it.
type refusal struct {
	dpop bool
	code string
}

// challenge sets the WWW-Authenticate challenges of a 401: Bearer and
// DPoP, with refused's error on the one it names.
func challenge(w http.ResponseWriter, refused refusal) {
	bearer, dp := `Bearer realm="doh"`, dpopChallenge
	switch {
	case refused.code == "":
	case refused.dpop:
		dp += `, error="` + refused.code + `"`
	default:
		bearer += `, error="` + refused.code + `"`
	}
	w.Header().Add("WWW-Authenticate", bearer)
	w.Header().Add("WWW-Authenticate", dp)
}

// credential returns the Authorization header's credential, and whether
// it uses the DPoP scheme rather than Bearer ([RFC 9449, Section 7.1]).
// Schemes are case-insensitive. ok is false without either scheme; with
// one, the credential may be empty, and is then refused.
//
// [RFC 9449, Section 7.1]: https://www.rfc-editor.org/rfc/rfc9449.html#section-7.1
func credential(r *http.Request) (token string, isDPoP, ok bool) {
	scheme, token, found := strings.Cut(r.Header.Get("Authorization"), " ")
	switch {
	case !found:
		return "", false, false
	case strings.EqualFold(scheme, "Bearer"):
		return strings.TrimSpace(token), false, true
	case strings.EqualFold(scheme, dpop.AuthorizationScheme):
		return strings.TrimSpace(token), true, true
	}
	return "", false, false
}

// proofURIs returns the URIs a proof for r may name as its htu
// ([RFC 9449, Section 4.3]), without the query: r's path at each of the
// admin listener's configured origins, since behind a proxy the request
// says little about the URL the client used. Without origins, or for a
// request to a loopback address, such as through an SSH tunnel, it's
// also the URL r itself names, with its Host and whether it came over
// TLS.
//
// [RFC 9449, Section 4.3]: https://www.rfc-editor.org/rfc/rfc9449.html#section-4.3
func (s *Server) proofURIs(r *http.Request) []string {
	path := r.URL.EscapedPath()
	uris := make([]string, 0, len(s.config.Admin.Origins)+1)
	for _, o := range s.config.Admin.Origins {
		uris = append(uris, strings.TrimSuffix(o, "/")+path)
	}
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if len(uris) == 0 || serviceaccount.IsLoopback(strings.Trim(host, "[]")) {
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		uris = append(uris, scheme+"://"+r.Host+path)
	}
	return uris
}

// proofURI returns which of [Server.proofURIs] to check proof's htu
// against: the one it names, if any, or else the first, which then fails
// verification. The proof's claims are only peeked at here, to choose;
// [dpop.Verifier.Verify] checks them.
func (s *Server) proofURI(r *http.Request, proof string) string {
	uris := s.proofURIs(r)
	if len(uris) == 1 || len(proof) > dpop.DefaultMaxSize {
		return uris[0]
	}
	signed, err := jws.Parse(proof)
	if err != nil {
		return uris[0]
	}
	var claims struct {
		HTU string `json:"htu"`
	}
	if json.Unmarshal(signed.Payload, &claims) != nil {
		return uris[0]
	}
	htu, err := dpop.TargetURI(claims.HTU)
	if err != nil {
		return uris[0]
	}
	for _, u := range uris {
		if t, err := dpop.TargetURI(u); err == nil && t == htu {
			return u
		}
	}
	return uris[0]
}

// verifyProof checks r's DPoP proof with v, following
// [RFC 9449, Section 4.3]: for r's method and URL, and if they're set,
// for an access token (ath) and a bound key's thumbprint (jkt). It
// returns the verified proof. Errors say which check failed, for the log
// only.
//
// [RFC 9449, Section 4.3]: https://www.rfc-editor.org/rfc/rfc9449.html#section-4.3
func (s *Server) verifyProof(v *dpop.Verifier, r *http.Request, token, jkt string) (*dpop.Proof, error) {
	proof, err := dpophttp.FromRequest(r)
	if err != nil {
		return nil, err
	}
	return v.Verify(r.Context(), proof, dpop.Request{
		Method:      r.Method,
		URI:         s.proofURI(r, proof),
		AccessToken: token,
		Thumbprint:  jkt,
	})
}

// checkBinding enforces a credential's DPoP binding, jkt, if it has one:
// a bound credential must come with the DPoP scheme and a valid proof by
// its key, and an unbound one as a bearer token ([RFC 9449, Section 7.1]).
// It returns why the credential is refused, if it is, logging the reason.
//
// [RFC 9449, Section 7.1]: https://www.rfc-editor.org/rfc/rfc9449.html#section-7.1
func (s *Server) checkBinding(r *http.Request, token, jkt string, isDPoP bool, by string) (refusal, bool) {
	var reason error
	refused := refusal{dpop: true, code: errInvalidToken}
	switch {
	case jkt == "" && isDPoP:
		reason = errors.New("an unbound credential sent with the DPoP scheme")
	case jkt == "":
		return refusal{}, true
	case !isDPoP:
		reason = errors.New("a DPoP-bound credential sent as a bearer token")
	default:
		if _, err := s.verifyProof(s.proofs, r, token, jkt); err != nil {
			reason, refused.code = err, errInvalidProof
		} else {
			return refusal{}, true
		}
	}
	s.logger.LogAttrs(r.Context(), slog.LevelWarn, "admin: credential refused", slog.String("by", by),
		slog.String("reason", reason.Error()), slog.String("client", s.clientAddr(r).String()))
	return refused, false
}
