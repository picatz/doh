package webpush

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json/v2"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/picatz/doh/internal/atomicfile"
)

// TokenLifetime is how long the VAPID tokens [VAPIDKey.Authorization]
// makes are valid: well within the 24 hours RFC 8292 allows, so a clock
// a little fast doesn't make push services refuse them.
const TokenLifetime = 12 * time.Hour

// maxTokenLifetime is the longest RFC 8292 allows ([Section 2]).
//
// [Section 2]: https://www.rfc-editor.org/rfc/rfc8292.html#section-2
const maxTokenLifetime = 24 * time.Hour

// VAPIDKey is an application server's key: an ECDSA P-256 key pair that
// signs the tokens push services check, and whose public key browsers
// subscribe with ([RFC 8292]).
//
// [RFC 8292]: https://www.rfc-editor.org/rfc/rfc8292.html
type VAPIDKey struct {
	private *ecdsa.PrivateKey
}

// GenerateVAPIDKey returns a new key.
func GenerateVAPIDKey() (*VAPIDKey, error) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return &VAPIDKey{private: k}, nil
}

// pemType is the PEM block a key is kept in: PKCS #8.
const pemType = "PRIVATE KEY"

// LoadOrCreateVAPIDKey returns the key kept at path, generating and
// saving one, readable only by its owner, if there's none yet.
//
// Replacing the file replaces the key. Browsers subscribed with the old
// one then can't be sent to, so each must subscribe again.
func LoadOrCreateVAPIDKey(path string) (*VAPIDKey, error) {
	b, err := os.ReadFile(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		k, err := GenerateVAPIDKey()
		if err != nil {
			return nil, err
		}
		der, err := x509.MarshalPKCS8PrivateKey(k.private)
		if err != nil {
			return nil, err
		}
		if err := atomicfile.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: pemType, Bytes: der}), 0o600); err != nil {
			return nil, fmt.Errorf("webpush: saving the VAPID key: %w", err)
		}
		return k, nil
	case err != nil:
		return nil, fmt.Errorf("webpush: reading the VAPID key: %w", err)
	}

	block, _ := pem.Decode(b)
	if block == nil || block.Type != pemType {
		return nil, fmt.Errorf("webpush: %s isn't a PEM %s", path, pemType)
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("webpush: %s: invalid key", path) // never the parser's details
	}
	ec, ok := key.(*ecdsa.PrivateKey)
	if !ok || ec.Curve != elliptic.P256() {
		return nil, fmt.Errorf("webpush: %s isn't a P-256 key", path)
	}
	return &VAPIDKey{private: ec}, nil
}

// PublicKey returns the key's public key, uncompressed, as browsers
// take it for PushManager.subscribe's applicationServerKey.
func (k *VAPIDKey) PublicKey() []byte {
	b, _ := k.private.PublicKey.Bytes() // never fails for a P-256 key
	return b
}

// PublicKeyString returns [VAPIDKey.PublicKey] as unpadded base64url.
func (k *VAPIDKey) PublicKeyString() string { return encodeKey(k.PublicKey()) }

// Authorization returns the Authorization header for a push to
// endpoint, sent at now: "vapid t=<token>, k=<public key>"
// ([RFC 8292, Section 3]). The token's audience is the endpoint's
// origin, it expires after [TokenLifetime], and subject, if not empty,
// is how the push service may reach the server's operator: a mailto: or
// https: URL.
//
// [RFC 8292, Section 3]: https://www.rfc-editor.org/rfc/rfc8292.html#section-3
func (k *VAPIDKey) Authorization(endpoint, subject string, now time.Time) (string, error) {
	aud, err := Audience(endpoint)
	if err != nil {
		return "", err
	}
	token, err := k.token(aud, now.Add(TokenLifetime), subject)
	if err != nil {
		return "", err
	}
	return "vapid t=" + token + ", k=" + k.PublicKeyString(), nil
}

// Audience returns a push endpoint's origin, a VAPID token's audience.
func Audience(endpoint string) (string, error) {
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return "", errors.New("webpush: a push endpoint is an https URL")
	}
	return u.Scheme + "://" + u.Host, nil
}

// jwtHeader is every token's header, as RFC 8292's example has it.
const jwtHeader = `{"typ":"JWT","alg":"ES256"}`

// claims are a VAPID token's claims, in the order RFC 8292's example
// has them.
type claims struct {
	Aud string `json:"aud"`
	Exp int64  `json:"exp"`
	Sub string `json:"sub,omitempty"`
}

// token returns a signed JWT for aud, expiring at exp.
func (k *VAPIDKey) token(aud string, exp time.Time, sub string) (string, error) {
	if sub != "" && !strings.HasPrefix(sub, "mailto:") && !strings.HasPrefix(sub, "https://") {
		return "", errors.New("webpush: a VAPID subject is a mailto: or https: URL")
	}
	body, err := json.Marshal(claims{Aud: aud, Exp: exp.Unix(), Sub: sub})
	if err != nil {
		return "", err
	}
	input := encodeKey([]byte(jwtHeader)) + "." + encodeKey(body)
	sum := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, k.private, sum[:])
	if err != nil {
		return "", err
	}
	// JWS's ES256 signature is r and s, 32 bytes each ([RFC 7518,
	// Section 3.4]), not ASN.1.
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return input + "." + encodeKey(sig), nil
}

// VerifyAuthorization checks a push request's Authorization header as a
// push service would: a vapid token, signed by the key it names, for
// endpoint's origin, not expired at now nor expiring more than 24 hours
// after it. It returns the key, uncompressed. doh only sends pushes;
// this is for tests, and fake push services.
func VerifyAuthorization(header, endpoint string, now time.Time) ([]byte, error) {
	rest, ok := strings.CutPrefix(header, "vapid ")
	if !ok {
		return nil, errors.New("webpush: not the vapid scheme")
	}
	var token, key string
	for part := range strings.SplitSeq(rest, ",") {
		name, value, _ := strings.Cut(strings.TrimSpace(part), "=")
		switch name {
		case "t":
			token = value
		case "k":
			key = value
		}
	}
	pubBytes, err := DecodeKey(key)
	if err != nil {
		return nil, errors.New("webpush: invalid k")
	}
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), pubBytes)
	if err != nil {
		return nil, errors.New("webpush: invalid k")
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("webpush: invalid t")
	}
	header0, err := DecodeKey(parts[0])
	if err != nil {
		return nil, errors.New("webpush: invalid t")
	}
	var h struct {
		Typ string `json:"typ"`
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(header0, &h); err != nil || h.Alg != "ES256" {
		return nil, errors.New("webpush: the token isn't ES256")
	}
	sig, err := DecodeKey(parts[2])
	if err != nil || len(sig) != 64 {
		return nil, errors.New("webpush: invalid signature")
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if !ecdsa.Verify(pub, sum[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		return nil, errors.New("webpush: invalid signature")
	}

	body, err := DecodeKey(parts[1])
	if err != nil {
		return nil, errors.New("webpush: invalid t")
	}
	var c claims
	if err := json.Unmarshal(body, &c); err != nil {
		return nil, errors.New("webpush: invalid claims")
	}
	aud, err := Audience(endpoint)
	if err != nil {
		return nil, err
	}
	exp := time.Unix(c.Exp, 0)
	switch {
	case c.Aud != aud:
		return nil, errors.New("webpush: the token is for " + strconv.Quote(c.Aud))
	case !now.Before(exp):
		return nil, errors.New("webpush: the token has expired")
	case exp.Sub(now) > maxTokenLifetime:
		return nil, errors.New("webpush: the token expires more than 24 hours from now")
	}
	return pubBytes, nil
}
