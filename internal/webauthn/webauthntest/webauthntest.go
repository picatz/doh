// Package webauthntest provides a virtual WebAuthn authenticator, for
// testing relying parties end to end without a browser or hardware.
//
// An [Authenticator] answers creation and request options as a browser and
// a platform authenticator together would: it creates discoverable ES256
// credentials with "none" attestation, signs assertions, and keeps a
// signature counter. It's for tests only; its keys live in memory.
package webauthntest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"github.com/picatz/cbor"
	"github.com/picatz/doh/internal/cose"
	"github.com/picatz/doh/internal/webauthn"
)

// Authenticator is a virtual authenticator holding any number of
// credentials. It's safe for concurrent use.
type Authenticator struct {
	mu          sync.Mutex
	credentials []*credential
}

type credential struct {
	id         []byte
	rpID       string
	userHandle []byte
	key        *ecdsa.PrivateKey
	count      uint32
}

// Response edits apply to a response before it's encoded, to forge or
// tamper with it in negative tests.
type Response struct {
	// Origin is the origin the client data claims.
	Origin string

	// ClientData, if set, edits the client data before it's encoded.
	ClientData func(map[string]any)

	// Signature, if set, edits an assertion's signature.
	Signature func([]byte) []byte
}

// Create answers creation options with a new credential, returning the
// RegistrationResponseJSON a browser would send.
func (a *Authenticator) Create(options webauthn.CreationOptions, r Response) ([]byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return nil, err
	}

	c := &credential{id: id, rpID: options.RP.ID, userHandle: append([]byte(nil), options.User.ID...), key: key}

	point, err := key.PublicKey.Bytes() // uncompressed: 0x04 || x || y
	if err != nil {
		return nil, err
	}
	coseKey, err := cbor.Marshal(map[int]any{
		1:  2, // kty: EC2
		3:  int(cose.AlgorithmES256),
		-1: 1, // crv: P-256
		-2: point[1:33],
		-3: point[33:],
	})
	if err != nil {
		return nil, err
	}

	var aaguid [16]byte
	attested := binary.BigEndian.AppendUint16(aaguid[:], uint16(len(id)))
	attested = append(append(attested, id...), coseKey...)
	authData := c.authData(webauthn.FlagAttestedCredentialData, attested)

	clientData, err := clientDataJSON("webauthn.create", options.Challenge, r)
	if err != nil {
		return nil, err
	}
	object, err := cbor.Marshal(map[string]any{"fmt": "none", "attStmt": map[string]any{}, "authData": authData})
	if err != nil {
		return nil, err
	}

	a.mu.Lock()
	a.credentials = append(a.credentials, c)
	a.mu.Unlock()

	return json.Marshal(map[string]any{
		"id": b64(id), "rawId": b64(id), "type": "public-key",
		"authenticatorAttachment": "platform",
		"clientExtensionResults":  map[string]any{"credProps": map[string]any{"rk": true}},
		"response": map[string]any{
			"clientDataJSON":     b64(clientData),
			"attestationObject":  b64(object),
			"authenticatorData":  b64(authData),
			"transports":         []string{"internal", "hybrid"},
			"publicKeyAlgorithm": int(cose.AlgorithmES256),
		},
	})
}

// ErrNoCredential reports that the authenticator holds no credential the
// options allow.
var ErrNoCredential = errors.New("webauthntest: no matching credential")

// Get answers request options with an assertion from the newest matching
// credential, returning the AuthenticationResponseJSON a browser would
// send.
func (a *Authenticator) Get(options webauthn.RequestOptions, r Response) ([]byte, error) {
	a.mu.Lock()
	c := a.find(options)
	if c == nil {
		a.mu.Unlock()
		return nil, ErrNoCredential
	}
	c.count++
	authData := c.authData(0, nil)
	a.mu.Unlock()

	clientData, err := clientDataJSON("webauthn.get", options.Challenge, r)
	if err != nil {
		return nil, err
	}
	hash := sha256.Sum256(clientData)
	digest := sha256.Sum256(append(append([]byte(nil), authData...), hash[:]...))
	signature, err := ecdsa.SignASN1(rand.Reader, c.key, digest[:])
	if err != nil {
		return nil, err
	}
	if r.Signature != nil {
		signature = r.Signature(signature)
	}

	return json.Marshal(map[string]any{
		"id": b64(c.id), "rawId": b64(c.id), "type": "public-key",
		"authenticatorAttachment": "platform",
		"clientExtensionResults":  map[string]any{},
		"response": map[string]any{
			"clientDataJSON":    b64(clientData),
			"authenticatorData": b64(authData),
			"signature":         b64(signature),
			"userHandle":        b64(c.userHandle),
		},
	})
}

// Len returns the number of credentials the authenticator holds.
func (a *Authenticator) Len() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.credentials)
}

// find returns the newest credential for the options' relying party that
// they allow, or nil. a.mu must be held.
func (a *Authenticator) find(options webauthn.RequestOptions) *credential {
	for i := len(a.credentials) - 1; i >= 0; i-- {
		c := a.credentials[i]
		if c.rpID != options.RPID {
			continue
		}
		if len(options.AllowCredentials) == 0 {
			return c
		}
		for _, allowed := range options.AllowCredentials {
			if string(allowed.ID) == string(c.id) {
				return c
			}
		}
	}
	return nil
}

// authData encodes authenticator data with user presence and verification.
func (c *credential) authData(flags webauthn.Flags, attested []byte) []byte {
	hash := sha256.Sum256([]byte(c.rpID))
	data := append([]byte(nil), hash[:]...)
	data = append(data, byte(flags|webauthn.FlagUserPresent|webauthn.FlagUserVerified))
	data = binary.BigEndian.AppendUint32(data, c.count)
	return append(data, attested...)
}

func clientDataJSON(typ string, challenge []byte, r Response) ([]byte, error) {
	if r.Origin == "" {
		return nil, fmt.Errorf("webauthntest: no origin")
	}
	m := map[string]any{"type": typ, "challenge": b64(challenge), "origin": r.Origin, "crossOrigin": false}
	if r.ClientData != nil {
		r.ClientData(m)
	}
	return json.Marshal(m)
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
