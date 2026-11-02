package alerts

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Standard Webhooks headers and formats
// (https://github.com/standard-webhooks/standard-webhooks/blob/main/spec/standard-webhooks.md).
const (
	// HeaderID, HeaderTimestamp, and HeaderSignature are the headers of a
	// signed webhook: the message's ID, when it was sent in seconds since
	// the Unix epoch, and its signatures.
	HeaderID        = "webhook-id"
	HeaderTimestamp = "webhook-timestamp"
	HeaderSignature = "webhook-signature"

	// SecretPrefix begins every webhook secret. What follows is the key,
	// base64 encoded.
	SecretPrefix = "whsec_"

	// DefaultTolerance is how far a webhook's timestamp may be from the
	// receiver's clock, as the specification recommends, so a captured
	// delivery can't be replayed later.
	DefaultTolerance = 5 * time.Minute
)

// secretBytes is the length of generated webhook keys: 256 bits, within
// the 24 to 64 bytes the specification recommends.
const secretBytes = 32

// newSecret returns a new webhook secret.
func newSecret() string {
	var b [secretBytes]byte
	_, _ = rand.Read(b[:]) // never fails
	return SecretPrefix + base64.StdEncoding.EncodeToString(b[:])
}

// secretKey returns the key of a webhook secret.
func secretKey(secret string) ([]byte, error) {
	enc, ok := strings.CutPrefix(secret, SecretPrefix)
	if !ok {
		return nil, errors.New("alerts: a webhook secret begins with " + SecretPrefix)
	}
	key, err := base64.StdEncoding.DecodeString(enc)
	if err != nil || len(key) == 0 {
		return nil, errors.New("alerts: a webhook secret's key must be base64")
	}
	return key, nil
}

// Sign returns the webhook-signature header of a webhook with id, sent at
// t, with body: "v1," and the base64 HMAC-SHA256, keyed with secret, of
// "id.timestamp.body".
func Sign(secret, id string, t time.Time, body []byte) (string, error) {
	key, err := secretKey(secret)
	if err != nil {
		return "", err
	}
	return "v1," + base64.StdEncoding.EncodeToString(mac(key, id, strconv.FormatInt(t.Unix(), 10), body)), nil
}

// mac returns the HMAC-SHA256 of "id.timestamp.body".
func mac(key []byte, id, timestamp string, body []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(id))
	h.Write([]byte{'.'})
	h.Write([]byte(timestamp))
	h.Write([]byte{'.'})
	h.Write(body)
	return h.Sum(nil)
}

// Verify checks a webhook's signature, as a receiver would: one of the
// space-separated signatures in its webhook-signature header must be a
// v1 signature of its ID, timestamp, and body, keyed with secret, and its
// timestamp within tolerance of now (or [DefaultTolerance], if zero).
// Signatures are compared in constant time.
func Verify(secret string, header http.Header, body []byte, now time.Time, tolerance time.Duration) error {
	key, err := secretKey(secret)
	if err != nil {
		return err
	}
	id, timestamp := header.Get(HeaderID), header.Get(HeaderTimestamp)
	if id == "" || timestamp == "" {
		return errors.New("alerts: missing webhook-id or webhook-timestamp")
	}
	secs, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return fmt.Errorf("alerts: invalid webhook-timestamp %q", timestamp)
	}
	if tolerance <= 0 {
		tolerance = DefaultTolerance
	}
	if d := now.Sub(time.Unix(secs, 0)); d > tolerance || d < -tolerance {
		return errors.New("alerts: webhook-timestamp is too old or too new")
	}

	want := mac(key, id, timestamp, body)
	for sig := range strings.FieldsSeq(header.Get(HeaderSignature)) {
		version, enc, ok := strings.Cut(sig, ",")
		if !ok || version != "v1" {
			continue
		}
		got, err := base64.StdEncoding.DecodeString(enc)
		if err == nil && hmac.Equal(got, want) {
			return nil
		}
	}
	return errors.New("alerts: no valid webhook signature")
}
