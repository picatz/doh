package webpush

import (
	"crypto/ecdh"
	"errors"
	"fmt"
	"net/url"
)

// MaxEndpointLength bounds a subscription's endpoint URL.
const MaxEndpointLength = 2048

// Subscription is a browser's push subscription, as its
// PushSubscription.toJSON() gives it.
type Subscription struct {
	// Endpoint is the push service's URL for this browser. Whoever knows
	// it can try to send to it, but the push service only accepts
	// messages signed with the VAPID key the browser subscribed with.
	Endpoint string `json:"endpoint"`

	// ExpirationTime is when the subscription ends, in milliseconds since
	// the Unix epoch, if the browser says; it's usually null.
	ExpirationTime *float64 `json:"expirationTime,omitempty"`

	// Keys are the browser's public key and authentication secret, as
	// base64url.
	Keys SubscriptionKeys `json:"keys"`
}

// SubscriptionKeys are a [Subscription]'s keys, as base64url.
type SubscriptionKeys struct {
	P256DH string `json:"p256dh"`
	Auth   string `json:"auth"`
}

// Decode checks s, returning its keys: an https endpoint of at most
// [MaxEndpointLength] characters, a p256dh key that's a point on P-256,
// and a 16-byte authentication secret. Which push services may be sent
// to is for the caller to decide.
func (s Subscription) Decode() (*url.URL, Keys, error) {
	if s.Endpoint == "" || len(s.Endpoint) > MaxEndpointLength {
		return nil, Keys{}, fmt.Errorf("webpush: a subscription's endpoint is a URL of at most %d characters", MaxEndpointLength)
	}
	u, err := url.Parse(s.Endpoint)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.Opaque != "" || u.User != nil {
		return nil, Keys{}, errors.New("webpush: a subscription's endpoint is an https URL")
	}
	p256dh, err := DecodeKey(s.Keys.P256DH)
	if err != nil || len(p256dh) != PublicKeySize {
		return nil, Keys{}, errors.New("webpush: a subscription's p256dh key is an uncompressed P-256 public key, base64url")
	}
	if _, err := ecdh.P256().NewPublicKey(p256dh); err != nil {
		return nil, Keys{}, errors.New("webpush: a subscription's p256dh key isn't a P-256 public key")
	}
	auth, err := DecodeKey(s.Keys.Auth)
	if err != nil || len(auth) != AuthSize {
		return nil, Keys{}, errors.New("webpush: a subscription's auth secret is 16 bytes, base64url")
	}
	return u, Keys{P256DH: p256dh, Auth: auth}, nil
}
