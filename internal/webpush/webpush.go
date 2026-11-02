// Package webpush sends Web Push messages without a push vendor's
// account: it encrypts them for a browser's subscription as
// [RFC 8291] describes, in the aes128gcm content coding of [RFC 8188],
// and signs requests with a VAPID key ([RFC 8292]), an ES256 JSON Web
// Token that tells the push service which server is sending.
//
// It's written with the standard library alone: crypto/ecdh for the key
// agreement, crypto/hkdf for the key derivation, AES-GCM for the
// encryption, and crypto/ecdsa for the token's signature. Each step is
// tested against RFC 8291's Appendix A and RFC 8292's example token.
//
// [RFC 8291]: https://www.rfc-editor.org/rfc/rfc8291.html
// [RFC 8188]: https://www.rfc-editor.org/rfc/rfc8188.html
// [RFC 8292]: https://www.rfc-editor.org/rfc/rfc8292.html
package webpush

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

// Sizes of the values a subscription and a message carry.
const (
	// PublicKeySize is the size of an uncompressed P-256 public key, as
	// a subscription's p256dh key and a VAPID key are given.
	PublicKeySize = 65

	// AuthSize is the size of a subscription's authentication secret.
	AuthSize = 16

	// SaltSize is the size of the random salt each message is encrypted
	// with.
	SaltSize = 16

	// RecordSize is the record size messages are encrypted with: one
	// record, the most push services take ([RFC 8291, Section 4]).
	//
	// [RFC 8291, Section 4]: https://www.rfc-editor.org/rfc/rfc8291.html#section-4
	RecordSize = 4096

	// headerSize is the size of an aes128gcm header with the sender's
	// public key as its key ID: salt, record size, ID length, and ID.
	headerSize = SaltSize + 4 + 1 + PublicKeySize

	// tagSize is AES-GCM's authentication tag.
	tagSize = 16

	// MaxPlaintext is the largest message that fits in one record:
	// what's left after the header, the padding delimiter, and the tag.
	MaxPlaintext = RecordSize - headerSize - 1 - tagSize
)

// ErrTooLarge reports a message larger than [MaxPlaintext].
var ErrTooLarge = errors.New("webpush: message too large")

// Keys are a subscription's keys, as a browser's PushSubscription gives
// them: the browser's public key, and the secret only it and the
// subscriber know.
type Keys struct {
	// P256DH is the browser's uncompressed P-256 public key.
	P256DH []byte

	// Auth is the 16-byte authentication secret.
	Auth []byte
}

// Encrypt encrypts plaintext for a subscription with keys, returning a
// message body in the aes128gcm content coding, with a new key pair and
// salt of its own.
func Encrypt(keys Keys, plaintext []byte) ([]byte, error) {
	sender, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	salt := make([]byte, SaltSize)
	_, _ = rand.Read(salt) // never fails
	return encrypt(keys, plaintext, sender, salt)
}

// encrypt is [Encrypt] with the sender's key pair and the salt given, so
// tests can reproduce RFC 8291's example exactly.
func encrypt(keys Keys, plaintext []byte, sender *ecdh.PrivateKey, salt []byte) ([]byte, error) {
	if len(plaintext) > MaxPlaintext {
		return nil, fmt.Errorf("%w: %d bytes, at most %d", ErrTooLarge, len(plaintext), MaxPlaintext)
	}
	if len(salt) != SaltSize {
		return nil, errors.New("webpush: the salt must be 16 bytes")
	}
	cek, nonce, err := deriveKeys(keys, sender, sender.PublicKey().Bytes(), salt, true)
	if err != nil {
		return nil, err
	}
	gcm, err := newGCM(cek)
	if err != nil {
		return nil, err
	}

	out := make([]byte, 0, headerSize+len(plaintext)+1+tagSize)
	out = append(out, salt...)
	out = binary.BigEndian.AppendUint32(out, RecordSize)
	out = append(out, PublicKeySize)
	out = append(out, sender.PublicKey().Bytes()...)

	// One record, the last: its plaintext ends with the delimiter 0x02
	// and no padding ([RFC 8188, Section 2]). The first record's nonce is
	// NONCE itself, XORed with a sequence number of 0.
	record := append(append(make([]byte, 0, len(plaintext)+1), plaintext...), 0x02)
	return gcm.Seal(out, nonce, record, nil), nil
}

// Decrypt decrypts a message body in the aes128gcm content coding, as
// the browser holding the subscription's private key and authentication
// secret would. doh only sends messages; Decrypt is for tests, and for
// checking what's sent.
func Decrypt(body []byte, private *ecdh.PrivateKey, auth []byte) ([]byte, error) {
	if len(body) < headerSize+tagSize+1 {
		return nil, errors.New("webpush: message too short")
	}
	salt := body[:SaltSize]
	rs := binary.BigEndian.Uint32(body[SaltSize:])
	idLen := int(body[SaltSize+4])
	if idLen != PublicKeySize || rs < tagSize+2 {
		return nil, errors.New("webpush: invalid aes128gcm header")
	}
	senderPub := body[SaltSize+5 : headerSize]
	ciphertext := body[headerSize:]
	if uint32(len(ciphertext)) > rs {
		return nil, errors.New("webpush: more than one record")
	}

	cek, nonce, err := deriveKeys(Keys{P256DH: private.PublicKey().Bytes(), Auth: auth}, private, senderPub, salt, false)
	if err != nil {
		return nil, err
	}
	gcm, err := newGCM(cek)
	if err != nil {
		return nil, err
	}
	plain, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, errors.New("webpush: message doesn't decrypt")
	}
	// Strip the padding, then the last record's delimiter.
	plain = []byte(strings.TrimRight(string(plain), "\x00"))
	if len(plain) == 0 || plain[len(plain)-1] != 0x02 {
		return nil, errors.New("webpush: no last-record delimiter")
	}
	return plain[:len(plain)-1], nil
}

// deriveKeys derives a message's content encryption key and nonce
// ([RFC 8291, Section 3.4]). local is the side doing the work: the
// sender, when sending, with peer its public key; or the browser, when
// receiving, with peer the sender's public key.
//
// [RFC 8291, Section 3.4]: https://www.rfc-editor.org/rfc/rfc8291.html#section-3.4
func deriveKeys(keys Keys, local *ecdh.PrivateKey, senderPub, salt []byte, sending bool) (cek, nonce []byte, err error) {
	if len(keys.Auth) != AuthSize {
		return nil, nil, errors.New("webpush: the authentication secret must be 16 bytes")
	}
	ua, err := ecdh.P256().NewPublicKey(keys.P256DH)
	if err != nil {
		return nil, nil, errors.New("webpush: invalid p256dh key")
	}
	peer := ua
	if !sending {
		if peer, err = ecdh.P256().NewPublicKey(senderPub); err != nil {
			return nil, nil, errors.New("webpush: invalid sender key")
		}
	}
	secret, err := local.ECDH(peer)
	if err != nil {
		return nil, nil, err
	}

	// PRK_key = HMAC-SHA-256(auth_secret, ecdh_secret)
	// key_info = "WebPush: info" || 0x00 || ua_public || as_public
	// IKM = HMAC-SHA-256(PRK_key, key_info || 0x01)
	prkKey, err := hkdf.Extract(sha256.New, secret, keys.Auth)
	if err != nil {
		return nil, nil, err
	}
	keyInfo := "WebPush: info\x00" + string(ua.Bytes()) + string(senderPub)
	ikm, err := hkdf.Expand(sha256.New, prkKey, keyInfo, 32)
	if err != nil {
		return nil, nil, err
	}

	// PRK = HMAC-SHA-256(salt, IKM), and from it, RFC 8188's key and
	// nonce.
	prk, err := hkdf.Extract(sha256.New, ikm, salt)
	if err != nil {
		return nil, nil, err
	}
	if cek, err = hkdf.Expand(sha256.New, prk, "Content-Encoding: aes128gcm\x00", 16); err != nil {
		return nil, nil, err
	}
	if nonce, err = hkdf.Expand(sha256.New, prk, "Content-Encoding: nonce\x00", 12); err != nil {
		return nil, nil, err
	}
	return cek, nonce, nil
}

// newGCM returns AES-128-GCM keyed with cek.
func newGCM(cek []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(cek)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// DecodeKey decodes a base64url value, as subscriptions and VAPID keys
// are given, with or without padding.
func DecodeKey(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
}

// encodeKey encodes b as unpadded base64url.
func encodeKey(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
