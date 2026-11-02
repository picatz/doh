package webpush

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// b64 decodes RFC 8291's base64url, which wraps with spaces.
func b64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := DecodeKey(strings.Join(strings.Fields(s), ""))
	if err != nil {
		t.Fatalf("decoding %q: %v", s, err)
	}
	return b
}

// RFC 8291, Section 5 and Appendix A.
const (
	rfcPlaintext  = "When I grow up, I want to be a watermelon"
	rfcASPublic   = "BP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIg Dll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8"
	rfcASPrivate  = "yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw"
	rfcUAPublic   = "BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcx aOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4"
	rfcUAPrivate  = "q1dXpw3UpT5VOmu_cf_v6ih07Aems3njxI-JWgLcM94"
	rfcSalt       = "DGv6ra1nlYgDCS1FRnbzlw"
	rfcAuthSecret = "BTBZMqHH6r4Tts7J_aSIgg"

	rfcECDHSecret = "kyrL1jIIOHEzg3sM2ZWRHDRB62YACZhhSlknJ672kSs"
	rfcPRKKey     = "Snr3JMxaHVDXHWJn5wdC52WjpCtd2EIEGBykDcZW32k"
	rfcKeyInfo    = "V2ViUHVzaDogaW5mbwAEJXGyvs3942BVG q8e0PTNNmwR zr5VX4m8t7GGpTM5FzFo7OLr4BhZe9MEebhuPI-OztV3 ylkYfpJGmQ22ggCLDgT-M_SrDepxkU21WCP3O1SUj0Ew bZIHMtu5pZpTKGSCIA5Zent7wmC6HCJ5mFgJkuk5cwAv MBKiiujwa7t45ewP"
	rfcIKM        = "S4lYMb_L0FxCeq0WhDx813KgSYqU26kOyzWUdsXYyrg"
	rfcPRK        = "09_eUZGrsvxChDCGRCdkLiDXrReGOEVeSCdCcPBSJSc"
	rfcCEK        = "oIhVW04MRdy2XN9CiKLxTg"
	rfcNonce      = "4h_95klXJ5E_qnoN"
	rfcHeader     = "DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z 9KsN6nGRTbVYI_c7VJSPQTBtkgcy27ml mlMoZIIgDll6e3vCYLocInmYWAmS6Tlz AC8wEqKK6PBru3jl7A8"
	rfcCiphertext = "8pfeW0KbunFT06SuDKoJH9Ql87S1QUrd irN6GcG7sFz1y1sqLgVi1VhjVkHsUoEs bI_0LpXMuGvnzQ"
	rfcBody       = "DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27ml mlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A_yl95bQpu6cVPT pK4Mqgkf1CXztLVBSt2Ks3oZwbuwXPXLWyouBWLVWGNWQexSgSxsj_Qulcy4a-fN"
)

func rfcKeys(t *testing.T) (sender, ua *ecdh.PrivateKey, keys Keys, salt []byte) {
	t.Helper()
	sender, err := ecdh.P256().NewPrivateKey(b64(t, rfcASPrivate))
	if err != nil {
		t.Fatal(err)
	}
	ua, err = ecdh.P256().NewPrivateKey(b64(t, rfcUAPrivate))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sender.PublicKey().Bytes(), b64(t, rfcASPublic)) || !bytes.Equal(ua.PublicKey().Bytes(), b64(t, rfcUAPublic)) {
		t.Fatal("the RFC's private keys don't give its public keys")
	}
	return sender, ua, Keys{P256DH: b64(t, rfcUAPublic), Auth: b64(t, rfcAuthSecret)}, b64(t, rfcSalt)
}

// TestEncrypt_RFC8291Example reproduces RFC 8291's example message
// exactly, with its sender key pair and salt.
func TestEncrypt_RFC8291Example(t *testing.T) {
	sender, _, keys, salt := rfcKeys(t)
	got, err := encrypt(keys, []byte(rfcPlaintext), sender, salt)
	if err != nil {
		t.Fatal(err)
	}
	if want := b64(t, rfcBody); !bytes.Equal(got, want) {
		t.Fatalf("body =\n%s\nwant\n%s", encodeKey(got), encodeKey(want))
	}
	if want := b64(t, rfcHeader); !bytes.Equal(got[:headerSize], want) {
		t.Errorf("header = %s, want %s", encodeKey(got[:headerSize]), encodeKey(want))
	}
	if want := b64(t, rfcCiphertext); !bytes.Equal(got[headerSize:], want) {
		t.Errorf("ciphertext = %s, want %s", encodeKey(got[headerSize:]), encodeKey(want))
	}
}

// TestDeriveKeys_RFC8291Intermediates checks each of Appendix A's
// intermediate values, so a mistake shows where it is.
func TestDeriveKeys_RFC8291Intermediates(t *testing.T) {
	sender, ua, keys, salt := rfcKeys(t)

	secret, err := sender.ECDH(ua.PublicKey())
	if err != nil || !bytes.Equal(secret, b64(t, rfcECDHSecret)) {
		t.Fatalf("ecdh_secret = %s, %v", encodeKey(secret), err)
	}
	prkKey, _ := hkdf.Extract(sha256.New, secret, keys.Auth)
	if !bytes.Equal(prkKey, b64(t, rfcPRKKey)) {
		t.Errorf("PRK_key = %s", encodeKey(prkKey))
	}
	keyInfo := "WebPush: info\x00" + string(keys.P256DH) + string(sender.PublicKey().Bytes())
	if !bytes.Equal([]byte(keyInfo), b64(t, rfcKeyInfo)) {
		t.Errorf("key_info = %s", encodeKey([]byte(keyInfo)))
	}
	ikm, _ := hkdf.Expand(sha256.New, prkKey, keyInfo, 32)
	if !bytes.Equal(ikm, b64(t, rfcIKM)) {
		t.Errorf("IKM = %s", encodeKey(ikm))
	}
	prk, _ := hkdf.Extract(sha256.New, ikm, salt)
	if !bytes.Equal(prk, b64(t, rfcPRK)) {
		t.Errorf("PRK = %s", encodeKey(prk))
	}

	// What the package derives, sending and receiving.
	for _, sending := range []bool{true, false} {
		local, k := sender, keys
		if !sending {
			local, k = ua, Keys{P256DH: ua.PublicKey().Bytes(), Auth: keys.Auth}
		}
		cek, nonce, err := deriveKeys(k, local, sender.PublicKey().Bytes(), salt, sending)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(cek, b64(t, rfcCEK)) || !bytes.Equal(nonce, b64(t, rfcNonce)) {
			t.Errorf("sending %v: CEK = %s, NONCE = %s", sending, encodeKey(cek), encodeKey(nonce))
		}
	}
}

func TestDecrypt_RFC8291Example(t *testing.T) {
	_, ua, keys, _ := rfcKeys(t)
	got, err := Decrypt(b64(t, rfcBody), ua, keys.Auth)
	if err != nil || string(got) != rfcPlaintext {
		t.Fatalf("Decrypt = %q, %v", got, err)
	}
}

func TestEncrypt_RoundTripAndFreshness(t *testing.T) {
	ua, err := ecdh.P256().GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	auth := bytes.Repeat([]byte{7}, AuthSize)
	keys := Keys{P256DH: ua.PublicKey().Bytes(), Auth: auth}
	msg := []byte(`{"title":"Threat blocked on kids-ipad ✓"}`)

	a, err := Encrypt(keys, msg)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := Encrypt(keys, msg)
	if bytes.Equal(a[:headerSize], b[:headerSize]) {
		t.Error("two messages share a salt and sender key")
	}
	if got, err := Decrypt(a, ua, auth); err != nil || !bytes.Equal(got, msg) {
		t.Fatalf("round trip = %q, %v", got, err)
	}

	// Negative: the wrong secret, the wrong key, and a changed salt,
	// sender key, or ciphertext. (The record size isn't authenticated;
	// RFC 8188 uses it only to split records.)
	if _, err := Decrypt(a, ua, bytes.Repeat([]byte{8}, AuthSize)); err == nil {
		t.Error("decrypted with the wrong auth secret")
	}
	other, _ := ecdh.P256().GenerateKey(nil)
	if _, err := Decrypt(a, other, auth); err == nil {
		t.Error("decrypted with the wrong key")
	}
	for _, i := range []int{0, SaltSize - 1, headerSize - 1, headerSize, len(a) - 1} {
		c := bytes.Clone(a)
		c[i] ^= 1
		if _, err := Decrypt(c, ua, auth); err == nil {
			t.Errorf("decrypted with byte %d changed", i)
		}
	}
}

func TestEncrypt_Bounds(t *testing.T) {
	ua, _ := ecdh.P256().GenerateKey(nil)
	keys := Keys{P256DH: ua.PublicKey().Bytes(), Auth: make([]byte, AuthSize)}
	body, err := Encrypt(keys, make([]byte, MaxPlaintext))
	if err != nil || len(body) != RecordSize {
		t.Fatalf("largest message: %d bytes, %v; want %d", len(body), err, RecordSize)
	}
	if _, err := Encrypt(keys, make([]byte, MaxPlaintext+1)); !errors.Is(err, ErrTooLarge) {
		t.Errorf("too large: %v", err)
	}
	for _, bad := range []Keys{
		{P256DH: keys.P256DH, Auth: make([]byte, 15)},
		{P256DH: keys.P256DH[:64], Auth: keys.Auth},
		{P256DH: append([]byte{4}, make([]byte, 64)...), Auth: keys.Auth}, // not on the curve
	} {
		if _, err := Encrypt(bad, []byte("x")); err == nil {
			t.Errorf("encrypted for %x / %x", bad.P256DH, bad.Auth)
		}
	}
}

// RFC 8292, Section 2.4's example.
const (
	rfcVAPIDHeader = `vapid t=eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJhdWQiOiJodHRwczovL3B1c2guZXhhbXBsZS5uZXQiLCJleHAiOjE0NTM1MjM3NjgsInN1YiI6Im1haWx0bzpwdXNoQGV4YW1wbGUuY29tIn0.i3CYb7t4xfxCDquptFOepC9GAu_HLGkMlMuCGSK2rpiUfnK9ojFwDXb1JrErtmysazNjjvW2L9OkSSHzvoD1oA, k=BA1Hxzyi1RUM1b5wjxsn7nGxAszw2u61m164i3MrAIxHF6YK5h4SDYic-dRuU_RCPCfA5aq9ojSwk5Y2EmClBPs`
	rfcVAPIDExp    = 1453523768
)

// TestVerifyAuthorization_RFC8292Example checks the verifier, which the
// tests of what's signed rely on, against RFC 8292's example token.
func TestVerifyAuthorization_RFC8292Example(t *testing.T) {
	at := time.Unix(rfcVAPIDExp-3600, 0)
	if _, err := VerifyAuthorization(rfcVAPIDHeader, "https://push.example.net/push/JzLQ3raZJfFBR0aqvOMsLrt54w4rJUsV", at); err != nil {
		t.Fatalf("the RFC's example: %v", err)
	}
	for desc, tt := range map[string]struct {
		header, endpoint string
		at               time.Time
	}{
		"expired":           {rfcVAPIDHeader, "https://push.example.net/x", time.Unix(rfcVAPIDExp, 0)},
		"too far ahead":     {rfcVAPIDHeader, "https://push.example.net/x", time.Unix(rfcVAPIDExp-25*3600, 0)},
		"another audience":  {rfcVAPIDHeader, "https://push.example.org/x", at},
		"tampered":          {strings.Replace(rfcVAPIDHeader, ".i3CY", ".i3CZ", 1), "https://push.example.net/x", at},
		"another key":       {strings.Replace(rfcVAPIDHeader, "k=BA1H", "k=BP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8x", 1), "https://push.example.net/x", at},
		"another scheme":    {strings.Replace(rfcVAPIDHeader, "vapid ", "WebPush ", 1), "https://push.example.net/x", at},
		"no token":          {"vapid k=BA1Hxzyi1RUM1b5wjxsn7nGxAszw2u61m164i3MrAIxHF6YK5h4SDYic-dRuU_RCPCfA5aq9ojSwk5Y2EmClBPs", "https://push.example.net/x", at},
		"http endpoint":     {rfcVAPIDHeader, "http://push.example.net/x", at},
		"alg none (header)": {strings.Replace(rfcVAPIDHeader, "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9", encodeKey([]byte(`{"typ":"JWT","alg":"none"}`)), 1), "https://push.example.net/x", at},
	} {
		if _, err := VerifyAuthorization(tt.header, tt.endpoint, tt.at); err == nil {
			t.Errorf("%s: verified", desc)
		}
	}
}

func TestVAPIDKey_Authorization(t *testing.T) {
	k, err := GenerateVAPIDKey()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(rfcVAPIDExp, 0).Add(-TokenLifetime)
	h, err := k.Authorization("https://push.example.net/push/JzLQ3raZJfFBR0aqvOMsLrt54w4rJUsV", "mailto:push@example.com", now)
	if err != nil {
		t.Fatal(err)
	}
	// The header and claims encode exactly as RFC 8292's example does,
	// for the same audience, expiry, and subject.
	wantPrefix := "vapid t=eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJhdWQiOiJodHRwczovL3B1c2guZXhhbXBsZS5uZXQiLCJleHAiOjE0NTM1MjM3NjgsInN1YiI6Im1haWx0bzpwdXNoQGV4YW1wbGUuY29tIn0."
	if !strings.HasPrefix(h, wantPrefix) || !strings.HasSuffix(h, ", k="+k.PublicKeyString()) {
		t.Fatalf("Authorization = %q", h)
	}
	pub, err := VerifyAuthorization(h, "https://push.example.net/other", now)
	if err != nil || !bytes.Equal(pub, k.PublicKey()) {
		t.Fatalf("verifying our own token: %v", err)
	}
	if len(k.PublicKey()) != PublicKeySize || k.PublicKey()[0] != 4 {
		t.Errorf("public key = %x", k.PublicKey())
	}
	if _, err := k.Authorization("https://push.example.net/x", "push@example.com", now); err == nil {
		t.Error("signed with a subject that isn't a URL")
	}
	if _, err := k.Authorization("http://push.example.net/x", "", now); err == nil {
		t.Error("signed for an http endpoint")
	}
}

func TestLoadOrCreateVAPIDKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vapid.pem")
	k1, err := LoadOrCreateVAPIDKey(path)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("key file mode = %v, %v; want 0600", info.Mode(), err)
	}
	k2, err := LoadOrCreateVAPIDKey(path)
	if err != nil || !bytes.Equal(k1.PublicKey(), k2.PublicKey()) {
		t.Fatalf("reloaded a different key: %v", err)
	}

	for name, content := range map[string]string{
		"garbage": "not a key",
		"wrong":   "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n",
		"bad der": "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n",
	} {
		p := filepath.Join(t.TempDir(), name)
		_ = os.WriteFile(p, []byte(content), 0o600)
		if _, err := LoadOrCreateVAPIDKey(p); err == nil {
			t.Errorf("%s: loaded", name)
		}
	}
}

func TestSubscription_Decode(t *testing.T) {
	ua, _ := ecdh.P256().GenerateKey(nil)
	good := Subscription{
		Endpoint: "https://fcm.googleapis.com/fcm/send/abc:def",
		Keys:     SubscriptionKeys{P256DH: encodeKey(ua.PublicKey().Bytes()), Auth: encodeKey(make([]byte, AuthSize))},
	}
	if _, keys, err := good.Decode(); err != nil || len(keys.P256DH) != PublicKeySize {
		t.Fatalf("Decode = %v", err)
	}
	padded := good
	padded.Keys.Auth += "=="
	if _, _, err := padded.Decode(); err != nil {
		t.Errorf("padded auth: %v", err)
	}

	mutate := func(f func(*Subscription)) Subscription { s := good; f(&s); return s }
	for desc, s := range map[string]Subscription{
		"no endpoint": mutate(func(s *Subscription) { s.Endpoint = "" }),
		"http":        mutate(func(s *Subscription) { s.Endpoint = "http://fcm.googleapis.com/fcm/send/x" }),
		"userinfo":    mutate(func(s *Subscription) { s.Endpoint = "https://u:p@fcm.googleapis.com/fcm/send/x" }),
		"too long": mutate(func(s *Subscription) {
			s.Endpoint = "https://fcm.googleapis.com/" + strings.Repeat("a", MaxEndpointLength)
		}),
		"short key":       mutate(func(s *Subscription) { s.Keys.P256DH = encodeKey(make([]byte, 33)) }),
		"key off curve":   mutate(func(s *Subscription) { s.Keys.P256DH = encodeKey(append([]byte{4}, make([]byte, 64)...)) }),
		"not base64":      mutate(func(s *Subscription) { s.Keys.P256DH = "!!!" }),
		"short auth":      mutate(func(s *Subscription) { s.Keys.Auth = encodeKey(make([]byte, 8)) }),
		"no auth":         mutate(func(s *Subscription) { s.Keys.Auth = "" }),
		"std base64 auth": mutate(func(s *Subscription) { s.Keys.Auth = "AAAAAAAAAAAAAAAAAAAA+/" }),
	} {
		if _, _, err := s.Decode(); err == nil {
			t.Errorf("%s: decoded", desc)
		}
	}
}
