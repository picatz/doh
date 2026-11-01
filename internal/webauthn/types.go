package webauthn

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// Base64URL is a byte string that JSON-encodes as unpadded base64url, the
// Base64URLString of the WebAuthn JSON serialization:
// https://www.w3.org/TR/webauthn-3/#typedefdef-base64urlstring
//
// Decoding is strict: padding, the standard alphabet, whitespace and
// non-canonical trailing bits are rejected with [ErrMalformed].
type Base64URL []byte

// MarshalJSON encodes b as an unpadded base64url JSON string.
func (b Base64URL) MarshalJSON() ([]byte, error) {
	return json.Marshal(base64.RawURLEncoding.EncodeToString(b))
}

// UnmarshalJSON decodes an unpadded base64url JSON string into a new slice.
func (b *Base64URL) UnmarshalJSON(data []byte) error {
	var text string
	if err := json.Unmarshal(data, &text); err != nil {
		return fmt.Errorf("%w: base64url value is not a JSON string", ErrMalformed)
	}
	decoded, err := decodeBase64URL(text)
	if err != nil {
		return err
	}
	*b = decoded
	return nil
}

// String returns the unpadded base64url encoding.
func (b Base64URL) String() string { return base64.RawURLEncoding.EncodeToString(b) }

func decodeBase64URL(text string) ([]byte, error) {
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(text)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid base64url", ErrMalformed)
	}
	return decoded, nil
}

// AAGUID is the 16-byte authenticator model identifier from attested
// credential data. It identifies a model, not a device, and by itself is not
// evidence of either: only a verified attestation binds it to a certificate.
// https://www.w3.org/TR/webauthn-3/#aaguid
type AAGUID [16]byte

// String returns the AAGUID in the 8-4-4-4-12 hexadecimal form used by FIDO
// metadata.
func (a AAGUID) String() string {
	h := hex.EncodeToString(a[:])
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

// IsZero reports whether a is all zeros, as authenticators send when they
// provide no model identity (and as "none" attestation may rewrite it).
func (a AAGUID) IsZero() bool { return a == AAGUID{} }

// MarshalText encodes the AAGUID in its hyphenated hexadecimal form.
func (a AAGUID) MarshalText() ([]byte, error) { return []byte(a.String()), nil }

// UnmarshalText decodes the hyphenated or plain hexadecimal form.
func (a *AAGUID) UnmarshalText(text []byte) error {
	clean := make([]byte, 0, 32)
	for i, c := range text {
		if c == '-' && (i == 8 || i == 13 || i == 18 || i == 23) && len(text) == 36 {
			continue
		}
		clean = append(clean, c)
	}
	if len(clean) != 32 {
		return fmt.Errorf("%w: AAGUID must be 16 bytes of hex", ErrMalformed)
	}
	if _, err := hex.Decode(a[:], clean); err != nil {
		return fmt.Errorf("%w: AAGUID must be 16 bytes of hex", ErrMalformed)
	}
	return nil
}

// UserVerification is the user verification requirement of a ceremony.
// https://www.w3.org/TR/webauthn-3/#enumdef-userverificationrequirement
type UserVerification string

// User verification requirements.
const (
	UserVerificationRequired    UserVerification = "required"
	UserVerificationPreferred   UserVerification = "preferred"
	UserVerificationDiscouraged UserVerification = "discouraged"
)

func (u UserVerification) valid() bool {
	return u == UserVerificationRequired || u == UserVerificationPreferred || u == UserVerificationDiscouraged
}

// ResidentKey asks for a client-side discoverable credential (a passkey that
// can sign in without a username).
// https://www.w3.org/TR/webauthn-3/#enumdef-residentkeyrequirement
type ResidentKey string

// Resident key requirements.
const (
	ResidentKeyDiscouraged ResidentKey = "discouraged"
	ResidentKeyPreferred   ResidentKey = "preferred"
	ResidentKeyRequired    ResidentKey = "required"
)

// AttestationConveyance is the relying party's attestation preference.
// "enterprise" is not offered: it needs per-RP authenticator provisioning.
// https://www.w3.org/TR/webauthn-3/#enumdef-attestationconveyancepreference
type AttestationConveyance string

// Attestation conveyance preferences.
const (
	AttestationConveyanceNone     AttestationConveyance = "none"
	AttestationConveyanceIndirect AttestationConveyance = "indirect"
	AttestationConveyanceDirect   AttestationConveyance = "direct"
)

// AuthenticatorAttachment restricts registration to platform or roaming
// authenticators.
// https://www.w3.org/TR/webauthn-3/#enumdef-authenticatorattachment
type AuthenticatorAttachment string

// Authenticator attachments.
const (
	AuthenticatorAttachmentPlatform      AuthenticatorAttachment = "platform"
	AuthenticatorAttachmentCrossPlatform AuthenticatorAttachment = "cross-platform"
)

// Hint tells the client which authenticator user interface to lead with.
// Hints are advisory; they are not verified and confer no assurance.
// https://www.w3.org/TR/webauthn-3/#enumdef-publickeycredentialhint
type Hint string

// Credential hints.
const (
	HintSecurityKey  Hint = "security-key"
	HintClientDevice Hint = "client-device"
	HintHybrid       Hint = "hybrid"
)

// Transport is an authenticator transport reported by the client. It is a
// routing hint for later ceremonies, never evidence of hardware.
// https://www.w3.org/TR/webauthn-3/#enumdef-authenticatortransport
type Transport string

// Authenticator transports.
const (
	TransportUSB       Transport = "usb"
	TransportNFC       Transport = "nfc"
	TransportBLE       Transport = "ble"
	TransportSmartCard Transport = "smart-card"
	TransportHybrid    Transport = "hybrid"
	TransportInternal  Transport = "internal"
)

// Mediation is the credential mediation requirement passed to
// navigator.credentials.get. Only the default (empty) and conditional
// mediation are offered.
// https://www.w3.org/TR/credential-management-1/#mediation-requirements
type Mediation string

// Mediation requirements.
const (
	MediationDefault     Mediation = ""
	MediationConditional Mediation = "conditional"
)

// CeremonyKind distinguishes registration from authentication ceremonies.
type CeremonyKind string

// Ceremony kinds.
const (
	CeremonyRegistration CeremonyKind = "registration"
	CeremonyLogin        CeremonyKind = "authentication"
)
