package webauthn

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/picatz/cbor"
)

// Flags is the authenticator data flags byte.
// https://www.w3.org/TR/webauthn-3/#authdata-flags
type Flags byte

// Authenticator data flag bits. Bits 1 and 5 are reserved for future use and
// are ignored, as the specification requires.
const (
	FlagUserPresent            Flags = 1 << 0 // UP
	FlagUserVerified           Flags = 1 << 2 // UV
	FlagBackupEligible         Flags = 1 << 3 // BE
	FlagBackupState            Flags = 1 << 4 // BS
	FlagAttestedCredentialData Flags = 1 << 6 // AT
	FlagExtensionData          Flags = 1 << 7 // ED
)

// Has reports whether every bit in mask is set.
func (f Flags) Has(mask Flags) bool { return f&mask == mask }

// maxCredentialID is the WebAuthn bound on credential IDs: §7.1 "Verify that
// the credentialId is ≤ 1023 bytes".
const maxCredentialID = 1023

// AuthenticatorData is parsed authenticator data.
// https://www.w3.org/TR/webauthn-3/#sctn-authenticator-data
type AuthenticatorData struct {
	RPIDHash  [32]byte
	Flags     Flags
	SignCount uint32
	// Attested is present only when the AT flag is set (registration).
	Attested *AttestedCredentialData
	// Extensions is the raw CBOR map of authenticator extension outputs,
	// present only when the ED flag is set. It is checked to be one
	// well-formed CBOR map, but its contents are not interpreted.
	Extensions []byte
}

// AttestedCredentialData is the credential created during registration.
// https://www.w3.org/TR/webauthn-3/#sctn-attested-credential-data
type AttestedCredentialData struct {
	AAGUID       AAGUID
	CredentialID []byte
	// PublicKey is the credential public key exactly as encoded (COSE_Key).
	PublicKey []byte
}

// authDataOptions bounds the CBOR embedded in authenticator data.
func authDataOptions() cbor.DecoderOptions {
	return cbor.DecoderOptions{MaxNestedLevels: 16, MaxArrayElements: 256, MaxMapPairs: 64,
		MaxStringBytes: 16 << 10, MaxBytes: 64 << 10, MaxEncodedBytes: 64 << 10, RejectTags: true}
}

// ParseAuthenticatorData parses authenticator data. It checks the structure
// only: that the AT and ED flags match the data present, that a credential ID
// is present, that the public key and extensions are each one CBOR map,
// and that nothing trails them. It does not check the RP ID hash, flags
// policy or the key's validity; the ceremony verification does that.
// The result does not alias data. Failures wrap [ErrMalformed].
func ParseAuthenticatorData(data []byte) (*AuthenticatorData, error) {
	if len(data) < 37 {
		return nil, fmt.Errorf("%w: authenticator data shorter than 37 bytes (%s)", ErrMalformed, specAuthData)
	}
	if len(data) > 64<<10 {
		return nil, fmt.Errorf("%w: authenticator data over 64 KiB", ErrMalformed)
	}
	out := &AuthenticatorData{Flags: Flags(data[32]), SignCount: binary.BigEndian.Uint32(data[33:37])}
	copy(out.RPIDHash[:], data[:32])
	rest := data[37:]
	if out.Flags.Has(FlagAttestedCredentialData) {
		if len(rest) < 18 {
			return nil, fmt.Errorf("%w: attested credential data truncated", ErrMalformed)
		}
		attested := &AttestedCredentialData{}
		copy(attested.AAGUID[:], rest[:16])
		length := int(binary.BigEndian.Uint16(rest[16:18]))
		rest = rest[18:]
		if length == 0 || length > len(rest) {
			return nil, fmt.Errorf("%w: credential ID length %d is out of range", ErrMalformed, length)
		}
		attested.CredentialID = bytes.Clone(rest[:length])
		rest = rest[length:]
		key, remaining, err := nextCBORMap(rest)
		if err != nil {
			return nil, fmt.Errorf("%w: credential public key: %v", ErrMalformed, err)
		}
		attested.PublicKey, rest = key, remaining
		out.Attested = attested
	}
	if out.Flags.Has(FlagExtensionData) {
		extensions, remaining, err := nextCBORMap(rest)
		if err != nil {
			return nil, fmt.Errorf("%w: authenticator extensions: %v", ErrMalformed, err)
		}
		out.Extensions, rest = extensions, remaining
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("%w: %d trailing bytes after authenticator data", ErrMalformed, len(rest))
	}
	return out, nil
}

// nextCBORMap decodes one CBOR map from the front of data and returns its
// encoding and the bytes after it.
func nextCBORMap(data []byte) ([]byte, []byte, error) {
	if len(data) == 0 || data[0]>>5 != 5 {
		return nil, nil, fmt.Errorf("not a CBOR map")
	}
	reader := bytes.NewReader(data)
	var raw cbor.RawMessage
	if err := cbor.NewDecoderWithOptions(reader, authDataOptions()).Decode(&raw); err != nil {
		return nil, nil, err
	}
	return []byte(raw), data[len(data)-reader.Len():], nil
}
