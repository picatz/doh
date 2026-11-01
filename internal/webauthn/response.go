package webauthn

import (
	"fmt"

	"github.com/picatz/doh/internal/cose"
	"github.com/picatz/doh/internal/strictjson"
)

// RegistrationResponse is RegistrationResponseJSON, what
// PublicKeyCredential.toJSON returns after navigator.credentials.create.
// https://www.w3.org/TR/webauthn-3/#dictdef-registrationresponsejson
type RegistrationResponse struct {
	ID                      string                  `json:"id"`
	RawID                   Base64URL               `json:"rawId"`
	Response                AttestationResponse     `json:"response"`
	AuthenticatorAttachment AuthenticatorAttachment `json:"authenticatorAttachment,omitempty"`
	ClientExtensionResults  ExtensionOutputs        `json:"clientExtensionResults"`
	Type                    string                  `json:"type"`
}

// AttestationResponse is AuthenticatorAttestationResponseJSON. Only
// ClientDataJSON and AttestationObject are trusted inputs to verification;
// AuthenticatorData, when present, must equal the copy inside the
// attestation object, and the other convenience members are ignored.
// https://www.w3.org/TR/webauthn-3/#dictdef-authenticatorattestationresponsejson
type AttestationResponse struct {
	ClientDataJSON     Base64URL      `json:"clientDataJSON"`
	AuthenticatorData  Base64URL      `json:"authenticatorData,omitempty"`
	Transports         []Transport    `json:"transports,omitempty"`
	PublicKey          Base64URL      `json:"publicKey,omitempty"`
	PublicKeyAlgorithm cose.Algorithm `json:"publicKeyAlgorithm,omitempty"`
	AttestationObject  Base64URL      `json:"attestationObject"`
}

// AuthenticationResponse is AuthenticationResponseJSON, what
// PublicKeyCredential.toJSON returns after navigator.credentials.get.
// https://www.w3.org/TR/webauthn-3/#dictdef-authenticationresponsejson
type AuthenticationResponse struct {
	ID                      string                  `json:"id"`
	RawID                   Base64URL               `json:"rawId"`
	Response                AssertionResponse       `json:"response"`
	AuthenticatorAttachment AuthenticatorAttachment `json:"authenticatorAttachment,omitempty"`
	ClientExtensionResults  ExtensionOutputs        `json:"clientExtensionResults"`
	Type                    string                  `json:"type"`
}

// AssertionResponse is AuthenticatorAssertionResponseJSON.
// https://www.w3.org/TR/webauthn-3/#dictdef-authenticatorassertionresponsejson
type AssertionResponse struct {
	ClientDataJSON    Base64URL `json:"clientDataJSON"`
	AuthenticatorData Base64URL `json:"authenticatorData"`
	Signature         Base64URL `json:"signature"`
	UserHandle        Base64URL `json:"userHandle,omitempty"`
}

// CredPropsOutput is the credProps client extension output.
// https://www.w3.org/TR/webauthn-3/#sctn-authenticator-credential-properties-extension
type CredPropsOutput struct {
	// RK reports whether the client created a discoverable credential. It
	// is the client's claim and is not signed by the authenticator.
	RK *bool `json:"rk,omitempty"`
}

// PRFOutput is the prf client extension output. Results, which are secret
// key material for the client, are deliberately not decoded.
// https://www.w3.org/TR/webauthn-3/#prf-extension
type PRFOutput struct {
	Enabled *bool `json:"enabled,omitempty"`
}

// ExtensionOutputs are the client extension outputs this package reads.
// Client extension outputs are not signed; treat them as client claims.
// Unrequested and unknown outputs are ignored.
type ExtensionOutputs struct {
	CredProps *CredPropsOutput `json:"credProps,omitempty"`
	PRF       *PRFOutput       `json:"prf,omitempty"`
}

// ParseRegistrationResponse decodes RegistrationResponseJSON. It requires
// type "public-key", an id equal to the base64url of a 1–1023 byte rawId, and non-empty
// clientDataJSON and attestationObject, and it rejects trailing data.
// Unknown members are ignored. Failures wrap [ErrMalformed].
func ParseRegistrationResponse(data []byte) (*RegistrationResponse, error) {
	var out RegistrationResponse
	if err := strictjson.UnmarshalOpen(data, &out); err != nil {
		return nil, fmt.Errorf("%w: response is not the expected JSON: %v", ErrMalformed, err)
	}
	if err := checkCredentialJSON(out.Type, out.ID, out.RawID); err != nil {
		return nil, err
	}
	if len(out.Response.ClientDataJSON) == 0 || len(out.Response.AttestationObject) == 0 {
		return nil, fmt.Errorf("%w: registration response lacks clientDataJSON or attestationObject (%s)", ErrMalformed, specJSON)
	}
	return &out, nil
}

// ParseAuthenticationResponse decodes AuthenticationResponseJSON with the
// same rules as [ParseRegistrationResponse], requiring clientDataJSON,
// authenticatorData and signature.
func ParseAuthenticationResponse(data []byte) (*AuthenticationResponse, error) {
	var out AuthenticationResponse
	if err := strictjson.UnmarshalOpen(data, &out); err != nil {
		return nil, fmt.Errorf("%w: response is not the expected JSON: %v", ErrMalformed, err)
	}
	if err := checkCredentialJSON(out.Type, out.ID, out.RawID); err != nil {
		return nil, err
	}
	r := out.Response
	if len(r.ClientDataJSON) == 0 || len(r.AuthenticatorData) == 0 || len(r.Signature) == 0 {
		return nil, fmt.Errorf("%w: authentication response lacks clientDataJSON, authenticatorData or signature", ErrMalformed)
	}
	return &out, nil
}

func checkCredentialJSON(kind, id string, rawID []byte) error {
	if kind != "public-key" {
		return fmt.Errorf("%w: credential type is not public-key", ErrMalformed)
	}
	// Credential IDs are at most 1023 bytes (§7.1 step 24, and the
	// credential ID definition), so a longer rawId is rejected before any
	// lookup or verification sees it.
	if len(rawID) == 0 || len(rawID) > maxCredentialID || id != Base64URL(rawID).String() {
		return fmt.Errorf("%w: credential id must be the base64url of a 1–1023 byte rawId", ErrMalformed)
	}
	return nil
}
