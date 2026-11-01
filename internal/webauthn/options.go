package webauthn

import "github.com/picatz/doh/internal/cose"

// The types in this file are the WebAuthn Level 3 JSON serialization of
// ceremony options, which browsers accept through
// PublicKeyCredential.parseCreationOptionsFromJSON and
// parseRequestOptionsFromJSON:
// https://www.w3.org/TR/webauthn-3/#sctn-parseCreationOptionsFromJSON

// RelyingPartyEntity names the relying party in creation options.
// https://www.w3.org/TR/webauthn-3/#dictdef-publickeycredentialrpentity
type RelyingPartyEntity struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// UserEntity names the account a credential is created for. ID is the user
// handle: a stable, opaque 1–64 byte value that must not contain personal
// information. Name and DisplayName are shown by the client and confer no
// authority.
// https://www.w3.org/TR/webauthn-3/#dictdef-publickeycredentialuserentityjson
type UserEntity struct {
	ID          Base64URL `json:"id"`
	Name        string    `json:"name"`
	DisplayName string    `json:"displayName"`
}

// CredentialParameter is one offered credential algorithm.
// https://www.w3.org/TR/webauthn-3/#dictdef-publickeycredentialparameters
type CredentialParameter struct {
	Type      string         `json:"type"`
	Algorithm cose.Algorithm `json:"alg"`
}

// CredentialDescriptor identifies an existing credential, for
// excludeCredentials and allowCredentials.
// https://www.w3.org/TR/webauthn-3/#dictdef-publickeycredentialdescriptorjson
type CredentialDescriptor struct {
	Type       string      `json:"type"`
	ID         Base64URL   `json:"id"`
	Transports []Transport `json:"transports,omitempty"`
}

// AuthenticatorSelection states authenticator requirements for registration.
// https://www.w3.org/TR/webauthn-3/#dictdef-authenticatorselectioncriteria
type AuthenticatorSelection struct {
	AuthenticatorAttachment AuthenticatorAttachment `json:"authenticatorAttachment,omitempty"`
	ResidentKey             ResidentKey             `json:"residentKey,omitempty"`
	RequireResidentKey      bool                    `json:"requireResidentKey,omitempty"`
	UserVerification        UserVerification        `json:"userVerification,omitempty"`
}

// PRFValues are pseudo-random function inputs for the prf extension.
// https://www.w3.org/TR/webauthn-3/#dictdef-authenticationextensionsprfvaluesjson
type PRFValues struct {
	First  Base64URL `json:"first"`
	Second Base64URL `json:"second,omitempty"`
}

// PRFInputs request the prf extension. At registration an empty value asks
// whether the credential supports PRF; Eval also evaluates it where the
// client supports that. EvalByCredential keys are base64url credential IDs.
// https://www.w3.org/TR/webauthn-3/#prf-extension
type PRFInputs struct {
	Eval             *PRFValues           `json:"eval,omitempty"`
	EvalByCredential map[string]PRFValues `json:"evalByCredential,omitempty"`
}

// ExtensionInputs are the client extension inputs this package offers.
// https://www.w3.org/TR/webauthn-3/#sctn-extensions
type ExtensionInputs struct {
	// CredProps asks the client to report whether the credential is
	// discoverable.
	CredProps bool       `json:"credProps,omitempty"`
	PRF       *PRFInputs `json:"prf,omitempty"`
}

// CreationOptions is PublicKeyCredentialCreationOptionsJSON.
// https://www.w3.org/TR/webauthn-3/#dictdef-publickeycredentialcreationoptionsjson
type CreationOptions struct {
	RP                     RelyingPartyEntity     `json:"rp"`
	User                   UserEntity             `json:"user"`
	Challenge              Base64URL              `json:"challenge"`
	PubKeyCredParams       []CredentialParameter  `json:"pubKeyCredParams"`
	Timeout                uint32                 `json:"timeout,omitempty"`
	ExcludeCredentials     []CredentialDescriptor `json:"excludeCredentials,omitempty"`
	AuthenticatorSelection AuthenticatorSelection `json:"authenticatorSelection"`
	Hints                  []Hint                 `json:"hints,omitempty"`
	Attestation            AttestationConveyance  `json:"attestation,omitempty"`
	Extensions             *ExtensionInputs       `json:"extensions,omitempty"`
}

// RequestOptions is PublicKeyCredentialRequestOptionsJSON.
// https://www.w3.org/TR/webauthn-3/#dictdef-publickeycredentialrequestoptionsjson
type RequestOptions struct {
	Challenge        Base64URL              `json:"challenge"`
	Timeout          uint32                 `json:"timeout,omitempty"`
	RPID             string                 `json:"rpId"`
	AllowCredentials []CredentialDescriptor `json:"allowCredentials,omitempty"`
	UserVerification UserVerification       `json:"userVerification"`
	Hints            []Hint                 `json:"hints,omitempty"`
	Extensions       *ExtensionInputs       `json:"extensions,omitempty"`
}

// CredentialCreationOptions is the argument for navigator.credentials.create
// in JSON form: {"publicKey": ...}. It matches what the webauthn module's
// browser client passes to parseCreationOptionsFromJSON.
type CredentialCreationOptions struct {
	PublicKey CreationOptions `json:"publicKey"`
}

// CredentialRequestOptions is the argument for navigator.credentials.get in
// JSON form. Mediation is "conditional" for autofill sign-in.
type CredentialRequestOptions struct {
	PublicKey RequestOptions `json:"publicKey"`
	Mediation Mediation      `json:"mediation,omitempty"`
}

// RegistrationOptions is returned by [RelyingParty.BeginRegistration]. Send
// it to the browser as JSON. ID is an opaque ceremony handle, not a secret
// and not authentication; the finish call also needs the session binding.
type RegistrationOptions struct {
	ID      string                    `json:"id"`
	Options CredentialCreationOptions `json:"options"`
}

// LoginOptions is returned by [RelyingParty.BeginLogin]. Send it to the
// browser as JSON; as with [RegistrationOptions], ID is not authentication.
type LoginOptions struct {
	ID      string                   `json:"id"`
	Options CredentialRequestOptions `json:"options"`
}
