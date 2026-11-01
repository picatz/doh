package webauthn

import (
	"bytes"
	"context"
	"slices"

	"github.com/picatz/doh/internal/cose"
)

// Credential is a credential record: what the relying party stores after
// registration and needs for every later authentication.
// https://www.w3.org/TR/webauthn-3/#credential-record
//
// Persist every field. Treat the record as integrity-sensitive: whoever can
// change PublicKey or UserHandle can sign in as the account.
type Credential struct {
	// ID is the credential ID (rawId).
	ID []byte `json:"id"`
	// UserHandle is the account the credential belongs to (user.id at
	// registration).
	UserHandle []byte `json:"userHandle"`
	// RPID is the relying party ID the credential is scoped to. FinishLogin
	// rejects a record whose RPID is not exactly the relying party's ID,
	// including an empty one.
	RPID string `json:"rpId"`
	// PublicKey is the COSE_Key credential public key exactly as the
	// authenticator encoded it. [ParsePublicKey] decodes it.
	PublicKey []byte `json:"publicKey"`
	// Algorithm is the COSE algorithm of PublicKey.
	Algorithm cose.Algorithm `json:"algorithm"`
	// SignCount is the last signature counter value seen. Zero means the
	// authenticator does not implement a counter (as synced passkeys do).
	SignCount uint32 `json:"signCount"`
	// Transports are the transports the client reported at registration.
	Transports []Transport `json:"transports,omitempty"`
	// UVInitialized records whether user verification has been performed
	// with this credential (uvInitialized).
	UVInitialized bool `json:"uvInitialized"`
	// BackupEligible is fixed at creation: whether the credential may be
	// synced (a multi-device passkey).
	BackupEligible bool `json:"backupEligible"`
	// BackupState is whether the credential was last reported as backed up.
	BackupState bool `json:"backupState"`
	// AAGUID is the authenticator model the attested data named. It is
	// evidence only when the attestation was verified against trusted roots.
	AAGUID AAGUID `json:"aaguid"`
	// AttestationFormat and AttestationType summarize the verified
	// attestation statement.
	AttestationFormat string          `json:"attestationFormat"`
	AttestationType   AttestationType `json:"attestationType"`
	// AttestationObject and AttestationClientDataJSON are kept so the
	// attestation can be re-evaluated later, for example against metadata.
	AttestationObject         []byte `json:"attestationObject,omitempty"`
	AttestationClientDataJSON []byte `json:"attestationClientDataJSON,omitempty"`
}

// Descriptor returns the credential as an allowCredentials or
// excludeCredentials entry.
func (c Credential) Descriptor() CredentialDescriptor {
	return CredentialDescriptor{Type: "public-key", ID: bytes.Clone(c.ID), Transports: slices.Clone(c.Transports)}
}

// Clone returns a deep copy of c.
func (c Credential) Clone() Credential {
	c.ID = bytes.Clone(c.ID)
	c.UserHandle = bytes.Clone(c.UserHandle)
	c.PublicKey = bytes.Clone(c.PublicKey)
	c.Transports = slices.Clone(c.Transports)
	c.AttestationObject = bytes.Clone(c.AttestationObject)
	c.AttestationClientDataJSON = bytes.Clone(c.AttestationClientDataJSON)
	return c
}

// CredentialLookup returns the stored credential record whose ID is
// credentialID. userHandle is the account the assertion is for: the
// ceremony's user when the user was identified before login, otherwise the
// userHandle the authenticator returned. Return an error wrapping
// [ErrCredential] when there is no such credential, or it is revoked or
// disabled; FinishLogin also rejects a record whose UserHandle or RPID
// differs, and reports either case exactly as it reports a bad signature.
//
// Look up by credential ID across all accounts, then let FinishLogin compare
// the owner: that way a credential registered to one account cannot be used
// to sign in to another.
type CredentialLookup func(ctx context.Context, credentialID, userHandle []byte) (*Credential, error)

// Registration is the result of a verified registration ceremony.
type Registration struct {
	// Credential is the new credential record. Store it for
	// Credential.UserHandle, rejecting the registration if the credential
	// ID is already registered to any account (§7.1: "Verify that the
	// credentialId is not yet registered for any user").
	Credential Credential
	// Attestation describes the verified attestation statement.
	Attestation Attestation
	// UserVerified reports the UV flag at registration.
	UserVerified bool
	// Extensions are the client's unsigned extension outputs.
	Extensions ExtensionOutputs
	// AuthenticatorAttachment is the client's unsigned claim.
	AuthenticatorAttachment AuthenticatorAttachment
}

// Login is the result of a verified authentication ceremony.
type Login struct {
	// Credential is the updated credential record: the new signature
	// counter, backup state and uvInitialized. Persist it with a
	// compare-and-swap on PreviousSignCount (or a revision) so concurrent
	// logins cannot roll the counter back.
	Credential Credential
	// PreviousSignCount is the stored counter before this assertion.
	PreviousSignCount uint32
	// UserHandle is the authenticated account.
	UserHandle []byte
	// UserVerified reports the UV flag of this assertion.
	UserVerified bool
	// BackupStateChanged reports a change in the BS flag since the record
	// was last updated, for example a passkey that was just synced.
	BackupStateChanged bool
	// CounterAnomaly reports a signature counter that did not increase.
	// It is a signal, not proof, that the authenticator was cloned; it is
	// only reported when [Policy.Counter] is [CounterReport].
	CounterAnomaly bool
	// Extensions are the client's unsigned extension outputs.
	Extensions ExtensionOutputs
	// AuthenticatorAttachment is the client's unsigned claim.
	AuthenticatorAttachment AuthenticatorAttachment
}
