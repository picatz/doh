package webauthn

import (
	"errors"
	"fmt"
)

var (
	// ErrInvalidInput is returned for a [Config], begin request or argument
	// that is outside this package's documented bounds or syntax.
	ErrInvalidInput = errors.New("webauthn: invalid input")
	// ErrChallenge is returned when a ceremony ID is unknown, expired, already
	// consumed, bound to a different session or of the other ceremony kind.
	// The ceremony cannot be retried; start a new one.
	ErrChallenge = errors.New("webauthn: ceremony missing, expired, consumed, or mismatched")
	// ErrMalformed is returned when a browser response, client data,
	// authenticator data, attestation object or COSE key cannot be parsed.
	ErrMalformed = errors.New("webauthn: malformed response")
	// ErrVerification is returned when a parsed response fails a WebAuthn
	// verification step. The [VerificationError] that wraps it names the step.
	ErrVerification = errors.New("webauthn: verification failed")
	// ErrCounter is returned when an assertion's signature counter did not
	// increase and [Policy.Counter] is [CounterReject].
	ErrCounter = errors.New("webauthn: signature counter did not increase")
	// ErrCredential is returned by a [CredentialLookup] when no usable
	// credential record matches the asserted credential ID and user handle.
	// [RelyingParty.FinishLogin] does not pass it on: it reports the same
	// [ErrVerification] failure as for an invalid signature.
	ErrCredential = errors.New("webauthn: credential not found")
	// ErrCapacity is returned by [MemoryChallengeStore.Put] when the store
	// holds its maximum number of unexpired ceremonies.
	ErrCapacity = errors.New("webauthn: store capacity reached")
	// ErrUnsupported is returned for an attestation statement format, COSE
	// algorithm or key type this package recognizes but does not verify. It
	// matches [errors.ErrUnsupported].
	ErrUnsupported = fmt.Errorf("webauthn: unsupported: %w", errors.ErrUnsupported)
)

// VerificationError reports which ceremony step rejected a response. Step is
// a short, stable description, Spec is a link to the WebAuthn Level 3 text
// that requires the check, and Err is one of this package's sentinels
// (usually [ErrVerification]), so callers can use [errors.Is].
//
// The message contains no challenge, credential or key bytes, but it does
// say why a response failed. Log it for operators; show users a generic
// failure so the details do not help an attacker probe the server.
type VerificationError struct {
	Ceremony CeremonyKind
	Step     string
	Spec     string
	Err      error
	// Detail, when set, refines a deliberately generic Step for operator
	// logs. FinishLogin uses it so that an unknown credential and an invalid
	// signature share one Step and message. Error omits it; never send it to
	// the client.
	Detail string
}

// Error describes the failed step and links the specification section.
func (e *VerificationError) Error() string {
	message := "webauthn: " + string(e.Ceremony) + ": " + e.Step
	if e.Spec != "" {
		message += " (" + e.Spec + ")"
	}
	return message
}

// Unwrap returns the sentinel that classifies the failure.
func (e *VerificationError) Unwrap() error { return e.Err }

// Specification links cited by verification errors and code comments.
const (
	specRegistration = "https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential"
	specAssertion    = "https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion"
	specOrigin       = "https://www.w3.org/TR/webauthn-3/#sctn-validating-origin"
	specAuthData     = "https://www.w3.org/TR/webauthn-3/#sctn-authenticator-data"
	specClientData   = "https://www.w3.org/TR/webauthn-3/#dictionary-client-data"
	specAlgorithms   = "https://www.w3.org/TR/webauthn-3/#sctn-alg-identifier"
	specPacked       = "https://www.w3.org/TR/webauthn-3/#sctn-packed-attestation"
	specPackedCert   = "https://www.w3.org/TR/webauthn-3/#sctn-packed-attestation-cert-requirements"
	specU2F          = "https://www.w3.org/TR/webauthn-3/#sctn-fido-u2f-attestation"
	specNone         = "https://www.w3.org/TR/webauthn-3/#sctn-none-attestation"
	specSignCount    = "https://www.w3.org/TR/webauthn-3/#sctn-sign-counter"
	specBackup       = "https://www.w3.org/TR/webauthn-3/#sctn-credential-backup"
	specCredRecord   = "https://www.w3.org/TR/webauthn-3/#credential-record"
	specJSON         = "https://www.w3.org/TR/webauthn-3/#dictdef-registrationresponsejson"
)

// failure builds a VerificationError for ceremony kind.
func failure(kind CeremonyKind, err error, spec, step string) error {
	return &VerificationError{Ceremony: kind, Step: step, Spec: spec, Err: err}
}

// stepAssertion is the one Step for every authentication failure that
// depends on whether a credential record exists.
const stepAssertion = "assertion does not verify against a registered credential"

// assertionFailure builds the indistinguishable authentication failure,
// keeping why in Detail.
func assertionFailure(detail string) error {
	return &VerificationError{Ceremony: CeremonyLogin, Step: stepAssertion, Spec: specAssertion, Err: ErrVerification, Detail: detail}
}
