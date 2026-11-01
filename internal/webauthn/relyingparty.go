package webauthn

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/picatz/doh/internal/cose"
)

// BackupPolicy decides whether backup-eligible (syncable) credentials are
// acceptable. https://www.w3.org/TR/webauthn-3/#sctn-credential-backup
type BackupPolicy int

// Backup policies.
const (
	// BackupAllowed accepts synced passkeys and device-bound credentials.
	BackupAllowed BackupPolicy = iota
	// BackupForbidden accepts only credentials whose BE flag is clear, for
	// relying parties that require keys bound to one authenticator.
	BackupForbidden
)

// CounterPolicy decides what an assertion whose signature counter did not
// increase does. https://www.w3.org/TR/webauthn-3/#sctn-sign-counter
type CounterPolicy int

// Counter policies. A counter that stays at zero on both sides means the
// authenticator has no counter and is never an anomaly.
const (
	// CounterReject fails the ceremony with [ErrCounter].
	CounterReject CounterPolicy = iota
	// CounterReport succeeds and sets [Login.CounterAnomaly], for relying
	// parties that feed the signal into risk scoring instead.
	CounterReport
)

// Policy holds the relying party's verification choices. The zero value is
// the secure default: user verification required, ES256, EdDSA and RS256
// keys, "none", "packed" and "fido-u2f" attestation accepted without a
// trust decision, synced passkeys allowed, and a non-increasing counter
// rejected.
type Policy struct {
	// UserVerification is the default requirement for both ceremonies.
	// Empty means [UserVerificationRequired].
	UserVerification UserVerification
	// Algorithms are offered in pubKeyCredParams in preference order, and a
	// registered key must use one of them. Empty means ES256, EdDSA, RS256.
	Algorithms []cose.Algorithm
	// AttestationFormats are the statement formats accepted at registration.
	// Empty means "none", "packed" and "fido-u2f", all of which this package
	// verifies. Other formats fail with [ErrUnsupported].
	AttestationFormats []string
	// TrustAttestation, when set, decides whether a cryptographically
	// verified attestation is trustworthy (§7.1 "Assess the attestation
	// trustworthiness"); an error fails the registration. Nil accepts every
	// verified attestation, which is right for consumer passkeys where the
	// model does not matter. [TrustRoots] builds a root-store check.
	TrustAttestation func(context.Context, Attestation) error
	// Backup decides whether backup-eligible credentials are accepted.
	Backup BackupPolicy
	// Counter decides what a non-increasing signature counter does.
	Counter CounterPolicy
}

// Config configures a [RelyingParty]. All fields except Store and ID have
// defaults.
type Config struct {
	// ID is the RP ID: a lowercase domain such as "example.com", or
	// "localhost" for development. IP addresses are not valid RP IDs.
	// https://www.w3.org/TR/webauthn-3/#rp-id
	ID string
	// Name is shown by clients during registration. Empty uses ID.
	Name string
	// Origins are the exact origins allowed in client data. A web origin
	// is "https://host[:port]" whose host is ID or a subdomain of it, or
	// "http://host[:port]" when ID is "localhost" or ends in ".localhost",
	// which browsers treat as secure contexts. A native app origin, such as
	// "android:apk-key-hash:...", is matched exactly. Empty means
	// "https://" + ID.
	Origins []string
	// RelatedOrigins are additional HTTPS origins outside ID's domain, for
	// related origin requests. Each must also be listed in the JSON that
	// [RelyingParty.WellKnown] returns, served at
	// https://ID/.well-known/webauthn.
	//
	// Browsers stop reading that document after five distinct registrable
	// domains (eTLD+1 labels, §5.11.1), so an origin on a sixth such domain
	// never works. This package cannot check that without the public suffix
	// list; keep the configured web origins within five registrable domains.
	// https://www.w3.org/TR/webauthn-3/#sctn-related-origins
	RelatedOrigins []string
	// TopOrigins are the top-level origins that may embed a ceremony in a
	// cross-origin iframe. Empty rejects every cross-origin ceremony.
	TopOrigins []string
	// Tenant namespaces ceremonies in Store. Empty means ID.
	//
	// Each pending [Ceremony] also records a fingerprint of the settings
	// verification depends on (ID, Origins, RelatedOrigins, TopOrigins and
	// Policy except TrustAttestation), and finishing it under different
	// settings fails with [ErrChallenge]. So relying parties that share a
	// Store and Tenant but differ in those settings cannot finish each
	// other's ceremonies, and changing the settings invalidates pending
	// ceremonies. Still give differently configured relying parties distinct
	// Tenants, so one never consumes (and so cancels) the other's ceremony.
	Tenant string
	// Store holds pending ceremonies. Required.
	Store ChallengeStore
	// Policy holds the verification choices.
	Policy Policy
	// Timeout is the ceremony lifetime and the options timeout: five minutes
	// by default, between one second and ten minutes.
	Timeout time.Duration
	// MaxResponseBytes bounds a finish response: 64 KiB by default, between
	// 1 KiB and 1 MiB.
	MaxResponseBytes int
	// Clock returns the current time, for ceremony expiry and for the chain
	// check of [TrustRoots] during FinishRegistration. Nil means time.Now.
	// A [MemoryChallengeStore] evicts by its own Now; set both to one clock.
	Clock func() time.Time
}

// RelyingParty runs WebAuthn Level 3 registration and authentication
// ceremonies. It holds no per-ceremony state, so it is safe for concurrent
// use when its [ChallengeStore] is, and cheap enough to create per tenant.
// Create it with [New]; the zero value is not usable.
type RelyingParty struct {
	id, name   string
	rpIDHash   [32]byte
	origins    []string
	related    []string
	topOrigins []string
	tenant     string
	store      ChallengeStore
	policy     Policy
	timeout    time.Duration
	maxBytes   int
	now        func() time.Time
	// configHash fingerprints the settings verification depends on. Every
	// ceremony records it and consume compares it.
	configHash []byte
}

var (
	defaultAlgorithms = []cose.Algorithm{cose.AlgorithmES256, cose.AlgorithmEdDSA, cose.AlgorithmRS256}
	verifiedFormats   = []string{FormatNone, FormatPacked, FormatFIDOU2F}
)

// New validates config and returns a relying party. It performs no network
// or storage access. Failures wrap [ErrInvalidInput].
func New(config Config) (*RelyingParty, error) {
	invalid := func(format string, args ...any) error {
		return fmt.Errorf("%w: "+format, append([]any{ErrInvalidInput}, args...)...)
	}
	if config.Store == nil {
		return nil, invalid("a ChallengeStore is required")
	}
	if !validRPID(config.ID) {
		return nil, invalid("RP ID %q must be a lowercase domain name or localhost", config.ID)
	}
	rp := &RelyingParty{id: config.ID, name: config.Name, tenant: config.Tenant, store: config.Store,
		timeout: config.Timeout, maxBytes: config.MaxResponseBytes, now: config.Clock, rpIDHash: sha256.Sum256([]byte(config.ID))}
	if rp.name == "" {
		rp.name = config.ID
	}
	if len(rp.name) > 256 {
		return nil, invalid("name exceeds 256 bytes")
	}
	if rp.tenant == "" {
		rp.tenant = config.ID
	}
	if len(rp.tenant) > 256 {
		return nil, invalid("tenant exceeds 256 bytes")
	}
	if rp.now == nil {
		rp.now = time.Now
	}
	if rp.timeout == 0 {
		rp.timeout = 5 * time.Minute
	}
	if rp.timeout < time.Second || rp.timeout > 10*time.Minute {
		return nil, invalid("timeout must be between one second and ten minutes")
	}
	if rp.maxBytes == 0 {
		rp.maxBytes = 64 << 10
	}
	if rp.maxBytes < 1<<10 || rp.maxBytes > 1<<20 {
		return nil, invalid("response bound must be between 1 KiB and 1 MiB")
	}
	origins := config.Origins
	if len(origins) == 0 {
		origins = []string{"https://" + config.ID}
	}
	for _, list := range [][]string{origins, config.RelatedOrigins, config.TopOrigins} {
		if len(list) > 64 {
			return nil, invalid("at most 64 origins per list")
		}
	}
	for _, origin := range origins {
		host, web, ok := parseOrigin(origin)
		if !ok {
			return nil, invalid("origin %q is not an exact origin", origin)
		}
		if web && !withinRPID(host, config.ID) {
			return nil, invalid("origin %q is outside RP ID %q; list it in RelatedOrigins", origin, config.ID)
		}
		if web && strings.HasPrefix(origin, "http:") && !isLocalhost(config.ID) {
			return nil, invalid("HTTP origins are allowed only for a localhost RP ID")
		}
	}
	for _, origin := range config.RelatedOrigins {
		if _, web, ok := parseOrigin(origin); !ok || !web || !strings.HasPrefix(origin, "https://") {
			return nil, invalid("related origin %q must be an exact HTTPS origin", origin)
		}
	}
	for _, origin := range config.TopOrigins {
		if _, web, ok := parseOrigin(origin); !ok || !web {
			return nil, invalid("top origin %q must be an exact web origin", origin)
		}
	}
	rp.origins = slices.Clone(origins)
	rp.related = slices.Clone(config.RelatedOrigins)
	rp.topOrigins = slices.Clone(config.TopOrigins)

	policy := config.Policy
	if policy.UserVerification == "" {
		policy.UserVerification = UserVerificationRequired
	}
	if !policy.UserVerification.valid() {
		return nil, invalid("unknown user verification requirement %q", policy.UserVerification)
	}
	if len(policy.Algorithms) == 0 {
		policy.Algorithms = defaultAlgorithms
	}
	if len(policy.Algorithms) > 16 {
		return nil, invalid("at most 16 algorithms")
	}
	policy.Algorithms = slices.Clone(policy.Algorithms)
	for i, algorithm := range policy.Algorithms {
		if algorithm.Available() != nil || slices.Contains(policy.Algorithms[:i], algorithm) {
			return nil, invalid("algorithm %v is unsupported or repeated", algorithm)
		}
	}
	if len(policy.AttestationFormats) == 0 {
		policy.AttestationFormats = verifiedFormats
	}
	policy.AttestationFormats = slices.Clone(policy.AttestationFormats)
	for i, format := range policy.AttestationFormats {
		if !slices.Contains(verifiedFormats, format) || slices.Contains(policy.AttestationFormats[:i], format) {
			return nil, invalid("attestation format %q is not verified by this package or is repeated", format)
		}
	}
	if policy.Backup != BackupAllowed && policy.Backup != BackupForbidden {
		return nil, invalid("unknown backup policy")
	}
	if policy.Counter != CounterReject && policy.Counter != CounterReport {
		return nil, invalid("unknown counter policy")
	}
	rp.policy = policy
	rp.configHash = rp.fingerprint()
	return rp, nil
}

// fingerprint hashes, in a canonical order, the settings that ceremony
// verification depends on, so a ceremony begun under one configuration
// cannot finish under another sharing its Store and Tenant. TrustAttestation
// is a function and cannot be hashed.
func (rp *RelyingParty) fingerprint() []byte {
	h := sha256.New()
	write := func(values ...string) {
		h.Write(binary.BigEndian.AppendUint32(nil, uint32(len(values))))
		for _, v := range values {
			h.Write(binary.BigEndian.AppendUint32(nil, uint32(len(v))))
			h.Write([]byte(v))
		}
	}
	sorted := func(in []string) []string {
		out := slices.Clone(in)
		slices.Sort(out)
		return out
	}
	write("keyblade webauthn relyingparty config v1", rp.id)
	write(sorted(rp.origins)...)
	write(sorted(rp.related)...)
	write(sorted(rp.topOrigins)...)
	algorithms := make([]string, len(rp.policy.Algorithms))
	for i, algorithm := range rp.policy.Algorithms {
		algorithms[i] = strconv.Itoa(int(algorithm))
	}
	write(algorithms...)
	write(sorted(rp.policy.AttestationFormats)...)
	write(string(rp.policy.UserVerification), strconv.Itoa(int(rp.policy.Backup)), strconv.Itoa(int(rp.policy.Counter)))
	return h.Sum(nil)
}

// ID returns the RP ID.
func (rp *RelyingParty) ID() string { return rp.id }

// WellKnown returns the JSON document for https://ID/.well-known/webauthn,
// listing every configured web origin, for related origin requests. Serve
// it with Content-Type application/json only when RelatedOrigins is set.
// Browsers honor origins from at most five registrable domains in it; see
// [Config.RelatedOrigins].
// https://www.w3.org/TR/webauthn-3/#sctn-related-origins
func (rp *RelyingParty) WellKnown() []byte {
	origins := []string{}
	for _, origin := range slices.Concat(rp.origins, rp.related) {
		if _, web, _ := parseOrigin(origin); web {
			origins = append(origins, origin)
		}
	}
	data, _ := json.Marshal(struct {
		Origins []string `json:"origins"`
	}{origins})
	return data
}

// RegistrationRequest describes a registration ceremony to begin.
type RegistrationRequest struct {
	// Binding is a server-controlled value tied to the caller's
	// authenticated session, 16–512 bytes, such as a random session ID. The
	// finish call must present the same value. Never take it from the
	// request body.
	Binding string
	// User is the account to create a credential for. User.ID is the user
	// handle (1–64 opaque bytes); Name is required; both names are at most
	// 256 bytes.
	User UserEntity
	// ExcludeCredentials lists the account's existing credentials (at most
	// 256) so the authenticator does not register twice.
	ExcludeCredentials []CredentialDescriptor
	// ResidentKey defaults to [ResidentKeyPreferred].
	ResidentKey ResidentKey
	// Attachment, when set, restricts the authenticator attachment.
	Attachment AuthenticatorAttachment
	// UserVerification overrides [Policy.UserVerification].
	UserVerification UserVerification
	// Attestation defaults to [AttestationConveyanceNone].
	Attestation AttestationConveyance
	// Hints are advisory client UI hints, at most one of each.
	Hints []Hint
	// Extensions are passed to the client unchanged.
	Extensions *ExtensionInputs
}

// LoginRequest describes an authentication ceremony to begin.
type LoginRequest struct {
	// Binding is as in [RegistrationRequest].
	Binding string
	// UserHandle is the account being signed in to, when the user was
	// identified beforehand (username-first). Leave it empty for
	// discoverable, usernameless login; the authenticator then returns the
	// user handle and FinishLogin requires it.
	UserHandle []byte
	// AllowCredentials restricts which credentials may be used (at most
	// 256). Leave it empty for discoverable login.
	AllowCredentials []CredentialDescriptor
	// UserVerification overrides [Policy.UserVerification].
	UserVerification UserVerification
	// Mediation is [MediationConditional] for autofill sign-in.
	Mediation Mediation
	// Hints are advisory client UI hints, at most one of each.
	Hints []Hint
	// Extensions are passed to the client unchanged.
	Extensions *ExtensionInputs
}

// BeginRegistration creates and stores a registration ceremony and returns
// the options to send to the browser. The challenge is 32 bytes from
// crypto/rand.
//
// Call it only for an authenticated account (or a verified enrollment flow):
// adding a credential is a sensitive account change. It fails with
// [ErrInvalidInput] for out-of-bounds input, or with the store's error.
func (rp *RelyingParty) BeginRegistration(ctx context.Context, request RegistrationRequest) (*RegistrationOptions, error) {
	invalid := func(message string) error { return fmt.Errorf("%w: %s", ErrInvalidInput, message) }
	if !validBinding(request.Binding) {
		return nil, invalid("binding must be 16–512 bytes")
	}
	user := request.User
	if len(user.ID) == 0 || len(user.ID) > 64 {
		return nil, invalid("user handle must be 1–64 bytes")
	}
	if user.Name == "" || len(user.Name) > 256 || len(user.DisplayName) > 256 {
		return nil, invalid("user name is required and names are at most 256 bytes")
	}
	exclude, err := descriptors(request.ExcludeCredentials)
	if err != nil {
		return nil, err
	}
	residentKey := request.ResidentKey
	if residentKey == "" {
		residentKey = ResidentKeyPreferred
	}
	if residentKey != ResidentKeyDiscouraged && residentKey != ResidentKeyPreferred && residentKey != ResidentKeyRequired {
		return nil, invalid("unknown resident key requirement")
	}
	if a := request.Attachment; a != "" && a != AuthenticatorAttachmentPlatform && a != AuthenticatorAttachmentCrossPlatform {
		return nil, invalid("unknown authenticator attachment")
	}
	attestation := request.Attestation
	if attestation == "" {
		attestation = AttestationConveyanceNone
	}
	if attestation != AttestationConveyanceNone && attestation != AttestationConveyanceIndirect && attestation != AttestationConveyanceDirect {
		return nil, invalid("attestation conveyance must be none, indirect or direct")
	}
	verification, err := rp.verification(request.UserVerification)
	if err != nil {
		return nil, err
	}
	if err := validHints(request.Hints); err != nil {
		return nil, err
	}
	challenge, id, err := randomPair()
	if err != nil {
		return nil, err
	}
	ceremony := Ceremony{Kind: CeremonyRegistration, RPID: rp.id, Challenge: challenge, UserHandle: bytes.Clone(user.ID),
		UserVerification: verification, Algorithms: slices.Clone(rp.policy.Algorithms), Expires: rp.now().Add(rp.timeout),
		ConfigHash: bytes.Clone(rp.configHash)}
	parameters := make([]CredentialParameter, len(rp.policy.Algorithms))
	for i, algorithm := range rp.policy.Algorithms {
		parameters[i] = CredentialParameter{Type: "public-key", Algorithm: algorithm}
	}
	options := CreationOptions{
		RP:                 RelyingPartyEntity{ID: rp.id, Name: rp.name},
		User:               UserEntity{ID: bytes.Clone(user.ID), Name: user.Name, DisplayName: user.DisplayName},
		Challenge:          bytes.Clone(challenge),
		PubKeyCredParams:   parameters,
		Timeout:            uint32(rp.timeout / time.Millisecond),
		ExcludeCredentials: exclude,
		AuthenticatorSelection: AuthenticatorSelection{AuthenticatorAttachment: request.Attachment, ResidentKey: residentKey,
			RequireResidentKey: residentKey == ResidentKeyRequired, UserVerification: verification},
		Hints:       slices.Clone(request.Hints),
		Attestation: attestation,
		Extensions:  cloneExtensions(request.Extensions),
	}
	if err := rp.store.Put(ctx, rp.key(id, request.Binding), ceremony); err != nil {
		return nil, err
	}
	return &RegistrationOptions{ID: base64.RawURLEncoding.EncodeToString(id), Options: CredentialCreationOptions{PublicKey: options}}, nil
}

// BeginLogin creates and stores an authentication ceremony and returns the
// options to send to the browser. It fails with [ErrInvalidInput] for
// out-of-bounds input, or with the store's error.
func (rp *RelyingParty) BeginLogin(ctx context.Context, request LoginRequest) (*LoginOptions, error) {
	if !validBinding(request.Binding) {
		return nil, fmt.Errorf("%w: binding must be 16–512 bytes", ErrInvalidInput)
	}
	if len(request.UserHandle) > 64 {
		return nil, fmt.Errorf("%w: user handle must be at most 64 bytes", ErrInvalidInput)
	}
	allow, err := descriptors(request.AllowCredentials)
	if err != nil {
		return nil, err
	}
	if request.Mediation != MediationDefault && request.Mediation != MediationConditional {
		return nil, fmt.Errorf("%w: mediation must be empty or conditional", ErrInvalidInput)
	}
	verification, err := rp.verification(request.UserVerification)
	if err != nil {
		return nil, err
	}
	if err := validHints(request.Hints); err != nil {
		return nil, err
	}
	challenge, id, err := randomPair()
	if err != nil {
		return nil, err
	}
	ceremony := Ceremony{Kind: CeremonyLogin, RPID: rp.id, Challenge: challenge, UserHandle: bytes.Clone(request.UserHandle),
		UserVerification: verification, Mediation: request.Mediation, Expires: rp.now().Add(rp.timeout),
		ConfigHash: bytes.Clone(rp.configHash)}
	for _, d := range allow {
		ceremony.AllowCredentials = append(ceremony.AllowCredentials, bytes.Clone(d.ID))
	}
	options := RequestOptions{
		Challenge:        bytes.Clone(challenge),
		Timeout:          uint32(rp.timeout / time.Millisecond),
		RPID:             rp.id,
		AllowCredentials: allow,
		UserVerification: verification,
		Hints:            slices.Clone(request.Hints),
		Extensions:       cloneExtensions(request.Extensions),
	}
	if err := rp.store.Put(ctx, rp.key(id, request.Binding), ceremony); err != nil {
		return nil, err
	}
	return &LoginOptions{ID: base64.RawURLEncoding.EncodeToString(id), Options: CredentialRequestOptions{PublicKey: options, Mediation: request.Mediation}}, nil
}

// Cancel consumes a pending ceremony so it can no longer finish. Browser
// cancellation does not reach the server; call Cancel when the user aborts.
func (rp *RelyingParty) Cancel(ctx context.Context, id, binding string) error {
	_, err := rp.consume(ctx, id, binding, "")
	return err
}

// FinishRegistration verifies a registration response against the pending
// ceremony id, following WebAuthn Level 3 §7.1 step by step:
// https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential
//
// The ceremony is consumed before the response is parsed, so every attempt,
// successful or not, needs a new BeginRegistration. binding must equal the
// begin request's Binding; a different binding finds no ceremony and
// consumes nothing. response is the RegistrationResponseJSON body.
//
// On success the caller must store the returned credential for its user,
// rejecting a credential ID that is already registered. Failures wrap
// [ErrChallenge], [ErrMalformed], [ErrVerification] or [ErrUnsupported];
// verification failures are [*VerificationError] values naming the step.
func (rp *RelyingParty) FinishRegistration(ctx context.Context, id, binding string, response []byte) (*Registration, error) {
	const kind = CeremonyRegistration
	ceremony, err := rp.consume(ctx, id, binding, kind)
	if err != nil {
		return nil, err
	}
	if len(response) > rp.maxBytes {
		return nil, fmt.Errorf("%w: response exceeds %d bytes", ErrMalformed, rp.maxBytes)
	}
	credential, err := ParseRegistrationResponse(response)
	if err != nil {
		return nil, err
	}
	// Steps 5–6: "Let JSONtext be the result of running UTF-8 decode on the
	// value of response.clientDataJSON" and parse it as C.
	clientData, err := ParseClientData(credential.Response.ClientDataJSON)
	if err != nil {
		return nil, err
	}
	// Steps 7–10: C.type, C.challenge, C.origin, C.crossOrigin, C.topOrigin.
	if err := rp.verifyClientData(kind, clientData, "webauthn.create", ceremony.Challenge, specRegistration); err != nil {
		return nil, err
	}
	// Step 11: "Let hash be the result of computing a hash over
	// response.clientDataJSON using SHA-256."
	clientDataHash := sha256.Sum256(credential.Response.ClientDataJSON)
	// Step 12: "Perform CBOR decoding on the attestationObject field ... to
	// obtain the attestation statement format fmt, the authenticator data
	// authData, and the attestation statement attStmt."
	object, err := ParseAttestationObject(credential.Response.AttestationObject)
	if err != nil {
		return nil, err
	}
	auth, err := ParseAuthenticatorData(object.AuthData)
	if err != nil {
		return nil, err
	}
	if auth.Attested == nil {
		return nil, failure(kind, ErrMalformed, specAuthData, "authenticator data lacks attested credential data")
	}
	// Step 24: "Verify that the credentialId is ≤ 1023 bytes." Checked here,
	// before any attestation work or policy callback sees the ID.
	if len(auth.Attested.CredentialID) > maxCredentialID {
		return nil, failure(kind, ErrVerification, specRegistration, "credential ID is longer than 1023 bytes")
	}
	if len(credential.Response.AuthenticatorData) != 0 && !bytes.Equal(credential.Response.AuthenticatorData, object.AuthData) {
		return nil, failure(kind, ErrMalformed, specJSON, "response authenticatorData differs from the attestation object")
	}
	// Step 13: "Verify that the rpIdHash in authData is the SHA-256 hash of
	// the RP ID expected by the Relying Party."
	if err := rp.checkFlags(kind, auth, ceremony.UserVerification, specRegistration); err != nil {
		return nil, err
	}
	// Step 17: evaluate BE for the relying party's policy.
	if rp.policy.Backup == BackupForbidden && auth.Flags.Has(FlagBackupEligible) {
		return nil, failure(kind, ErrVerification, specBackup, "backup-eligible credentials are not accepted by policy")
	}
	// Step 19: "Verify that the "alg" parameter in the credential public key
	// in authData matches the alg attribute of one of the items in
	// pkOptions.pubKeyCredParams."
	key, err := ParsePublicKey(auth.Attested.PublicKey)
	if err != nil {
		return nil, failure(kind, sentinel(err), specAlgorithms, "credential public key: "+err.Error())
	}
	if !slices.Contains(ceremony.Algorithms, key.Algorithm) {
		return nil, failure(kind, ErrVerification, specRegistration, "credential algorithm "+key.Algorithm.String()+" was not offered")
	}
	// The credential ID in the signed authenticator data is the one the
	// relying party will store; the unsigned rawId must name the same one.
	if !bytes.Equal(credential.RawID, auth.Attested.CredentialID) {
		return nil, failure(kind, ErrVerification, specRegistration, "rawId differs from the attested credential ID")
	}
	// Step 20: "Determine the attestation statement format by performing a
	// USASCII case-sensitive match on fmt against the set of supported
	// WebAuthn Attestation Statement Format Identifier values."
	if slices.Contains(verifiedFormats, object.Format) && !slices.Contains(rp.policy.AttestationFormats, object.Format) {
		return nil, failure(kind, ErrVerification, specRegistration, "attestation format "+object.Format+" is not accepted by policy")
	}
	// Step 21: "Verify that attStmt is a correct attestation statement,
	// conveying a valid attestation signature, by using the attestation
	// statement format fmt's verification procedure given attStmt, authData
	// and hash."
	attestation, err := verifyStatement(object, auth, key, clientDataHash[:])
	if err != nil {
		return nil, err
	}
	// Steps 22–23: obtain trust anchors and assess the attestation's
	// trustworthiness, as the relying party's policy decides. The context
	// carries the relying party's clock for [TrustRoots].
	if rp.policy.TrustAttestation != nil {
		trustCtx := context.WithValue(ctx, verificationTimeKey{}, rp.now())
		if err := rp.policy.TrustAttestation(trustCtx, *cloneAttestation(attestation)); err != nil {
			return nil, &VerificationError{Ceremony: kind, Step: "attestation is not trusted by policy", Spec: specRegistration, Err: errors.Join(ErrVerification, err)}
		}
	}
	// Step 25 (credential ID not registered to any user) is the caller's
	// store insert. Step 26: create the credential record.
	record := Credential{
		ID:                        bytes.Clone(auth.Attested.CredentialID),
		UserHandle:                bytes.Clone(ceremony.UserHandle),
		RPID:                      rp.id,
		PublicKey:                 bytes.Clone(auth.Attested.PublicKey),
		Algorithm:                 key.Algorithm,
		SignCount:                 auth.SignCount,
		Transports:                cleanTransports(credential.Response.Transports),
		UVInitialized:             auth.Flags.Has(FlagUserVerified),
		BackupEligible:            auth.Flags.Has(FlagBackupEligible),
		BackupState:               auth.Flags.Has(FlagBackupState),
		AAGUID:                    auth.Attested.AAGUID,
		AttestationFormat:         attestation.Format,
		AttestationType:           attestation.Type,
		AttestationObject:         bytes.Clone(credential.Response.AttestationObject),
		AttestationClientDataJSON: bytes.Clone(credential.Response.ClientDataJSON),
	}
	// Step 27: client and authenticator extension outputs. Authenticator
	// outputs are structurally checked and otherwise ignored; client outputs
	// are returned as unsigned claims.
	return &Registration{Credential: record, Attestation: *cloneAttestation(attestation), UserVerified: auth.Flags.Has(FlagUserVerified),
		Extensions: credential.ClientExtensionResults, AuthenticatorAttachment: credential.AuthenticatorAttachment}, nil
}

// FinishLogin verifies an authentication response against the pending
// ceremony id, following WebAuthn Level 3 §7.2 step by step:
// https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion
//
// lookup resolves the asserted credential; see [CredentialLookup]. As with
// FinishRegistration, the ceremony is consumed before parsing. On success
// the caller persists [Login.Credential] (compare-and-swap on the previous
// counter) and only then creates its own session. Failures wrap
// [ErrChallenge], [ErrMalformed], [ErrVerification], [ErrCounter] or
// [ErrUnsupported], or are lookup's own error when it does not wrap
// [ErrCredential].
//
// lookup is called only after the challenge, client data, origin, rpIdHash
// and flags verify. Then an unknown credential (lookup returns
// [ErrCredential]), a record of another account or relying party, and an
// invalid signature all return the same [*VerificationError], wrapping
// [ErrVerification], with the same message; only its Detail field, meant
// for operator logs, tells them apart.
func (rp *RelyingParty) FinishLogin(ctx context.Context, id, binding string, response []byte, lookup CredentialLookup) (*Login, error) {
	const kind = CeremonyLogin
	if lookup == nil {
		return nil, fmt.Errorf("%w: a CredentialLookup is required", ErrInvalidInput)
	}
	ceremony, err := rp.consume(ctx, id, binding, kind)
	if err != nil {
		return nil, err
	}
	if len(response) > rp.maxBytes {
		return nil, fmt.Errorf("%w: response exceeds %d bytes", ErrMalformed, rp.maxBytes)
	}
	credential, err := ParseAuthenticationResponse(response)
	if err != nil {
		return nil, err
	}
	// Step 5: "If pkOptions.allowCredentials is not empty, verify that
	// credential.id identifies one of the public key credentials listed".
	if len(ceremony.AllowCredentials) != 0 && !slices.ContainsFunc(ceremony.AllowCredentials, func(id []byte) bool { return bytes.Equal(id, credential.RawID) }) {
		return nil, failure(kind, ErrVerification, specAssertion, "credential was not in allowCredentials")
	}
	// Step 6, first half: identify the user account.
	owner := ceremony.UserHandle
	returned := []byte(credential.Response.UserHandle)
	if len(owner) != 0 {
		// "If response.userHandle is present, verify that it equals the user
		// handle of the user account."
		if len(returned) != 0 && !bytes.Equal(returned, owner) {
			return nil, failure(kind, ErrVerification, specAssertion, "userHandle differs from the identified account")
		}
	} else {
		// "verify that response.userHandle is present."
		if len(returned) == 0 || len(returned) > 64 {
			return nil, failure(kind, ErrVerification, specAssertion, "discoverable login returned no userHandle")
		}
		owner = returned
	}
	// Steps 8–14 run before the credential record is looked up, so a
	// response that does not answer this ceremony's challenge from an
	// allowed origin learns nothing about which credentials exist.
	//
	// Steps 8–10: decode and parse the client data.
	clientData, err := ParseClientData(credential.Response.ClientDataJSON)
	if err != nil {
		return nil, err
	}
	// Steps 11–14: C.type, C.challenge, C.origin, C.crossOrigin, C.topOrigin.
	if err := rp.verifyClientData(kind, clientData, "webauthn.get", ceremony.Challenge, specAssertion); err != nil {
		return nil, err
	}
	auth, err := ParseAuthenticatorData(credential.Response.AuthenticatorData)
	if err != nil {
		return nil, err
	}
	if auth.Attested != nil {
		return nil, failure(kind, ErrMalformed, specAuthData, "assertion authenticator data carries attested credential data")
	}
	// Steps 15–18: rpIdHash, UP, UV and the BE/BS consistency rule.
	if err := rp.checkFlags(kind, auth, ceremony.UserVerification, specAssertion); err != nil {
		return nil, err
	}
	currentBE, currentBS := auth.Flags.Has(FlagBackupEligible), auth.Flags.Has(FlagBackupState)
	if rp.policy.Backup == BackupForbidden && currentBE {
		return nil, failure(kind, ErrVerification, specBackup, "backup-eligible credentials are not accepted by policy")
	}
	// Step 6, second half: look up the credential record. From here until
	// the signature verifies, an unknown credential, a record of another
	// account or relying party and a bad signature fail with the same error,
	// so the outcome is not an oracle for which credential IDs exist.
	record, err := lookup(ctx, bytes.Clone(credential.RawID), bytes.Clone(owner))
	if err != nil {
		if errors.Is(err, ErrCredential) {
			return nil, assertionFailure("no credential record for this credential and account")
		}
		return nil, err
	}
	if record == nil || !bytes.Equal(record.ID, credential.RawID) || !bytes.Equal(record.UserHandle, owner) || record.RPID != rp.id {
		return nil, assertionFailure("credential record does not belong to this account and relying party")
	}
	// A stored record that does not parse is the relying party's own
	// corruption, not something a client can probe for, so it says so.
	key, err := ParsePublicKey(record.PublicKey)
	if err != nil {
		return nil, failure(kind, sentinel(err), specCredRecord, "stored credential public key: "+err.Error())
	}
	if record.Algorithm != 0 && record.Algorithm != key.Algorithm {
		return nil, failure(kind, ErrVerification, specCredRecord, "stored algorithm differs from the stored key")
	}
	// Steps 20–21: "Using credentialRecord.publicKey, verify that sig is a
	// valid signature over the binary concatenation of authData and hash."
	clientDataHash := sha256.Sum256(credential.Response.ClientDataJSON)
	signed := append(bytes.Clone(credential.Response.AuthenticatorData), clientDataHash[:]...)
	if key.Verify(signed, credential.Response.Signature) != nil {
		return nil, assertionFailure("assertion signature is invalid")
	}
	// Step 19: "If credentialRecord.backupEligible is set, verify that
	// currentBe is set. If credentialRecord.backupEligible is not set,
	// verify that currentBe is not set." Checked after the signature so it
	// reveals nothing about a record to an unauthenticated response.
	if currentBE != record.BackupEligible {
		return nil, failure(kind, ErrVerification, specAssertion, "backup eligibility changed since registration")
	}
	// Step 22: the signature counter.
	result := &Login{PreviousSignCount: record.SignCount, UserHandle: bytes.Clone(owner), UserVerified: auth.Flags.Has(FlagUserVerified),
		BackupStateChanged: currentBS != record.BackupState, Extensions: credential.ClientExtensionResults,
		AuthenticatorAttachment: credential.AuthenticatorAttachment}
	updated := record.Clone()
	if auth.SignCount != 0 || record.SignCount != 0 {
		if auth.SignCount > record.SignCount {
			updated.SignCount = auth.SignCount
		} else if rp.policy.Counter == CounterReject {
			return nil, failure(kind, ErrCounter, specSignCount, "signature counter did not increase")
		} else {
			// Report and keep the higher stored value, so a replayed or
			// cloned low counter cannot roll the record back.
			result.CounterAnomaly = true
		}
	}
	// Step 24: update the credential record.
	updated.BackupState = currentBS
	if !updated.UVInitialized && result.UserVerified {
		updated.UVInitialized = true
	}
	result.Credential = updated
	return result, nil
}

// verifyClientData applies the client data steps shared by both ceremonies.
func (rp *RelyingParty) verifyClientData(kind CeremonyKind, c *CollectedClientData, typ string, challenge []byte, spec string) error {
	// "Verify that the value of C.type is webauthn.create" / "webauthn.get".
	if c.Type != typ {
		return failure(kind, ErrVerification, spec, "client data type is not "+typ)
	}
	// "Verify that the value of C.challenge equals the base64url encoding of
	// pkOptions.challenge."
	expected := base64.RawURLEncoding.EncodeToString(challenge)
	if subtle.ConstantTimeCompare([]byte(c.Challenge), []byte(expected)) != 1 {
		return failure(kind, ErrVerification, spec, "client data challenge does not match the ceremony")
	}
	// "Verify that the value of C.origin is an origin expected by the
	// Relying Party." Exact string matching, as §13.4.9 recommends.
	if !slices.Contains(rp.origins, c.Origin) && !slices.Contains(rp.related, c.Origin) {
		return failure(kind, ErrVerification, specOrigin, "client data origin is not allowed")
	}
	// "If C.crossOrigin is present and set to true, verify that the Relying
	// Party expects that this credential would have been created within an
	// iframe that is not same-origin with its ancestors." Level 3 clients
	// set topOrigin whenever crossOrigin is true; requiring it lets the
	// relying party check which page embedded the ceremony.
	if c.CrossOrigin && (len(rp.topOrigins) == 0 || c.TopOrigin == "") {
		return failure(kind, ErrVerification, spec, "cross-origin ceremony is not allowed")
	}
	// "If C.topOrigin is present: verify that the Relying Party expects ...
	// an iframe that is not same-origin with its ancestors. Verify that the
	// value of C.topOrigin matches the origin of a page that the Relying
	// Party expects to be sub-framed within."
	if c.TopOrigin != "" && (!c.CrossOrigin || !slices.Contains(rp.topOrigins, c.TopOrigin)) {
		return failure(kind, ErrVerification, specOrigin, "client data topOrigin is not allowed")
	}
	return nil
}

// checkFlags applies the rpIdHash, UP, UV and BE/BS steps shared by both
// ceremonies.
func (rp *RelyingParty) checkFlags(kind CeremonyKind, auth *AuthenticatorData, verification UserVerification, spec string) error {
	if subtle.ConstantTimeCompare(auth.RPIDHash[:], rp.rpIDHash[:]) != 1 {
		return failure(kind, ErrVerification, spec, "rpIdHash is not the SHA-256 of the RP ID")
	}
	// "verify that the UP bit of the flags in authData is set."
	if !auth.Flags.Has(FlagUserPresent) {
		return failure(kind, ErrVerification, spec, "user presence flag is not set")
	}
	// "If the Relying Party requires user verification ..., verify that the
	// UV bit of the flags in authData is set."
	if verification == UserVerificationRequired && !auth.Flags.Has(FlagUserVerified) {
		return failure(kind, ErrVerification, spec, "user verification was required but the UV flag is not set")
	}
	// "If the BE bit of the flags in authData is not set, verify that the BS
	// bit is not set."
	if !auth.Flags.Has(FlagBackupEligible) && auth.Flags.Has(FlagBackupState) {
		return failure(kind, ErrVerification, specBackup, "backup state is set on a credential that is not backup eligible")
	}
	return nil
}

// consume validates the ceremony ID and binding syntax, then atomically takes
// the ceremony. An empty kind accepts either kind (for Cancel).
func (rp *RelyingParty) consume(ctx context.Context, id, binding string, kind CeremonyKind) (Ceremony, error) {
	raw, err := base64.RawURLEncoding.Strict().DecodeString(id)
	if err != nil || len(raw) != 32 || !validBinding(binding) {
		return Ceremony{}, ErrChallenge
	}
	ceremony, err := rp.store.Consume(ctx, rp.key(raw, binding), rp.now())
	if err != nil {
		return Ceremony{}, err
	}
	if (kind != "" && ceremony.Kind != kind) || ceremony.RPID != rp.id || !rp.now().Before(ceremony.Expires) || len(ceremony.Challenge) < 16 || len(ceremony.Challenge) > 1024 ||
		subtle.ConstantTimeCompare(ceremony.ConfigHash, rp.configHash) != 1 {
		return Ceremony{}, ErrChallenge
	}
	return ceremony, nil
}

// key derives the store key from the ceremony ID and session binding, so a
// request with the wrong binding misses the ceremony instead of consuming it.
func (rp *RelyingParty) key(id []byte, binding string) CeremonyKey {
	bindingHash := sha256.Sum256([]byte(binding))
	h := sha256.New()
	h.Write([]byte("keyblade webauthn relyingparty ceremony v1\x00"))
	h.Write(id)
	h.Write(bindingHash[:])
	return CeremonyKey{Tenant: rp.tenant, ID: base64.RawURLEncoding.EncodeToString(h.Sum(nil))}
}

func (rp *RelyingParty) verification(override UserVerification) (UserVerification, error) {
	if override == "" {
		return rp.policy.UserVerification, nil
	}
	if !override.valid() {
		return "", fmt.Errorf("%w: unknown user verification requirement", ErrInvalidInput)
	}
	return override, nil
}

func randomPair() (challenge, id []byte, err error) {
	buffer := make([]byte, 64)
	if _, err := rand.Read(buffer); err != nil {
		return nil, nil, err
	}
	return buffer[:32:32], buffer[32:], nil
}

func validBinding(binding string) bool { return len(binding) >= 16 && len(binding) <= 512 }

func descriptors(in []CredentialDescriptor) ([]CredentialDescriptor, error) {
	if len(in) > 256 {
		return nil, fmt.Errorf("%w: at most 256 credential descriptors", ErrInvalidInput)
	}
	var out []CredentialDescriptor
	for _, d := range in {
		if len(d.ID) == 0 || len(d.ID) > maxCredentialID || (d.Type != "" && d.Type != "public-key") || len(d.Transports) > 8 {
			return nil, fmt.Errorf("%w: credential descriptor IDs must be 1–1023 bytes", ErrInvalidInput)
		}
		out = append(out, CredentialDescriptor{Type: "public-key", ID: bytes.Clone(d.ID), Transports: cleanTransports(d.Transports)})
	}
	return out, nil
}

func validHints(hints []Hint) error {
	for i, hint := range hints {
		if (hint != HintSecurityKey && hint != HintClientDevice && hint != HintHybrid) || slices.Contains(hints[:i], hint) {
			return fmt.Errorf("%w: hints must be distinct known values", ErrInvalidInput)
		}
	}
	return nil
}

// cleanTransports keeps at most eight short, distinct transport strings.
// Unknown values are kept, as the specification asks relying parties to
// store them for future clients.
func cleanTransports(in []Transport) []Transport {
	var out []Transport
	for _, t := range in {
		if len(out) == 8 {
			break
		}
		if t != "" && len(t) <= 32 && !slices.Contains(out, t) {
			out = append(out, t)
		}
	}
	return out
}

func cloneExtensions(in *ExtensionInputs) *ExtensionInputs {
	if in == nil {
		return nil
	}
	out := &ExtensionInputs{CredProps: in.CredProps}
	if in.PRF != nil {
		out.PRF = &PRFInputs{}
		if in.PRF.Eval != nil {
			out.PRF.Eval = &PRFValues{First: bytes.Clone(in.PRF.Eval.First), Second: bytes.Clone(in.PRF.Eval.Second)}
		}
		if in.PRF.EvalByCredential != nil {
			out.PRF.EvalByCredential = make(map[string]PRFValues, len(in.PRF.EvalByCredential))
			for k, v := range in.PRF.EvalByCredential {
				out.PRF.EvalByCredential[k] = PRFValues{First: bytes.Clone(v.First), Second: bytes.Clone(v.Second)}
			}
		}
	}
	return out
}

func cloneAttestation(a *Attestation) *Attestation {
	out := *a
	if a.Certificates != nil {
		out.Certificates = make([][]byte, len(a.Certificates))
		for i, c := range a.Certificates {
			out.Certificates[i] = bytes.Clone(c)
		}
	}
	return &out
}

// sentinel returns the package sentinel that classifies err.
func sentinel(err error) error {
	if errors.Is(err, ErrUnsupported) {
		return ErrUnsupported
	}
	return ErrMalformed
}

// validRPID reports whether id is a lowercase DNS name or "localhost". It
// cannot check the public suffix list; browsers enforce that an RP ID is a
// registrable domain suffix of the page's origin.
func validRPID(id string) bool {
	if id == "localhost" {
		return true
	}
	if len(id) == 0 || len(id) > 253 || strings.ToLower(id) != id {
		return false
	}
	if _, err := netip.ParseAddr(id); err == nil {
		return false
	}
	labels := strings.Split(id, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

// parseOrigin checks that origin is an exact serialized origin. For a web
// origin it returns the host and web=true. A native origin is "scheme:rest"
// with a lowercase scheme, no "//" and no whitespace, matched exactly.
func parseOrigin(origin string) (host string, web, ok bool) {
	if len(origin) == 0 || len(origin) > 2048 || strings.ContainsAny(origin, " \t\r\n") {
		return "", false, false
	}
	if strings.HasPrefix(origin, "https://") || strings.HasPrefix(origin, "http://") {
		u, err := url.Parse(origin)
		if err != nil || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || u.String() != origin {
			return "", true, false
		}
		host = u.Hostname()
		if strings.ToLower(u.Host) != u.Host || (u.Scheme == "https" && u.Port() == "443") || (u.Scheme == "http" && u.Port() == "80") {
			return "", true, false
		}
		if u.Scheme == "http" && host != "localhost" && !strings.HasSuffix(host, ".localhost") {
			return "", true, false
		}
		return host, true, true
	}
	scheme, rest, found := strings.Cut(origin, ":")
	if !found || scheme == "" || rest == "" || strings.HasPrefix(rest, "//") {
		return "", false, false
	}
	for _, c := range scheme {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '+' || c == '.') {
			return "", false, false
		}
	}
	return "", false, true
}

// isLocalhost reports whether rpID is "localhost" or a subdomain of it, the
// RP IDs whose web origins may use plain HTTP, as parseOrigin allows.
func isLocalhost(rpID string) bool {
	return rpID == "localhost" || strings.HasSuffix(rpID, ".localhost")
}

// withinRPID reports whether host is the RP ID or one of its subdomains.
func withinRPID(host, rpID string) bool {
	return host == rpID || strings.HasSuffix(host, "."+rpID)
}
