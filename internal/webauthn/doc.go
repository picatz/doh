// Package webauthn is a native WebAuthn Level 3 relying party: it builds
// registration and authentication options and verifies the browser's
// responses, step by step as the specification orders them, using only the
// standard library and [github.com/picatz/cbor].
//
// It runs anywhere Go does, including js/wasm and wasip1/wasm.
//
// It's lifted from the relyingparty package of
// github.com/picatz/go-keyblade at commit f19051863d21, with its
// dependencies [github.com/picatz/doh/internal/cose] and
// [github.com/picatz/doh/internal/strictjson], so doh carries no
// dependency on that module. Fixes belong upstream first.
//
// # Ceremonies
//
// Create a [RelyingParty] with [New] from a [Config] naming the RP ID, the
// allowed origins and a [ChallengeStore]. Each ceremony is two calls:
//
//   - [RelyingParty.BeginRegistration] returns [RegistrationOptions] for
//     navigator.credentials.create; [RelyingParty.FinishRegistration]
//     verifies the RegistrationResponseJSON and returns a [Credential] to
//     store (WebAuthn §7.1).
//   - [RelyingParty.BeginLogin] returns [LoginOptions] for
//     navigator.credentials.get, for username-first, discoverable or
//     conditional (autofill) login; [RelyingParty.FinishLogin] verifies the
//     AuthenticationResponseJSON against the record a [CredentialLookup]
//     returns and reports the updated record to persist (WebAuthn §7.2).
//
// Options and responses use the WebAuthn Level 3 JSON serialization, so the
// browser side is parseCreationOptionsFromJSON, parseRequestOptionsFromJSON
// and PublicKeyCredential.toJSON with no conversion code.
//
// # Challenges
//
// Challenges are 32 bytes from crypto/rand and never leave the server except
// inside the options. A ceremony is bound to a server-controlled session
// value and stored under a key derived from the ceremony ID and that value;
// [ChallengeStore.Consume] must take it atomically, so a challenge can be
// used at most once and a request with the wrong session cannot consume
// another session's ceremony. Every finish call consumes its ceremony before
// parsing, whatever the outcome. [CeremonyKey] carries a tenant, so one store
// can serve many relying parties. [MemoryChallengeStore] is a bounded
// in-process implementation.
//
// # Verification
//
// Verification checks client data type, challenge, origin, crossOrigin and
// topOrigin; the RP ID hash; the UP, UV, BE and BS flag rules; the credential
// algorithm against the offered parameters; COSE keys for ES256, ES384,
// ES512 (and their fully specified ESP forms), EdDSA/Ed25519, RS256, RS384,
// RS512 and PS256; the "none", "packed" (self and x5c) and "fido-u2f"
// attestation formats; credential ID length; assertion signatures over
// authenticatorData || SHA-256(clientDataJSON); the signature counter; and
// user handles for discoverable login. A failed step returns a
// [*VerificationError] that names the step and links its specification
// section. Formats this package does not verify yet ("tpm", "android-key",
// "android-safetynet", "apple", "compound") fail with [ErrUnsupported].
//
// # Trust
//
// A verified attestation proves which key signed the creation, not that the
// key belongs to a trustworthy model: [Policy.TrustAttestation] (for example
// [TrustRoots]) makes that decision, and by default none is made. Client
// extension outputs, transports and the authenticator attachment are client
// claims and are returned as such. The relying party authenticates a
// credential; it does not create the application's session, which belongs
// after the caller has persisted the updated [Credential].
//
// # Limits
//
// Responses are bounded by [Config.MaxResponseBytes] (64 KiB by default),
// client data by 16 KiB, authenticator data by 64 KiB and COSE keys by
// 2 KiB; RSA keys must be 2048–8192 bits. Related origins are checked by
// exact match against [Config.RelatedOrigins]; this package does not fetch
// or validate anyone's /.well-known/webauthn. It has had no independent
// security audit and claims no FIDO conformance certification.
//
// Stability: experimental
package webauthn
