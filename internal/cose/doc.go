// Package cose is the COSE signature vocabulary that Keyblade's FIDO,
// WebAuthn and approval code share: typed algorithm identifiers from the
// IANA COSE Algorithms registry, strict parsing and encoding of COSE_Key
// public keys, and signature verification that takes the signed message,
// never a digest.
//
// It implements the signature algorithms that CTAP authenticators, WebAuthn
// relying parties and platform approval keys use:
//
//   - ECDSA: ES256, ES384 and ES512 ([RFC 9053 §2.1]), and the fully
//     specified ESP256, ESP384 and ESP512 ([RFC 9864 §2.1]);
//   - EdDSA with Ed25519: EdDSA ([RFC 9053 §2.2]) and the fully specified
//     Ed25519 ([RFC 9864 §2.2]);
//   - RSA: RS256, RS384 and RS512 ([RFC 8812 §2]), and PS256
//     ([RFC 8230 §2]).
//
// Here every identifier names exactly one key type, curve and hash, which
// [Algorithm.Descriptor] reports. The polymorphic ES256, ES384 and ES512
// are pinned to P-256, P-384 and P-521, the pairings RFC 9053 §2.1 suggests
// and WebAuthn requires, and EdDSA to Ed25519.
//
// # Agility
//
// Adding an algorithm is one entry in the table behind
// [Algorithm.Descriptor]; nothing else dispatches on identifiers. An
// identifier the table lacks is still a valid [Algorithm]: it formats as
// Algorithm(N), round-trips through text and JSON, and fails with
// [ErrUnsupported] from [Algorithm.Available], [ParsePublicKey],
// [MarshalPublicKey] and [Verify]. Callers choose which identifiers they
// accept; this package never negotiates.
//
// Go exports no ML-DSA or SLH-DSA, so this package claims no post-quantum
// signature and reserves no identifiers for one. Because [Verify] takes the
// message rather than a digest, a message-signing algorithm such as ML-DSA
// will be a table entry when Go provides it.
//
// # Signature encodings
//
// [Verify] takes signatures as COSE encodes them: ECDSA as the fixed-length
// concatenation of r and s ([RFC 9053 §2.1]). CTAP and WebAuthn instead carry
// ECDSA signatures in ASN.1 DER ([WebAuthn signature formats]), which [VerifyASN1]
// takes. EdDSA and RSA signatures are the same in both.
//
// # Errors
//
// Errors match one of four categories with [errors.Is]: [ErrInvalidInput]
// for an argument that can never succeed, [ErrFormat] for encoded data that
// is not well formed, [ErrUnsupported] for an algorithm, key type or curve
// this package does not implement, and [ErrVerification] for a signature
// that does not verify.
//
// # Scope
//
// The module depends only on the standard library and
// github.com/picatz/cbor, so modules that must not require the Keyblade root
// module, such as webauthn, can import it. It does not implement COSE
// messages such as COSE_Sign1, key agreement, MACs or private keys.
//
// Stability: experimental
//
// It's lifted from the cose package of github.com/picatz/go-keyblade
// at commit f19051863d21, for [github.com/picatz/doh/internal/webauthn].
//
// [RFC 9053 §2.1]: https://www.rfc-editor.org/rfc/rfc9053.html#section-2.1
// [RFC 9053 §2.2]: https://www.rfc-editor.org/rfc/rfc9053.html#section-2.2
// [RFC 9864 §2.1]: https://www.rfc-editor.org/rfc/rfc9864.html#section-2.1
// [RFC 9864 §2.2]: https://www.rfc-editor.org/rfc/rfc9864.html#section-2.2
// [RFC 8812 §2]: https://www.rfc-editor.org/rfc/rfc8812.html#section-2
// [RFC 8230 §2]: https://www.rfc-editor.org/rfc/rfc8230.html#section-2
// [WebAuthn signature formats]: https://www.w3.org/TR/webauthn-3/#sctn-signature-attestation-types
package cose
