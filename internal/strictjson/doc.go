// Package strictjson decodes untrusted JSON with one definition of strict.
//
// encoding/json is lenient in ways that let two parsers read different
// meanings from one document: it keeps the last of two members with the same
// name, matches member names without regard to case, replaces invalid UTF-8
// and lone UTF-16 surrogate escapes with U+FFFD, ignores members the target
// does not define, and stops at the end of the first value. Signed and
// security-relevant formats (JWS and JWT headers and claims, WebAuthn client
// data, DSSE envelopes, in-toto statements, on-disk records) need one answer.
//
// [Check] and [Unmarshal] refuse, at any depth:
//
//   - a member name repeated within one object ([ErrDuplicateMember]);
//   - data after the first value ([ErrTrailingData]);
//   - invalid UTF-8, a lone surrogate escape, empty input or other syntax
//     errors ([ErrSyntax]);
//   - nesting deeper than [MaxDepth] ([ErrTooDeep]).
//
// [Unmarshal] also refuses a member the target struct does not define, and a
// member that differs from a defined one only in case ([ErrUnknownMember]),
// and a top-level null where an object is required ([ErrType]).
// [UnmarshalOpen] and [UnmarshalExtra] are the open variants for formats that
// allow extension members, such as JWT claims; they still refuse duplicates
// and case-only collisions.
//
// # Duplicate members
//
// RFC 8259 §4 says member names within an object "SHOULD be unique" and that
// when they are not, "the behavior of software that receives such an object
// is unpredictable". RFC 7493 §2.3 (I-JSON) forbids them outright, and
// RFC 7515 §5.2 requires a JWS to be rejected, or its duplicates handled as
// RFC 7493 requires, when the protected header repeats a name. A repeated
// name is a differential between parsers, so this package refuses it rather
// than choosing the first or the last. Names are compared after unescaping,
// so "a" and "a" are duplicates. Names that differ only in case are
// distinct members for [Check] but are refused by [Unmarshal] when they
// would bind to the same Go field, which encoding/json would do silently.
//
// # Matching encoding/json
//
// The scanner follows the Go type the way encoding/json decodes it, so the
// names it checks are the names json binds: embedded-field dominance and tag
// rules as in typeFields, map keys decoded as json decodes them (so "1" and
// "01" are one key of a map[int]T), pointers and non-nil interfaces holding
// pointers, the spare capacity json reuses in a slice, and the ,string option,
// whose quoted text is held to the same rules as a document. Types with their
// own UnmarshalJSON or UnmarshalText are opaque: such a method that decodes
// an object must itself use this package.
//
// # Resource use
//
// [Check] and [Unmarshal] scan the input once, without building a tree. They
// hold the member names of the objects open at that moment, a stack bounded
// by [MaxDepth], so extra memory is bounded by the widest single object and
// a 15 MiB array of small objects is checked without allocating. The
// package applies no size limit, because callers such as signed bundles
// legitimately take large inputs: bound what you read (io.LimitReader,
// http.MaxBytesReader) before you pass it in. Errors quote at most 64 bytes
// of a member name, so a hostile name cannot inflate them.
//
// # Conversion errors
//
// When a value cannot be converted, [Unmarshal], [UnmarshalOpen] and
// [UnmarshalExtra] return an [ErrType] error whose Error method omits the decoder's
// message, including numeric values and custom UnmarshalJSON or UnmarshalText
// messages. Ordinary error formatting with %s or %v therefore does not print
// those details. The original cause is retained: errors.Is can match custom
// sentinels and errors.As can recover an [encoding/json.UnmarshalTypeError]
// or a custom error. Inspecting or formatting that cause is an explicit opt-in to its
// original details, which may contain sensitive input values.
//
// # Raw helpers
//
// [Object], [Array], [String], [OptionalString], [Unknown] and [Base64] walk
// a checked document as [encoding/json.RawMessage] values for formats that
// are parsed by hand rather than into a struct.
//
// When encoding/json/v2 leaves its experiment, this package can become a thin
// wrapper over its RejectUnknownMembers and AllowDuplicateNames(false)
// options without changing callers.
//
// Stability: experimental
//
// It's lifted from the strictjson package of github.com/picatz/go-keyblade
// at commit f19051863d21, for [github.com/picatz/doh/internal/webauthn].
//
// [RFC 8259 §4]: https://www.rfc-editor.org/rfc/rfc8259.html#section-4
// [RFC 7493 §2.3]: https://www.rfc-editor.org/rfc/rfc7493.html#section-2.3
// [RFC 7515 §5.2]: https://www.rfc-editor.org/rfc/rfc7515.html#section-5.2
package strictjson
