package strictjson

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
)

// IsNull reports whether raw is the JSON literal null.
func IsNull(raw json.RawMessage) bool {
	return string(bytes.TrimSpace(raw)) == "null"
}

// Object decodes raw, which must be a JSON object (not null), into its
// members by exact name. Run Check on the enclosing document first.
func Object(raw json.RawMessage) (map[string]json.RawMessage, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return nil, fmt.Errorf("%w: want an object", ErrType)
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &members); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSyntax, err)
	}
	return members, nil
}

// Array decodes raw, which must be a JSON array (not null), into its
// elements.
func Array(raw json.RawMessage) ([]json.RawMessage, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '[' {
		return nil, fmt.Errorf("%w: want an array", ErrType)
	}
	var elems []json.RawMessage
	if err := json.Unmarshal(trimmed, &elems); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSyntax, err)
	}
	return elems, nil
}

// String decodes raw, which must be a JSON string (not null).
func String(raw json.RawMessage) (string, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '"' {
		return "", fmt.Errorf("%w: want a string", ErrType)
	}
	var s string
	if err := json.Unmarshal(trimmed, &s); err != nil {
		return "", fmt.Errorf("%w: %v", ErrSyntax, err)
	}
	return s, nil
}

// OptionalString decodes an optional string member: absent and null both
// read as "".
func OptionalString(members map[string]json.RawMessage, name string) (string, error) {
	raw, ok := members[name]
	if !ok || IsNull(raw) {
		return "", nil
	}
	s, err := String(raw)
	if err != nil {
		return "", fmt.Errorf("%w: member %s", err, quote([]byte(name)))
	}
	return s, nil
}

// Unknown returns the smallest member name of members that is not in known.
// The boolean reports whether such a member exists: an empty name is valid,
// so ("", true) reports an unknown empty name and ("", false) means every
// name is known.
func Unknown(members map[string]json.RawMessage, known ...string) (name string, found bool) {
	for member := range members {
		isKnown := slices.Contains(known, member)
		if !isKnown && (!found || member < name) {
			name, found = member, true
		}
	}
	return name, found
}

// Base64 decodes s as RFC 4648 base64 in either the standard or the URL-safe
// alphabet (sections 4 and 5), padded or unpadded. It rejects whitespace,
// mixed alphabets and nonzero trailing bits, so each byte string has exactly
// one accepted encoding per alphabet and padding choice.
func Base64(s string) ([]byte, error) {
	urlSafe := strings.ContainsAny(s, "-_")
	if urlSafe && strings.ContainsAny(s, "+/") {
		return nil, fmt.Errorf("%w: mixed base64 alphabets", ErrSyntax)
	}
	if strings.ContainsAny(s, "\r\n\t ") {
		return nil, fmt.Errorf("%w: whitespace in base64", ErrSyntax)
	}
	var enc *base64.Encoding
	switch {
	case urlSafe && strings.HasSuffix(s, "="):
		enc = base64.URLEncoding
	case urlSafe:
		enc = base64.RawURLEncoding
	case strings.HasSuffix(s, "="):
		enc = base64.StdEncoding
	default:
		enc = base64.RawStdEncoding
	}
	out, err := enc.Strict().DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid base64", ErrSyntax)
	}
	return out, nil
}

// MaxDecodedSize returns the number of bytes a base64 string with n
// characters, not counting trailing '=' padding, decodes to, so callers can
// bound a field before decoding it. For any string [Base64] accepts, it is
// exactly the decoded length; for other strings it is an upper bound.
func MaxDecodedSize(n int) int { return n/4*3 + n%4*3/4 }
