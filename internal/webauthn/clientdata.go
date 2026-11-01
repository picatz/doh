package webauthn

import (
	"bytes"
	"encoding/json"
	"fmt"
	"unicode/utf8"

	"github.com/picatz/doh/internal/strictjson"
)

// maxClientData bounds clientDataJSON. Browsers produce a few hundred bytes.
const maxClientData = 16 << 10

// maxClientDataMembers bounds the top-level members of clientDataJSON,
// including unknown ones.
const maxClientDataMembers = 64

// CollectedClientData is the client data a browser signs over, as hashed
// into every attestation and assertion.
// https://www.w3.org/TR/webauthn-3/#dictionary-client-data
type CollectedClientData struct {
	Type        string `json:"type"`
	Challenge   string `json:"challenge"`
	Origin      string `json:"origin"`
	TopOrigin   string `json:"topOrigin,omitempty"`
	CrossOrigin bool   `json:"crossOrigin,omitempty"`
}

// ParseClientData parses clientDataJSON. It strips a leading UTF-8 byte
// order mark, as the specification's UTF-8 decode step requires, and rejects
// invalid UTF-8, a value that is not one JSON object, duplicate member names
// at any depth (which different JSON parsers resolve differently), nesting
// deeper than 64 levels, more than 64 top-level members, unpaired UTF-16
// surrogate escapes, a non-string type, challenge, origin or topOrigin, and
// a non-boolean crossOrigin. Members are matched by exact name: a member
// whose name differs from type, challenge, origin, topOrigin or crossOrigin
// only in case is rejected, because parsers that match names
// case-insensitively would read a different value. Other unknown members
// are allowed: clients may extend client data. Failures wrap [ErrMalformed].
//
// https://www.w3.org/TR/webauthn-3/#clientdatajson-serialization
func ParseClientData(data []byte) (*CollectedClientData, error) {
	if len(data) > maxClientData {
		return nil, fmt.Errorf("%w: clientDataJSON over %d bytes", ErrMalformed, maxClientData)
	}
	data = bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))
	if !utf8.Valid(data) {
		return nil, fmt.Errorf("%w: clientDataJSON is not UTF-8", ErrMalformed)
	}
	members, err := decodeMembers(data)
	if err != nil {
		return nil, err
	}
	out := &CollectedClientData{}
	for name, target := range map[string]*string{"type": &out.Type, "challenge": &out.Challenge, "origin": &out.Origin, "topOrigin": &out.TopOrigin} {
		raw, ok := members[name]
		if !ok {
			if name == "topOrigin" {
				continue
			}
			return nil, fmt.Errorf("%w: clientDataJSON lacks %q (%s)", ErrMalformed, name, specClientData)
		}
		if json.Unmarshal(raw, target) != nil || raw[0] != '"' {
			return nil, fmt.Errorf("%w: clientDataJSON %q is not a string", ErrMalformed, name)
		}
	}
	if raw, ok := members["crossOrigin"]; ok {
		if json.Unmarshal(raw, &out.CrossOrigin) != nil || (raw[0] != 't' && raw[0] != 'f') {
			return nil, fmt.Errorf("%w: clientDataJSON crossOrigin is not a boolean", ErrMalformed)
		}
	}
	if _, present := members["topOrigin"]; present && out.TopOrigin == "" {
		return nil, fmt.Errorf("%w: clientDataJSON topOrigin is empty", ErrMalformed)
	}
	return out, nil
}

// decodeMembers decodes one JSON object strictly, with strictjson, and
// returns the raw members this package reads, keyed by exact name. It
// rejects duplicate names at any depth, nesting over strictjson.MaxDepth,
// unpaired surrogate escapes, trailing data, and a member whose name
// differs from one we read only in case. Other unknown members are ignored.
func decodeMembers(data []byte) (map[string]json.RawMessage, error) {
	var wire struct {
		Type        json.RawMessage `json:"type"`
		Challenge   json.RawMessage `json:"challenge"`
		Origin      json.RawMessage `json:"origin"`
		TopOrigin   json.RawMessage `json:"topOrigin"`
		CrossOrigin json.RawMessage `json:"crossOrigin"`
	}
	if err := strictjson.UnmarshalOpen(data, &wire); err != nil {
		return nil, fmt.Errorf("%w: clientDataJSON is not a strict JSON object: %w", ErrMalformed, err)
	}
	var all map[string]json.RawMessage
	if err := json.Unmarshal(data, &all); err != nil {
		return nil, fmt.Errorf("%w: clientDataJSON is not a JSON object", ErrMalformed)
	}
	if len(all) > maxClientDataMembers {
		return nil, fmt.Errorf("%w: clientDataJSON has too many members", ErrMalformed)
	}
	members := map[string]json.RawMessage{}
	for name, raw := range map[string]json.RawMessage{"type": wire.Type, "challenge": wire.Challenge, "origin": wire.Origin, "topOrigin": wire.TopOrigin, "crossOrigin": wire.CrossOrigin} {
		if raw != nil {
			members[name] = raw
		}
	}
	return members, nil
}
