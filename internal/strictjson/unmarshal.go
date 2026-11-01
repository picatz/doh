package strictjson

import (
	"bytes"
	"encoding/json"
	"fmt"
	"maps"
	"reflect"
	"strings"
	"unicode"
)

// Unmarshal decodes data, exactly one JSON value, into the value v points
// to, as [encoding/json.Unmarshal] does, but strictly. After the conditions
// [Check] reports, it fails with [ErrUnknownMember] when an object has a
// member that the struct it decodes into does not define, or that differs
// from a defined member only in case, at any depth, and with [ErrType] when
// data is null where v is a struct or map, or a value does not fit v.
//
// Struct members are named by their json tags, including those of embedded
// structs. Values whose type implements [encoding/json.Unmarshaler] or
// [encoding.TextUnmarshaler], and values held in interfaces, are decoded by
// those methods without further inspection.
//
// Errors satisfy errors.Is(err, [ErrInvalid]); an error returned by a
// target's own UnmarshalJSON or UnmarshalText is wrapped alongside [ErrType].
// Conversion errors omit the decoder's message. The original cause remains
// available through errors.Is and errors.As, and may contain input values.
func Unmarshal(data []byte, v any) error {
	_, err := unmarshal(data, v, false, false)
	return err
}

// UnmarshalOpen is like [Unmarshal] but ignores members the target struct
// does not define, as formats with extension members require, such as JWT
// claims and WebAuthn responses. It still refuses repeated names and names
// that differ from a defined member only in case.
func UnmarshalOpen(data []byte, v any) error {
	_, err := unmarshal(data, v, true, false)
	return err
}

// UnmarshalExtra is like [UnmarshalOpen] and also returns the members of the
// top-level object that the struct v points to does not define, by exact
// name, or nil if there are none. v must point to a struct. Pair it with
// [MarshalExtra] to preserve extension members.
func UnmarshalExtra(data []byte, v any) (map[string]json.RawMessage, error) {
	return unmarshal(data, v, true, true)
}

func unmarshal(data []byte, v any, open, wantExtra bool) (map[string]json.RawMessage, error) {
	rv := reflect.ValueOf(v)
	if rv.Kind() != reflect.Pointer || rv.IsNil() {
		return nil, &json.InvalidUnmarshalError{Type: reflect.TypeOf(v)}
	}
	target := rv.Type().Elem()
	if wantExtra && indirect(target).Kind() != reflect.Struct {
		return nil, fmt.Errorf("%w: members can be returned only for a struct", ErrType)
	}
	cycles, err := scan(data, target, rv.Elem(), open)
	if err != nil {
		return nil, err
	}
	if t := bytes.TrimLeft(data, " \t\r\n"); len(t) > 0 && t[0] == 'n' {
		switch indirect(target).Kind() {
		case reflect.Struct, reflect.Map:
			return nil, fmt.Errorf("%w: null where an object is required", ErrType)
		}
	}
	var extra map[string]json.RawMessage
	if wantExtra {
		if t := bytes.TrimLeft(data, " \t\r\n"); len(t) > 0 && t[0] == '{' {
			if err := json.Unmarshal(data, &extra); err != nil {
				return nil, syntaxf("%v", err)
			}
			known := Members(indirect(target))
			maps.DeleteFunc(extra, func(name string, _ json.RawMessage) bool { return known[name] })
		}
		if len(extra) == 0 {
			extra = nil
		}
	}
	// encoding/json before Go 1.27 replaces an interface that holds a
	// pointer to itself with a fresh value; from Go 1.27 it follows the
	// cycle until the stack overflows. Clearing the interfaces the input
	// reaches gives the earlier result on every release. The cycles come from
	// the caller's value, never from input.
	for _, c := range cycles {
		c.SetZero()
	}
	if err := json.Unmarshal(data, v); err != nil {
		return nil, &conversionError{cause: err}
	}
	return extra, nil
}

// foldName returns a key under which two names collide exactly when
// encoding/json would match them to the same field: each rune becomes the
// smallest rune of its Unicode simple case-folding orbit, so "ſub" (with
// U+017F) and "SUB" both collide with "sub".
func foldName(name string) string {
	var b strings.Builder
	b.Grow(len(name))
	for _, r := range name {
		least := r
		for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
			least = min(least, f)
		}
		b.WriteRune(least)
	}
	return b.String()
}

// MarshalExtra encodes v, a struct or a pointer to one, with encoding/json
// and then adds each member of extra that v does not define, the members
// [UnmarshalExtra] returned. A member of extra never replaces a defined
// member, even one omitted as empty. Members are written in sorted order
// when extra is not empty. With no extra members, MarshalExtra is equivalent
// to [encoding/json.Marshal], including encoding a nil pointer as null.
// Otherwise, v must be a struct or a pointer to one that encodes as an
// object; a nil pointer or any non-object encoding fails with [ErrType].
func MarshalExtra(v any, extra map[string]json.RawMessage) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil || len(extra) == 0 {
		return b, err
	}
	t := reflect.TypeOf(v)
	if t == nil || indirect(t).Kind() != reflect.Struct {
		return nil, fmt.Errorf("%w: members can be added only to a struct", ErrType)
	}
	obj, err := Object(b)
	if err != nil {
		return nil, err
	}
	known := Members(t)
	for k, raw := range extra {
		if !known[k] {
			obj[k] = raw
		}
	}
	return json.Marshal(obj)
}
