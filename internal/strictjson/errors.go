package strictjson

import (
	"errors"
	"fmt"
)

// sentinel is an error category whose parent is the broader category it
// belongs to.
type sentinel struct {
	msg    string
	parent error
}

func (s *sentinel) Error() string { return s.msg }
func (s *sentinel) Unwrap() error { return s.parent }

// ErrInvalid is the category of every document this package refuses. Each
// more specific error below satisfies errors.Is(err, ErrInvalid). Errors
// name the offending member, never its value. Conversion errors retain the
// original cause for errors.Is and errors.As; inspecting or formatting that
// cause explicitly may reveal input values or custom decoder messages.
var ErrInvalid = errors.New("strictjson: invalid JSON")

var (
	// ErrSyntax reports input that is not one well-formed JSON value: empty
	// input, a syntax error, invalid UTF-8 or an unpaired surrogate escape.
	ErrSyntax error = &sentinel{"strictjson: syntax error", ErrInvalid}
	// ErrTrailingData reports data after the first JSON value.
	ErrTrailingData error = &sentinel{"strictjson: data after the JSON value", ErrInvalid}
	// ErrTooDeep reports nesting deeper than [MaxDepth].
	ErrTooDeep error = &sentinel{"strictjson: nested too deeply", ErrInvalid}
	// ErrDuplicateMember reports an object that repeats a member name.
	ErrDuplicateMember error = &sentinel{"strictjson: duplicate member", ErrInvalid}
	// ErrUnknownMember reports a member the target does not define, or one
	// that differs from a defined member only in case. An undefined
	// member's error lists the members the target does define.
	ErrUnknownMember error = &sentinel{"strictjson: unknown member", ErrInvalid}
	// ErrType reports a value that does not fit the target, such as a string
	// for a number or a null where an object is required. Errors from the
	// target's own UnmarshalJSON and UnmarshalText methods are wrapped
	// alongside it, without including their messages in the returned error.
	ErrType error = &sentinel{"strictjson: value does not fit the target", ErrInvalid}
)

// conversionError keeps the decoder's diagnostic available to callers that
// deliberately inspect the cause, without formatting arbitrary input values
// or calling a custom error's Error method in ordinary error messages.
type conversionError struct{ cause error }

func (e *conversionError) Error() string   { return ErrType.Error() }
func (e *conversionError) Unwrap() []error { return []error{ErrType, e.cause} }

func syntaxf(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrSyntax}, args...)...)
}
