package strictjson

import (
	"bytes"
	"fmt"
	"reflect"
	"unicode/utf8"
)

// MaxDepth is the deepest nesting of arrays and objects that [Check] and
// [Unmarshal] accept.
const MaxDepth = 64

// maxName is the longest member name, in bytes, that an error quotes.
const maxName = 64

// Check reports whether data is exactly one valid JSON value, in valid UTF-8,
// with no repeated member name in any object, at most [MaxDepth] levels of
// nesting, and no unpaired UTF-16 surrogate escape. It depends on no target
// type, so it also covers documents that are parsed by hand.
//
// A \uD800 to \uDBFF escape must be followed immediately by a \uDC00 to
// \uDFFF escape, and a low surrogate escape must not appear on its own.
// encoding/json decodes a lone surrogate to U+FFFD, so two different
// strings would otherwise read as one value, and other decoders reject or
// keep them; RFC 8259 §8.2 leaves the behavior unpredictable.
//
// Check makes one pass over data without building a tree: it holds only the
// member names of the objects that are open at that moment, so its memory is
// bounded by the widest single object, not by the input. It applies no size
// limit; callers that read untrusted input should bound the read first.
//
// The error satisfies errors.Is(err, [ErrInvalid]) and one of [ErrSyntax],
// [ErrTrailingData], [ErrTooDeep] or [ErrDuplicateMember].
func Check(data []byte) error {
	_, err := scan(data, nil, reflect.Value{}, true)
	return err
}

// quote returns name quoted for an error, cut to maxName bytes with an
// ellipsis so that a hostile member name cannot inflate the error.
func quote(name []byte) string {
	if len(name) <= maxName {
		return fmt.Sprintf("%q", name)
	}
	cut := maxName
	for cut > 0 && !utf8.RuneStart(name[cut]) {
		cut--
	}
	return fmt.Sprintf("%q", name[:cut]) + "..."
}

// scanner validates one JSON document in a single pass.
type scanner struct {
	data []byte
	pos  int
	open bool // members the target does not define are allowed
	// keys and sets hold, for each open object, the member names seen so
	// far: a short slice that aliases data, and a set once it grows.
	keys [MaxDepth][][]byte
	sets [MaxDepth]map[string]struct{}
	// decoded holds, for an open object that decodes into a map whose keys
	// are not strings, the keys its member names decode to.
	decoded [MaxDepth]map[any]struct{}
	// cycles holds the interfaces the input reaches that hold a pointer to
	// themselves, for unmarshal to clear before it decodes.
	cycles []reflect.Value
}

// smallObject is the member count above which an object's names move from a
// slice, compared linearly, to a set.
const smallObject = 16

// scan checks data against target, if target is non-nil, in one pass. open
// allows members that a struct target does not define. It returns the
// settable interfaces in rv that the input reaches and that hold a pointer
// to themselves.
func scan(data []byte, target reflect.Type, rv reflect.Value, open bool) ([]reflect.Value, error) {
	if !utf8.Valid(data) {
		return nil, syntaxf("invalid UTF-8")
	}
	s := &scanner{data: data, open: open}
	s.skip()
	if err := s.value(target, rv, 0); err != nil {
		return nil, err
	}
	s.skip()
	if s.pos != len(s.data) {
		return nil, ErrTrailingData
	}
	return s.cycles, nil
}

// follow is the package-level follow, recording a self-referencing
// interface it stops at.
func (s *scanner) follow(t reflect.Type, rv reflect.Value) (reflect.Type, reflect.Value) {
	t, rv, cycle := follow(t, rv)
	if cycle.IsValid() && cycle.CanSet() {
		s.cycles = append(s.cycles, cycle)
	}
	return t, rv
}

func (s *scanner) skip() {
	for s.pos < len(s.data) {
		switch s.data[s.pos] {
		case ' ', '\t', '\n', '\r':
			s.pos++
		default:
			return
		}
	}
}

func (s *scanner) value(t reflect.Type, rv reflect.Value, depth int) error {
	if s.pos >= len(s.data) {
		if depth == 0 {
			return syntaxf("empty input")
		}
		return syntaxf("unexpected end")
	}
	if c := s.data[s.pos]; rv.IsValid() && c != '{' && c != '[' {
		// A scalar replaces the interface it reaches, so a self-reference
		// on the way matters here too.
		s.follow(t, rv)
	}
	switch c := s.data[s.pos]; {
	case c == '{':
		return s.object(t, rv, depth)
	case c == '[':
		return s.array(t, rv, depth)
	case c == '"':
		_, _, err := s.str()
		return err
	case c == '-' || '0' <= c && c <= '9':
		return s.number()
	case c == 't':
		return s.literal("true")
	case c == 'f':
		return s.literal("false")
	case c == 'n':
		return s.literal("null")
	default:
		return syntaxf("invalid character %q", c)
	}
}

func (s *scanner) literal(word string) error {
	if !bytes.HasPrefix(s.data[s.pos:], []byte(word)) {
		return syntaxf("invalid literal")
	}
	s.pos += len(word)
	return nil
}

func (s *scanner) digits() bool {
	start := s.pos
	for s.pos < len(s.data) && '0' <= s.data[s.pos] && s.data[s.pos] <= '9' {
		s.pos++
	}
	return s.pos > start
}

func (s *scanner) number() error {
	if s.data[s.pos] == '-' {
		s.pos++
	}
	if s.pos >= len(s.data) {
		return syntaxf("unexpected end")
	}
	switch c := s.data[s.pos]; {
	case c == '0':
		s.pos++
	case '1' <= c && c <= '9':
		s.digits()
	default:
		return syntaxf("invalid number")
	}
	if s.pos < len(s.data) && s.data[s.pos] == '.' {
		s.pos++
		if !s.digits() {
			return syntaxf("invalid number")
		}
	}
	if s.pos < len(s.data) && (s.data[s.pos] == 'e' || s.data[s.pos] == 'E') {
		s.pos++
		if s.pos < len(s.data) && (s.data[s.pos] == '+' || s.data[s.pos] == '-') {
			s.pos++
		}
		if !s.digits() {
			return syntaxf("invalid number")
		}
	}
	return nil
}

// str scans the string at s.pos and returns the bytes between its quotes and
// whether they contain an escape. Surrogate escapes must pair.
func (s *scanner) str() (raw []byte, escaped bool, err error) {
	s.pos++ // opening quote
	start := s.pos
	for s.pos < len(s.data) {
		switch c := s.data[s.pos]; {
		case c == '"':
			raw = s.data[start:s.pos]
			s.pos++
			return raw, escaped, nil
		case c < 0x20:
			return nil, false, syntaxf("control character in string")
		case c == '\\':
			escaped = true
			s.pos++
			if s.pos >= len(s.data) {
				return nil, false, syntaxf("unexpected end")
			}
			switch s.data[s.pos] {
			case '"', '\\', '/', 'b', 'f', 'n', 'r', 't':
				s.pos++
			case 'u':
				r, ok := hex4(s.data, s.pos+1)
				if !ok {
					return nil, false, syntaxf("invalid \\u escape")
				}
				s.pos += 5
				switch {
				case 0xDC00 <= r && r <= 0xDFFF:
					return nil, false, syntaxf("unpaired low surrogate escape")
				case 0xD800 <= r && r <= 0xDBFF:
					low, ok := hex4(s.data, s.pos+2)
					if !ok || s.data[s.pos] != '\\' || s.data[s.pos+1] != 'u' || low < 0xDC00 || low > 0xDFFF {
						return nil, false, syntaxf("unpaired high surrogate escape")
					}
					s.pos += 6
				}
			default:
				return nil, false, syntaxf("invalid escape")
			}
		default:
			s.pos++
		}
	}
	return nil, false, syntaxf("unexpected end")
}

func (s *scanner) array(t reflect.Type, rv reflect.Value, depth int) error {
	if depth >= MaxDepth {
		return ErrTooDeep
	}
	t, rv = s.follow(t, rv)
	var elem reflect.Type
	tracked := false
	if tg := resolve(t); tg.kind == kindList {
		elem = tg.elem
		tracked = rv.IsValid() && mayHoldInterface(elem)
		if tracked && rv.Kind() == reflect.Slice {
			// encoding/json grows a slice into its spare capacity without
			// clearing it, so the elements up to Cap are decode destinations.
			rv = rv.Slice(0, rv.Cap())
		}
	}
	s.pos++
	s.skip()
	if s.pos < len(s.data) && s.data[s.pos] == ']' {
		s.pos++
		return nil
	}
	for i := 0; ; i++ {
		s.skip()
		var ev reflect.Value
		if tracked && i < rv.Len() {
			ev = rv.Index(i)
		}
		if err := s.value(elem, ev, depth+1); err != nil {
			return err
		}
		s.skip()
		if s.pos >= len(s.data) {
			return syntaxf("unexpected end")
		}
		switch s.data[s.pos] {
		case ',':
			s.pos++
		case ']':
			s.pos++
			return nil
		default:
			return syntaxf("invalid character in array")
		}
	}
}

func (s *scanner) object(t reflect.Type, rv reflect.Value, depth int) error {
	if depth >= MaxDepth {
		return ErrTooDeep
	}
	t, rv = s.follow(t, rv)
	tg := resolve(t)
	s.keys[depth] = s.keys[depth][:0]
	s.sets[depth] = nil
	s.decoded[depth] = nil
	s.pos++
	s.skip()
	if s.pos < len(s.data) && s.data[s.pos] == '}' {
		s.pos++
		return nil
	}
	for {
		s.skip()
		if s.pos >= len(s.data) || s.data[s.pos] != '"' {
			return syntaxf("object member name expected")
		}
		raw, escaped, err := s.str()
		if err != nil {
			return err
		}
		name := raw
		if escaped {
			name = unescape(raw)
		}
		if s.repeated(depth, name) {
			return fmt.Errorf("%w: %s", ErrDuplicateMember, quote(name))
		}
		var child reflect.Type
		var cv reflect.Value
		quoted := false
		switch tg.kind {
		case kindStruct:
			f, ok := tg.fields.byName[string(name)]
			switch {
			case ok:
				child = f.typ
				quoted = f.quoted
				if rv.IsValid() && mayHoldInterface(child) {
					cv = fieldValue(rv, f.index)
				}
			case hasFolded(tg.fields, name):
				return fmt.Errorf("%w: %s differs from a defined member only in case", ErrUnknownMember, quote(name))
			case !s.open:
				return fmt.Errorf("%w: %s; %s", ErrUnknownMember, quote(name), tg.fields.known)
			}
		case kindMap:
			child = tg.elem
			if tg.keyOf != nil {
				// encoding/json decodes the name to a key, and a later name
				// that decodes to the same key replaces the earlier value.
				if key, ok := tg.keyOf(name); ok {
					if s.decoded[depth] == nil {
						s.decoded[depth] = map[any]struct{}{}
					}
					if _, dup := s.decoded[depth][key]; dup {
						return fmt.Errorf("%w: %s decodes to a map key already present", ErrDuplicateMember, quote(name))
					}
					s.decoded[depth][key] = struct{}{}
				}
			}
		}
		s.skip()
		if s.pos >= len(s.data) || s.data[s.pos] != ':' {
			return syntaxf("colon expected after member name")
		}
		s.pos++
		s.skip()
		if quoted && s.pos < len(s.data) && s.data[s.pos] == '"' {
			if err := s.quotedValue(name); err != nil {
				return err
			}
		} else if err := s.value(child, cv, depth+1); err != nil {
			return err
		}
		s.skip()
		if s.pos >= len(s.data) {
			return syntaxf("unexpected end")
		}
		switch s.data[s.pos] {
		case ',':
			s.pos++
		case '}':
			s.pos++
			s.keys[depth] = s.keys[depth][:0]
			s.sets[depth] = nil
			s.decoded[depth] = nil
			return nil
		default:
			return syntaxf("invalid character in object")
		}
	}
}

// quotedValue checks the value of a member with the ,string option, which
// encoding/json reads as JSON text inside a JSON string. The text is held to
// the same rules as a document: a lone surrogate escape, invalid UTF-8 and
// syntax errors are refused, so a quoted string cannot differ from a plain one.
func (s *scanner) quotedValue(name []byte) error {
	raw, escaped, err := s.str()
	if err != nil {
		return err
	}
	inner := raw
	if escaped {
		inner = unescape(raw)
	}
	if err := Check(inner); err != nil {
		return fmt.Errorf("%w: quoted value of %s: %w", ErrSyntax, quote(name), err)
	}
	return nil
}

// repeated records name as a member of the object open at depth and reports
// whether it was already there.
func (s *scanner) repeated(depth int, name []byte) bool {
	if set := s.sets[depth]; set != nil {
		if _, ok := set[string(name)]; ok {
			return true
		}
		set[string(name)] = struct{}{}
		return false
	}
	for _, k := range s.keys[depth] {
		if bytes.Equal(k, name) {
			return true
		}
	}
	s.keys[depth] = append(s.keys[depth], name)
	if len(s.keys[depth]) > smallObject {
		set := make(map[string]struct{}, 2*smallObject)
		for _, k := range s.keys[depth] {
			set[string(k)] = struct{}{}
		}
		s.sets[depth] = set
		s.keys[depth] = s.keys[depth][:0]
	}
	return false
}

// hex4 decodes the four hex digits at data[i:i+4].
func hex4(data []byte, i int) (rune, bool) {
	if i < 0 || i+4 > len(data) {
		return 0, false
	}
	var r rune
	for _, c := range data[i : i+4] {
		switch {
		case '0' <= c && c <= '9':
			r = r<<4 | rune(c-'0')
		case 'a' <= c && c <= 'f':
			r = r<<4 | rune(c-'a'+10)
		case 'A' <= c && c <= 'F':
			r = r<<4 | rune(c-'A'+10)
		default:
			return 0, false
		}
	}
	return r, true
}

// unescape decodes the escapes of a string body that str has validated.
func unescape(raw []byte) []byte {
	out := make([]byte, 0, len(raw))
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if c != '\\' {
			out = append(out, c)
			continue
		}
		i++
		switch raw[i] {
		case 'b':
			out = append(out, '\b')
		case 'f':
			out = append(out, '\f')
		case 'n':
			out = append(out, '\n')
		case 'r':
			out = append(out, '\r')
		case 't':
			out = append(out, '\t')
		case 'u':
			r, _ := hex4(raw, i+1)
			i += 4
			if 0xD800 <= r && r <= 0xDBFF {
				low, _ := hex4(raw, i+3)
				r = (r-0xD800)<<10 | (low - 0xDC00) + 0x10000
				i += 6
			}
			out = utf8.AppendRune(out, r)
		default: // " \ /
			out = append(out, raw[i])
		}
	}
	return out
}
