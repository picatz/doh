package strictjson_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"unicode/utf8"

	"github.com/picatz/doh/internal/strictjson"
)

// oracleCheck is the first, token-based definition of Check, kept as an
// independent implementation for the fuzz tests to compare the scanner with.
func oracleCheck(data []byte) error {
	if !utf8.Valid(data) {
		return oracleSyntax("invalid UTF-8")
	}
	if err := oracleTokens(data); err != nil {
		return err
	}
	return oracleSurrogates(data)
}

func oracleSyntax(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{strictjson.ErrSyntax}, args...)...)
}

// oracleTokens is the structural half of Check.
func oracleTokens(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	// Each frame is the set of member names seen in one open object, or nil
	// for an open array.
	var stack []map[string]bool
	expectKey := false
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			if len(stack) != 0 {
				return oracleSyntax("unexpected end")
			}
			return oracleSyntax("empty input")
		}
		if err != nil {
			return oracleSyntax("%v", err)
		}
		if expectKey {
			// Inside an object, the decoder yields either a member name or
			// the closing delimiter.
			if key, ok := tok.(string); ok {
				frame := stack[len(stack)-1]
				if frame[key] {
					return fmt.Errorf("%w: %q", strictjson.ErrDuplicateMember, key)
				}
				frame[key] = true
				expectKey = false
				continue
			}
		}
		switch tok {
		case json.Delim('{'), json.Delim('['):
			if len(stack) >= strictjson.MaxDepth {
				return strictjson.ErrTooDeep
			}
			if tok == json.Delim('{') {
				stack = append(stack, map[string]bool{})
			} else {
				stack = append(stack, nil)
			}
		case json.Delim('}'), json.Delim(']'):
			stack = stack[:len(stack)-1]
		}
		if len(stack) == 0 {
			// A complete top-level value: anything after it is an error.
			if _, err := dec.Token(); err != io.EOF {
				return strictjson.ErrTrailingData
			}
			return nil
		}
		// After a value inside an object the next token is a member name;
		// inside an array it is another value.
		expectKey = stack[len(stack)-1] != nil
	}
}

// oracleSurrogates rejects an unpaired UTF-16 surrogate escape in any string
// of data, which oracleTokens has already accepted as valid JSON. Outside
// strings JSON has no backslashes, so a scan of quotes and escapes suffices.
func oracleSurrogates(data []byte) error {
	inString := false
	for i := 0; i < len(data); i++ {
		switch c := data[i]; {
		case c == '"':
			inString = !inString
		case c == '\\' && inString:
			if i+1 < len(data) && data[i+1] == 'u' {
				r, ok := oracleHex4(data, i+2)
				if !ok {
					return oracleSyntax("invalid \\u escape")
				}
				switch {
				case 0xDC00 <= r && r <= 0xDFFF:
					return oracleSyntax("unpaired low surrogate escape")
				case 0xD800 <= r && r <= 0xDBFF:
					low, ok := oracleHex4(data, i+8)
					if !ok || data[i+6] != '\\' || data[i+7] != 'u' || low < 0xDC00 || low > 0xDFFF {
						return oracleSyntax("unpaired high surrogate escape")
					}
					i += 6 // skip the high escape; the loop skips past the low one
				}
				i += 5
			} else {
				i++ // skip the escaped character, which may be a quote
			}
		}
	}
	return nil
}

// oracleHex4 decodes the four hex digits at data[i:i+4].
func oracleHex4(data []byte, i int) (rune, bool) {
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
