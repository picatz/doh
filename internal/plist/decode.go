package plist

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// MaxSize and MaxDepth bound what [Unmarshal] reads: property lists bigger
// than MaxSize bytes, or nested deeper than MaxDepth, are refused.
const (
	MaxSize  = 1 << 20
	MaxDepth = 32
)

// Unmarshal parses an XML property list of the values this package
// encodes: dictionaries, arrays, strings, integers, and booleans. Others,
// such as data and dates, are refused, as are lists over MaxSize bytes or
// MaxDepth deep, so it can check what [Encode] writes, and read small,
// trusted lists.
func Unmarshal(b []byte) (Value, error) {
	if len(b) > MaxSize {
		return nil, fmt.Errorf("plist: %d bytes, more than %d", len(b), MaxSize)
	}
	d := xml.NewDecoder(bytes.NewReader(b))
	d.Strict = true

	// Find <plist>, skipping the declaration, doctype, and white space.
	for {
		tok, err := d.Token()
		if err != nil {
			return nil, fmt.Errorf("plist: no <plist> element: %w", err)
		}
		if start, ok := tok.(xml.StartElement); ok {
			if start.Name.Local != "plist" {
				return nil, fmt.Errorf("plist: root element is <%s>, not <plist>", start.Name.Local)
			}
			break
		}
	}

	start, err := nextElement(d)
	if err != nil {
		return nil, err
	}
	if start == nil {
		return nil, errors.New("plist: empty <plist>")
	}
	v, err := decodeValue(d, *start, 1)
	if err != nil {
		return nil, err
	}
	if extra, err := nextElement(d); err != nil || extra != nil {
		return nil, errors.New("plist: <plist> holds more than one value")
	}
	return v, nil
}

// nextElement returns the next start element, or nil at an end element,
// skipping white space and comments.
func nextElement(d *xml.Decoder) (*xml.StartElement, error) {
	for {
		tok, err := d.Token()
		if err != nil {
			return nil, fmt.Errorf("plist: %w", err)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			return &t, nil
		case xml.EndElement:
			return nil, nil
		case xml.CharData:
			if len(bytes.TrimSpace(t)) > 0 {
				return nil, fmt.Errorf("plist: unexpected text %q", t)
			}
		case xml.Comment:
		default:
			return nil, fmt.Errorf("plist: unexpected %T", tok)
		}
	}
}

// decodeValue decodes the value start begins.
func decodeValue(d *xml.Decoder, start xml.StartElement, depth int) (Value, error) {
	if depth > MaxDepth {
		return nil, fmt.Errorf("plist: nested more than %d deep", MaxDepth)
	}
	switch start.Name.Local {
	case "string":
		s, err := text(d)
		return String(s), err
	case "integer":
		s, err := text(d)
		if err != nil {
			return nil, err
		}
		i, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
		if err != nil {
			return nil, fmt.Errorf("plist: integer: %w", err)
		}
		return Integer(i), nil
	case "true", "false":
		if end, err := nextElement(d); err != nil || end != nil {
			return nil, fmt.Errorf("plist: <%s/> isn't empty", start.Name.Local)
		}
		return Bool(start.Name.Local == "true"), nil
	case "array":
		a := Array{}
		for {
			el, err := nextElement(d)
			if err != nil {
				return nil, err
			}
			if el == nil {
				return a, nil
			}
			v, err := decodeValue(d, *el, depth+1)
			if err != nil {
				return nil, err
			}
			a = append(a, v)
		}
	case "dict":
		dict := Dict{}
		for {
			el, err := nextElement(d)
			if err != nil {
				return nil, err
			}
			if el == nil {
				return dict, nil
			}
			if el.Name.Local != "key" {
				return nil, fmt.Errorf("plist: <%s> where a <key> belongs", el.Name.Local)
			}
			key, err := text(d)
			if err != nil {
				return nil, err
			}
			if _, dup := dict.Lookup(key); dup {
				return nil, fmt.Errorf("plist: key %q repeated", key)
			}
			el, err = nextElement(d)
			if err != nil {
				return nil, err
			}
			if el == nil {
				return nil, fmt.Errorf("plist: key %q has no value", key)
			}
			v, err := decodeValue(d, *el, depth+1)
			if err != nil {
				return nil, err
			}
			dict = append(dict, Entry{Key: key, Value: v})
		}
	default:
		return nil, fmt.Errorf("plist: <%s> isn't supported", start.Name.Local)
	}
}

// text returns the text of the element just started, up to its end.
func text(d *xml.Decoder) (string, error) {
	var b strings.Builder
	for {
		tok, err := d.Token()
		if err == io.EOF {
			return "", errors.New("plist: unexpected end")
		}
		if err != nil {
			return "", fmt.Errorf("plist: %w", err)
		}
		switch t := tok.(type) {
		case xml.CharData:
			b.Write(t)
		case xml.EndElement:
			return b.String(), nil
		case xml.Comment:
		default:
			return "", fmt.Errorf("plist: unexpected %T in text", tok)
		}
	}
}

// Lookup returns the value of key in d, if it's there.
func (d Dict) Lookup(key string) (Value, bool) {
	for _, e := range d {
		if e.Key == key {
			return e.Value, true
		}
	}
	return nil, false
}
