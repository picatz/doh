package plist

import (
	"bytes"
	"encoding/xml"
	"strings"
	"testing"
	"unicode/utf8"
)

// FuzzMarshal encodes arbitrary keys and strings, as profile names and
// device names reach configuration profiles: the output must be
// well-formed XML, whatever they hold, so no value can break out of its
// element and add settings, and valid XML text must read back exactly.
func FuzzMarshal(f *testing.F) {
	f.Add("PayloadDisplayName", "Kids & <friends>", int64(1))
	f.Add("</key><key>x", "]]></string><true/><string>", int64(-1))
	f.Add("a\x00b", "\r\n\t", int64(0))
	f.Fuzz(func(t *testing.T, key, value string, n int64) {
		b := Marshal(Dict{
			{Key: key, Value: String(value)},
			{Key: "n", Value: Integer(n)},
			{Key: "list", Value: Array{String(value), Bool(true)}},
		})

		d := xml.NewDecoder(bytes.NewReader(b))
		d.Strict = true
		var texts []string
		var elements []string
		var text strings.Builder
		for {
			tok, err := d.Token()
			if err != nil {
				if err.Error() != "EOF" {
					t.Fatalf("not well-formed: %v\n%s", err, b)
				}
				break
			}
			switch tok := tok.(type) {
			case xml.StartElement:
				elements = append(elements, tok.Name.Local)
				text.Reset()
			case xml.CharData:
				text.Write(tok)
			case xml.EndElement:
				if tok.Name.Local == "key" || tok.Name.Local == "string" || tok.Name.Local == "integer" {
					texts = append(texts, text.String())
				}
			}
		}
		want := []string{"plist", "dict", "key", "string", "key", "integer", "key", "array", "string", "true"}
		if strings.Join(elements, " ") != strings.Join(want, " ") {
			t.Fatalf("elements %v, want %v", elements, want)
		}
		// XML can't hold every character: others are replaced, keeping
		// the output well-formed. The rest read back exactly, even line
		// breaks, which are escaped.
		if !xmlText(key) || !xmlText(value) {
			return
		}
		if texts[0] != key || texts[1] != value || texts[5] != value {
			t.Fatalf("read back %q, want key %q and value %q", texts, key, value)
		}
	})
}

// xmlText reports whether s holds only characters XML 1.0 allows.
func xmlText(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if !(r == 0x09 || r == 0x0A || r == 0x0D || r >= 0x20 && r <= 0xD7FF || r >= 0xE000 && r <= 0xFFFD || r >= 0x10000 && r <= 0x10FFFF) {
			return false
		}
	}
	return true
}
