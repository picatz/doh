package webauthn

import (
	"errors"
	"strconv"
	"strings"
	"testing"
)

func TestParseClientDataStrict(t *testing.T) {
	const base = `"type":"webauthn.get","challenge":"abc","origin":"https://example.com"`
	nest := func(depth int) string {
		return strings.Repeat(`{"a":`, depth) + `1` + strings.Repeat(`}`, depth)
	}
	var members strings.Builder
	for i := range 61 {
		members.WriteString(`,"m` + strconv.Itoa(i) + `":1`)
	}
	for name, test := range map[string]struct {
		json string
		ok   bool
	}{
		"valid":                        {`{` + base + `}`, true},
		"valid full":                   {`{` + base + `,"crossOrigin":true,"topOrigin":"https://top.example"}`, true},
		"unknown nested allowed":       {`{` + base + `,"x":{"a":[{"b":1},{"b":2}],"c":{"b":3}}}`, true},
		"escaped pair allowed":         {`{` + base + `,"x":"😀"}`, true},
		"depth at bound":               {`{` + base + `,"x":` + nest(62) + `}`, true},
		"depth over bound":             {`{` + base + `,"x":` + nest(64) + `}`, false},
		"duplicate type":               {`{"type":"a","type":"webauthn.get","challenge":"abc","origin":"o"}`, false},
		"duplicate nested":             {`{` + base + `,"x":{"a":1,"a":2}}`, false},
		"duplicate in array object":    {`{` + base + `,"x":[{"a":1,"a":2}]}`, false},
		"same name in sibling objects": {`{` + base + `,"x":{"a":1},"y":{"a":2}}`, true},
		"case Type":                    {`{"Type":"webauthn.create","type":"webauthn.get","challenge":"abc","origin":"o"}`, false},
		"case only Type":               {`{"Type":"webauthn.get","challenge":"abc","origin":"o"}`, false},
		"case ORIGIN":                  {`{` + base + `,"ORIGIN":"https://evil.example"}`, false},
		"case Challenge":               {`{` + base + `,"Challenge":"x"}`, false},
		"case TOPORIGIN":               {`{` + base + `,"TOPORIGIN":"x"}`, false},
		"case CrossOrigin":             {`{` + base + `,"crossorigin":true}`, false},
		"case variant nested ok":       {`{` + base + `,"x":{"Type":"a"}}`, true},
		"lone high surrogate":          {`{"type":"webauthn.get","challenge":"abc","origin":"https://a\ud800.example"}`, false},
		"lone low surrogate":           {`{"type":"webauthn.get","challenge":"abc","origin":"\udc00"}`, false},
		"high then non-low":            {`{"type":"webauthn.get","challenge":"abc","origin":"\ud800A"}`, false},
		"escaped backslash then u":     {`{` + base + `,"x":"\\ud800"}`, true},
		"members at bound":             {`{` + base + members.String() + `}`, true},
		"too many members":             {`{` + base + members.String() + `,"z1":1}`, false},
	} {
		_, err := ParseClientData([]byte(test.json))
		if test.ok && err != nil {
			t.Errorf("%s: ParseClientData = %v, want success", name, err)
		}
		if !test.ok && !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: ParseClientData = %v, want ErrMalformed", name, err)
		}
	}
}
