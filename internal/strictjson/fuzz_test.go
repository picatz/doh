package strictjson_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"unicode/utf8"

	"github.com/picatz/doh/internal/strictjson"
)

var seeds = []string{
	`{}`, `[]`, `null`, `0`, `"x"`, ``, `{"a":1,"a":2}`, `{"a":1,"A":2}`,
	`{"name":"n","inner":{"n":1},"items":[{"n":2}]}`, `{"Name":"n"}`,
	`"\ud800"`, `"😀"`, "\"\xff\"", `{} {}`, `[[[[[]]]]]`,
	`{"a":"a","a":1}`, `{"inner":{"N":1}}`, `{"nope":1}`,
}

// FuzzCheck checks that Check accepts only documents encoding/json also
// accepts, with no repeated member, and that every refusal is categorized.
func FuzzCheck(f *testing.F) {
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		err := strictjson.Check(data)
		if (err == nil) != (oracleCheck(data) == nil) {
			t.Fatalf("Check = %v but the reference checker says %v for %q", err, oracleCheck(data), data)
		}
		if err != nil {
			if !errors.Is(err, strictjson.ErrInvalid) {
				t.Fatalf("uncategorized error: %v", err)
			}
			return
		}
		if oracleCheck(data) != nil {
			t.Fatalf("Check accepted what the reference checker refuses: %q", data)
		}
		if !json.Valid(data) || !utf8.Valid(data) {
			t.Fatalf("Check accepted what encoding/json or UTF-8 refuses: %q", data)
		}
		// A document Check accepts has no repeated names, so decoding it into
		// a map and encoding it back must keep every member.
		var tree any
		dec := json.NewDecoder(bytesReader(data))
		dec.UseNumber()
		if err := dec.Decode(&tree); err != nil {
			t.Fatal(err)
		}
		if countMembers(tree) != countNames(t, data) {
			t.Fatalf("member count differs after decoding: %q", data)
		}
	})
}

// FuzzUnmarshal checks that Unmarshal agrees with encoding/json on every
// document it accepts, and that the open variant accepts whatever the strict
// one does.
func FuzzUnmarshal(f *testing.F) {
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		var strict, open, plain doc
		err := strictjson.Unmarshal(data, &strict)
		openErr := strictjson.UnmarshalOpen(data, &open)
		if err != nil {
			if !errors.Is(err, strictjson.ErrInvalid) {
				t.Fatalf("uncategorized error: %v", err)
			}
			return
		}
		if openErr != nil {
			t.Fatalf("UnmarshalOpen refused what Unmarshal accepts: %v", openErr)
		}
		if err := strictjson.Check(data); err != nil {
			t.Fatalf("Unmarshal accepted what Check refuses: %v", err)
		}
		if err := json.Unmarshal(data, &plain); err != nil {
			t.Fatalf("encoding/json refuses what Unmarshal accepts: %v", err)
		}
		if !reflect.DeepEqual(strict, plain) || !reflect.DeepEqual(open, plain) {
			t.Fatalf("results differ for %q", data)
		}
	})
}

func countMembers(v any) int {
	n := 0
	switch v := v.(type) {
	case map[string]any:
		n += len(v)
		for _, e := range v {
			n += countMembers(e)
		}
	case []any:
		for _, e := range v {
			n += countMembers(e)
		}
	}
	return n
}

// countNames counts member names with the token stream, which reports each
// repeated name that a decoded map would merge.
func countNames(t *testing.T, data []byte) int {
	t.Helper()
	dec := json.NewDecoder(bytesReader(data))
	var stack []bool // true: an object
	expectKey := false
	n := 0
	for {
		tok, err := dec.Token()
		if err != nil {
			return n
		}
		if expectKey {
			if _, ok := tok.(string); ok {
				n++
				expectKey = false
				continue
			}
		}
		switch tok {
		case json.Delim('{'):
			stack = append(stack, true)
		case json.Delim('['):
			stack = append(stack, false)
		case json.Delim('}'), json.Delim(']'):
			stack = stack[:len(stack)-1]
		}
		expectKey = len(stack) > 0 && stack[len(stack)-1]
	}
}

func bytesReader(b []byte) *bytes.Reader { return bytes.NewReader(b) }

// fuzzExtraDoc has defined members of several shapes, so UnmarshalExtra fuzzing
// reaches strings, slices and interfaces.
type fuzzExtraDoc struct {
	Iss string   `json:"iss"`
	Sub string   `json:"sub,omitempty"`
	Aud []string `json:"aud,omitempty"`
	Any any      `json:"any,omitempty"`
}

// sameJSON reports whether a and b encode the same JSON value.
func sameJSON(a, b json.RawMessage) bool {
	var x, y any
	dx, dy := json.NewDecoder(bytes.NewReader(a)), json.NewDecoder(bytes.NewReader(b))
	dx.UseNumber()
	dy.UseNumber()
	return dx.Decode(&x) == nil && dy.Decode(&y) == nil && reflect.DeepEqual(x, y)
}

// FuzzUnmarshalExtra checks that UnmarshalExtra agrees with UnmarshalOpen,
// returns exactly the top-level members the struct does not define (each a
// valid JSON value, none a defined name) and no more, returns nothing with an
// error, and that MarshalExtra of its results parses back to the same struct
// and members.
func FuzzUnmarshalExtra(f *testing.F) {
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	for _, s := range []string{
		`{"iss":"a","sub":"b","aud":["c"],"any":{"k":[1,2.5,null]},"x":{"k":1},"y":[2],"z":"<&>"}`,
		`{"iss":"a","ISS":"b"}`, `{"iss":"a","iss":"b"}`, `{"x":1,"x":2}`, `{"iss":1}`, `{"aud":"c"}`,
		`{"iss":"a"`, `{"iss":"a"}{"x":1}`, `{"x":` + string(bytes.Repeat([]byte("["), 600)) + `}`,
		`{"x":12345678901234567890123456789,"y":1e999}`, "{\"x\":\"\xff\"}", `{"iss":"a","x\u0000":0}`,
		`  {"extra" : [ true , false ] }  `, `{"":1}`,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		var got, open fuzzExtraDoc
		extra, err := strictjson.UnmarshalExtra(data, &got)
		openErr := strictjson.UnmarshalOpen(data, &open)
		if (err == nil) != (openErr == nil) {
			t.Fatalf("UnmarshalExtra = %v but UnmarshalOpen = %v for %q", err, openErr, data)
		}
		if err != nil {
			if extra != nil || !errors.Is(err, strictjson.ErrInvalid) {
				t.Fatalf("error %v returned members %v", err, extra)
			}
			return
		}
		if !reflect.DeepEqual(got, open) {
			t.Fatalf("results differ for %q: %+v != %+v", data, got, open)
		}
		var all map[string]json.RawMessage
		if json.Unmarshal(data, &all) != nil {
			// Not an object (a struct target refuses null and arrays, so
			// this is unreachable); there can be no extra members.
			if extra != nil {
				t.Fatalf("members %v from a non-object %q", extra, data)
			}
			return
		}
		known := strictjson.Members(reflect.TypeOf(got))
		if len(extra) == 0 && extra != nil {
			t.Fatal("empty non-nil members")
		}
		for name, raw := range extra {
			if known[name] {
				t.Fatalf("defined member %q returned as extra", name)
			}
			if !json.Valid(raw) || !sameJSON(raw, all[name]) {
				t.Fatalf("member %q = %q, document has %q", name, raw, all[name])
			}
		}
		for name := range all {
			if _, ok := extra[name]; !ok && !known[name] {
				t.Fatalf("undefined member %q was dropped from %q", name, data)
			}
		}
		// Round trip through MarshalExtra.
		out, err := strictjson.MarshalExtra(&got, extra)
		if err != nil {
			t.Fatalf("MarshalExtra: %v", err)
		}
		var back fuzzExtraDoc
		again, err := strictjson.UnmarshalExtra(out, &back)
		if err != nil {
			t.Fatalf("round trip %q refused: %v", out, err)
		}
		if !reflect.DeepEqual(back, got) || len(again) != len(extra) {
			t.Fatalf("round trip changed %+v/%v into %+v/%v via %q", got, extra, back, again, out)
		}
		for name, raw := range extra {
			if !sameJSON(raw, again[name]) {
				t.Fatalf("round trip changed member %q: %q != %q", name, raw, again[name])
			}
		}
	})
}

func TestUnmarshalExtraRefusals(t *testing.T) {
	var c claims
	var n int
	var m map[string]any
	for name, tc := range map[string]struct {
		data   string
		target any
		want   error
	}{
		"empty":             {``, &c, strictjson.ErrSyntax},
		"truncated":         {`{"iss":"a","x":`, &c, strictjson.ErrSyntax},
		"invalid UTF-8":     {"{\"x\":\"\xff\"}", &c, strictjson.ErrSyntax},
		"lone surrogate":    {`{"x":"\ud800"}`, &c, strictjson.ErrSyntax},
		"trailing data":     {`{"iss":"a"} {}`, &c, strictjson.ErrTrailingData},
		"too deep":          {`{"x":` + string(bytes.Repeat([]byte("["), strictjson.MaxDepth+1)) + `}`, &c, strictjson.ErrTooDeep},
		"duplicate defined": {`{"iss":"a","iss":"b"}`, &c, strictjson.ErrDuplicateMember},
		"duplicate extra":   {`{"x":1,"x":2}`, &c, strictjson.ErrDuplicateMember},
		"case variant":      {`{"ISS":"a"}`, &c, strictjson.ErrUnknownMember},
		"wrong type":        {`{"iss":1}`, &c, strictjson.ErrType},
		"null":              {`null`, &c, strictjson.ErrType},
		"array":             {`[]`, &c, strictjson.ErrType},
		"scalar":            {`1`, &c, strictjson.ErrType},
		"non-struct target": {`{"x":1}`, &m, strictjson.ErrType},
		"int target":        {`1`, &n, strictjson.ErrType},
	} {
		extra, err := strictjson.UnmarshalExtra([]byte(tc.data), tc.target)
		if extra != nil || !errors.Is(err, tc.want) || !errors.Is(err, strictjson.ErrInvalid) {
			t.Errorf("%s: %v, %v; want nil, %v", name, extra, err, tc.want)
		}
	}
	if _, err := strictjson.UnmarshalExtra([]byte(`{}`), nil); err == nil {
		t.Error("nil target accepted")
	}
	if _, err := strictjson.UnmarshalExtra([]byte(`{}`), c); err == nil {
		t.Error("non-pointer target accepted")
	}
	if _, err := strictjson.UnmarshalExtra([]byte(`{}`), (*claims)(nil)); err == nil {
		t.Error("nil pointer target accepted")
	}
}
