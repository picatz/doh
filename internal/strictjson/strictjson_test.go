package strictjson_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/picatz/doh/internal/strictjson"
)

type inner struct {
	N int `json:"n"`
}

type embedded struct {
	Shared string `json:"shared"`
}

type doc struct {
	embedded
	Name   string           `json:"name"`
	Tags   []string         `json:"tags"`
	Inner  *inner           `json:"inner"`
	Items  []inner          `json:"items"`
	Map    map[string]inner `json:"map"`
	Any    any              `json:"any"`
	Raw    json.RawMessage  `json:"raw"`
	Skip   string           `json:"-"`
	Dash   string           `json:"-,"`
	Plain  string
	Hidden string `json:"hidden"`
	_      int
}

func TestCheck(t *testing.T) {
	for _, tt := range []struct {
		name string
		in   string
		want error
	}{
		{"object", `{"a":1,"b":[true,null,"x"]}`, nil},
		{"scalar", `7`, nil},
		{"spaces", " \n{\"a\": 1}\t", nil},
		{"case differs", `{"a":1,"A":2}`, nil},
		{"empty", ``, strictjson.ErrSyntax},
		{"blank", `  `, strictjson.ErrSyntax},
		{"truncated", `{"a":`, strictjson.ErrSyntax},
		{"bad token", `{"a":nul}`, strictjson.ErrSyntax},
		{"invalid utf8", "{\"a\":\"\xff\"}", strictjson.ErrSyntax},
		{"lone high", `{"a":"\ud800"}`, strictjson.ErrSyntax},
		{"lone low", `{"a":"\udc00"}`, strictjson.ErrSyntax},
		{"high then letter", `{"a":"\ud800x"}`, strictjson.ErrSyntax},
		{"valid pair", `{"a":"😀"}`, nil},
		{"escaped quote then escape", `{"a":"\"\\ud800"}`, nil},
		{"trailing value", `{} {}`, strictjson.ErrTrailingData},
		{"trailing garbage", `{}x`, strictjson.ErrTrailingData},
		{"duplicate", `{"a":1,"a":2}`, strictjson.ErrDuplicateMember},
		{"duplicate escaped", `{"a":1,"a":2}`, strictjson.ErrDuplicateMember},
		{"duplicate nested", `{"x":[{"a":1,"a":2}]}`, strictjson.ErrDuplicateMember},
		{"same name in siblings", `{"x":{"a":1},"y":{"a":2}}`, nil},
		{"deep ok", strings.Repeat("[", strictjson.MaxDepth) + strings.Repeat("]", strictjson.MaxDepth), nil},
		{"too deep", strings.Repeat("[", strictjson.MaxDepth+1) + strings.Repeat("]", strictjson.MaxDepth+1), strictjson.ErrTooDeep},
	} {
		t.Run(tt.name, func(t *testing.T) {
			err := strictjson.Check([]byte(tt.in))
			if tt.want == nil {
				if err != nil {
					t.Fatalf("Check = %v", err)
				}
				return
			}
			if !errors.Is(err, tt.want) || !errors.Is(err, strictjson.ErrInvalid) {
				t.Fatalf("Check = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestUnmarshal(t *testing.T) {
	for _, tt := range []struct {
		name string
		in   string
		want error
	}{
		{"all fields", `{"name":"n","tags":["a"],"inner":{"n":1},"items":[{"n":2}],"map":{"k":{"n":3}},"any":{"free":{"form":1}},"raw":{"x":[1]},"Plain":"p","-":"d","shared":"s"}`, nil},
		{"null members", `{"name":null,"inner":null}`, nil},
		{"unknown", `{"nope":1}`, strictjson.ErrUnknownMember},
		{"unknown nested", `{"inner":{"n":1,"nope":2}}`, strictjson.ErrUnknownMember},
		{"unknown in slice", `{"items":[{"n":1},{"zzz":2}]}`, strictjson.ErrUnknownMember},
		{"unknown in map", `{"map":{"k":{"zzz":2}}}`, strictjson.ErrUnknownMember},
		{"case only", `{"Name":"n"}`, strictjson.ErrUnknownMember},
		{"case only nested", `{"inner":{"N":1}}`, strictjson.ErrUnknownMember},
		{"kelvin sign folds", "{\"K\":1}", strictjson.ErrUnknownMember},
		{"skipped field", `{"Skip":"x"}`, strictjson.ErrUnknownMember},
		{"unexported", `{"hidden":"x","_":1}`, strictjson.ErrUnknownMember},
		{"duplicate", `{"name":"a","name":"b"}`, strictjson.ErrDuplicateMember},
		{"trailing", `{"name":"a"} {}`, strictjson.ErrTrailingData},
		{"null object", `null`, strictjson.ErrType},
		{"array for object", `[]`, strictjson.ErrType},
		{"wrong type", `{"name":3}`, strictjson.ErrType},
		{"syntax", `{`, strictjson.ErrSyntax},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var d doc
			err := strictjson.Unmarshal([]byte(tt.in), &d)
			if tt.want == nil {
				if err != nil {
					t.Fatalf("Unmarshal = %v", err)
				}
				return
			}
			if !errors.Is(err, tt.want) || !errors.Is(err, strictjson.ErrInvalid) {
				t.Fatalf("Unmarshal = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestUnmarshalResultMatchesEncodingJSON(t *testing.T) {
	in := `{"name":"n","tags":["a","b"],"inner":{"n":1},"shared":"s","any":[1,{"a":null}]}`
	var got, want doc
	if err := strictjson.Unmarshal([]byte(in), &got); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(in), &want); err != nil {
		t.Fatal(err)
	}
	a, _ := json.Marshal(got)
	b, _ := json.Marshal(want)
	if string(a) != string(b) {
		t.Fatalf("got %s, want %s", a, b)
	}
}

func TestUnmarshalTargets(t *testing.T) {
	var m map[string]int
	if err := strictjson.Unmarshal([]byte(`{"A":1,"a":2}`), &m); err != nil || len(m) != 2 {
		t.Fatalf("map: %v %v", m, err)
	}
	var s []inner
	if err := strictjson.Unmarshal([]byte(`[{"n":1}]`), &s); err != nil || len(s) != 1 {
		t.Fatalf("slice: %v %v", s, err)
	}
	if err := strictjson.Unmarshal([]byte(`[{"x":1}]`), &s); !errors.Is(err, strictjson.ErrUnknownMember) {
		t.Fatalf("slice unknown: %v", err)
	}
	var n int
	if err := strictjson.Unmarshal([]byte(`4`), &n); err != nil || n != 4 {
		t.Fatalf("int: %v %v", n, err)
	}
	var p *inner
	if err := strictjson.Unmarshal([]byte(`{"n":1}`), &p); err != nil || p == nil || p.N != 1 {
		t.Fatalf("pointer: %v %v", p, err)
	}
	if err := strictjson.Unmarshal([]byte(`null`), &p); !errors.Is(err, strictjson.ErrType) {
		t.Fatalf("null into *struct: %v", err)
	}
	var i int
	if err := strictjson.Unmarshal([]byte(`null`), &i); err != nil {
		t.Fatalf("null into int: %v", err)
	}
	var invalid *doc
	if err := strictjson.Unmarshal([]byte(`{}`), nil); err == nil {
		t.Fatal("nil target accepted")
	}
	if err := strictjson.Unmarshal([]byte(`{}`), invalid); err == nil {
		t.Fatal("nil pointer target accepted")
	}
	if err := strictjson.Unmarshal([]byte(`{}`), doc{}); err == nil {
		t.Fatal("non-pointer target accepted")
	}
}

type failing struct{}

var errBoom = errors.New("boom")

func (*failing) UnmarshalJSON([]byte) error { return errBoom }

type text string

func (t *text) UnmarshalText(b []byte) error { *t = text(b); return nil }

func TestUnmarshalCustom(t *testing.T) {
	var f struct {
		F failing `json:"f"`
	}
	err := strictjson.Unmarshal([]byte(`{"f":{"anything":1}}`), &f)
	if !errors.Is(err, errBoom) || !errors.Is(err, strictjson.ErrType) {
		t.Fatalf("custom error lost: %v", err)
	}
	var x struct {
		T text `json:"t"`
	}
	if err := strictjson.Unmarshal([]byte(`{"t":"v"}`), &x); err != nil || x.T != "v" {
		t.Fatalf("text: %v %v", x, err)
	}
}

type claims struct {
	Iss string `json:"iss"`
	Sub string `json:"sub"`
}

func TestUnmarshalOpen(t *testing.T) {
	var c claims
	if err := strictjson.UnmarshalOpen([]byte(`{"iss":"a","extra":{"x":1}}`), &c); err != nil || c.Iss != "a" {
		t.Fatalf("open: %v %v", c, err)
	}
	for in, want := range map[string]error{
		`{"iss":"a","iss":"b"}`: strictjson.ErrDuplicateMember,
		`{"iss":"a","ISS":"b"}`: strictjson.ErrUnknownMember,
		`{"Sub":"a"}`:           strictjson.ErrUnknownMember,
		`{"iss":"a"}x`:          strictjson.ErrTrailingData,
		`null`:                  strictjson.ErrType,
	} {
		if err := strictjson.UnmarshalOpen([]byte(in), &c); !errors.Is(err, want) {
			t.Errorf("%s: %v, want %v", in, err, want)
		}
	}
}

func TestExtra(t *testing.T) {
	var c claims
	extra, err := strictjson.UnmarshalExtra([]byte(`{"iss":"a","x":{"k":1},"y":[2]}`), &c)
	if err != nil || len(extra) != 2 || string(extra["x"]) != `{"k":1}` {
		t.Fatalf("extra = %v, %v", extra, err)
	}
	out, err := strictjson.MarshalExtra(c, extra)
	if err != nil || string(out) != `{"iss":"a","sub":"","x":{"k":1},"y":[2]}` {
		t.Fatalf("MarshalExtra = %s, %v", out, err)
	}
	// An extra member never replaces a defined one.
	out, err = strictjson.MarshalExtra(c, map[string]json.RawMessage{"iss": json.RawMessage(`"evil"`)})
	if err != nil || string(out) != `{"iss":"a","sub":""}` {
		t.Fatalf("MarshalExtra override = %s, %v", out, err)
	}
	if extra, err := strictjson.UnmarshalExtra([]byte(`{"iss":"a"}`), &c); err != nil || extra != nil {
		t.Fatalf("no extra = %v, %v", extra, err)
	}
	var n int
	if _, err := strictjson.UnmarshalExtra([]byte(`1`), &n); !errors.Is(err, strictjson.ErrType) {
		t.Fatalf("non-struct: %v", err)
	}
	if _, err := strictjson.UnmarshalExtra([]byte(`[]`), &c); !errors.Is(err, strictjson.ErrType) {
		t.Fatalf("array: %v", err)
	}
}

func TestMembers(t *testing.T) {
	got := strictjson.Members(reflectType(doc{}))
	for _, name := range []string{"name", "shared", "Plain", "-", "hidden", "tags"} {
		if !got[name] {
			t.Errorf("missing member %q", name)
		}
	}
	for _, name := range []string{"Skip", "_", "embedded"} {
		if got[name] {
			t.Errorf("unexpected member %q", name)
		}
	}
}

func TestRawHelpers(t *testing.T) {
	members, err := strictjson.Object(json.RawMessage(` {"a":"x","b":null,"c":[1]} `))
	if err != nil || len(members) != 3 {
		t.Fatalf("Object = %v, %v", members, err)
	}
	for _, bad := range []string{`null`, `[]`, ``, `"s"`} {
		if _, err := strictjson.Object(json.RawMessage(bad)); !errors.Is(err, strictjson.ErrInvalid) {
			t.Errorf("Object(%q) = %v", bad, err)
		}
	}
	if elems, err := strictjson.Array(members["c"]); err != nil || len(elems) != 1 {
		t.Fatalf("Array = %v, %v", elems, err)
	}
	if _, err := strictjson.Array(json.RawMessage(`null`)); err == nil {
		t.Fatal("Array accepted null")
	}
	if s, err := strictjson.String(members["a"]); err != nil || s != "x" {
		t.Fatalf("String = %q, %v", s, err)
	}
	if _, err := strictjson.String(members["b"]); err == nil {
		t.Fatal("String accepted null")
	}
	if s, _ := strictjson.OptionalString(members, "b"); s != "" {
		t.Fatalf("OptionalString(null) = %q", s)
	}
	if s, _ := strictjson.OptionalString(members, "missing"); s != "" {
		t.Fatalf("OptionalString(missing) = %q", s)
	}
	if _, err := strictjson.OptionalString(members, "c"); err == nil {
		t.Fatal("OptionalString accepted an array")
	}
	if got, found := strictjson.Unknown(members, "a", "b"); got != "c" || !found {
		t.Fatalf("Unknown = %q, %v", got, found)
	}
	if got, found := strictjson.Unknown(members, "a", "b", "c"); got != "" || found {
		t.Fatalf("Unknown = %q, %v", got, found)
	}
	if !strictjson.IsNull(json.RawMessage(" null ")) || strictjson.IsNull(json.RawMessage(`0`)) {
		t.Fatal("IsNull")
	}
}

func TestBase64(t *testing.T) {
	for _, tt := range []struct {
		in   string
		want string
		ok   bool
	}{
		{"aGk", "hi", true},
		{"aGk=", "hi", true},
		{"aGk_", "hi?", true},
		{"+/8", "\xfb\xff", true},
		{"-_8", "\xfb\xff", true},
		{"+-8", "", false},
		{"aG k", "", false},
		{"aGl", "", false}, // nonzero trailing bits
		{"!!", "", false},
	} {
		got, err := strictjson.Base64(tt.in)
		if (err == nil) != tt.ok || (tt.ok && string(got) != tt.want) {
			t.Errorf("Base64(%q) = %q, %v", tt.in, got, err)
		}
	}
	if got := strictjson.MaxDecodedSize(4); got != 3 {
		t.Fatalf("MaxDecodedSize(4) = %d", got)
	}
}

func reflectType(v any) reflect.Type { return reflect.TypeOf(v) }

func TestErrorsTruncateMemberNames(t *testing.T) {
	long := strings.Repeat("k", 1<<20)
	for name, run := range map[string]func() error{
		"duplicate": func() error { return strictjson.Check([]byte(`{"` + long + `":1,"` + long + `":2}`)) },
		"unknown": func() error {
			return strictjson.Unmarshal([]byte(`{"`+long+`":1}`), new(claims))
		},
		"case": func() error {
			typ := reflect.StructOf([]reflect.StructField{{
				Name: "I", Type: reflect.TypeFor[string](), Tag: reflect.StructTag(`json:"` + strings.Repeat("i", 1<<20) + `"`),
			}})
			return strictjson.Unmarshal([]byte(`{"`+strings.Repeat("I", 1<<20)+`":1}`), reflect.New(typ).Interface())
		},
	} {
		err := run()
		if err == nil {
			t.Fatalf("%s: no error", name)
		}
		if len(err.Error()) > 256 || !strings.Contains(err.Error(), "...") {
			t.Errorf("%s: error is %d bytes: %.100q", name, len(err.Error()), err)
		}
	}
	// A name cut inside a multi-byte rune is cut before it.
	err := strictjson.Check([]byte(`{"` + strings.Repeat("\u00e9", 5) + strings.Repeat("é", 100) + `":1,"` + strings.Repeat("\u00e9", 5) + strings.Repeat("é", 100) + `":2}`))
	if err == nil || !utf8.ValidString(err.Error()) {
		t.Fatalf("invalid error text: %v", err)
	}
}

func TestEscapedAndWideObjects(t *testing.T) {
	if err := strictjson.Check([]byte(`{"a\nb":1,"a\u000ab":2}`)); !errors.Is(err, strictjson.ErrDuplicateMember) {
		t.Fatalf("escaped duplicate: %v", err)
	}
	if err := strictjson.Check([]byte(`{"\ud83d\ude00":1,"\ud83d\ude00":2}`)); !errors.Is(err, strictjson.ErrDuplicateMember) {
		t.Fatalf("surrogate-pair duplicate: %v", err)
	}
	var wide, dup strings.Builder
	wide.WriteByte('{')
	for i := range 1000 {
		fmt.Fprintf(&wide, `"k%d":%d,`, i, i)
	}
	dup.WriteString(wide.String())
	wide.WriteString(`"last":0}`)
	dup.WriteString(`"k999":0}`)
	if err := strictjson.Check([]byte(wide.String())); err != nil {
		t.Fatalf("wide object: %v", err)
	}
	if err := strictjson.Check([]byte(dup.String())); !errors.Is(err, strictjson.ErrDuplicateMember) {
		t.Fatalf("wide duplicate: %v", err)
	}
}

// An unknown member's error names the members the target defines, sorted
// and capped, so the author can see what was meant.
func TestUnknownMemberListsKnownMembers(t *testing.T) {
	var narrow struct {
		Zeta  int `json:"zeta"`
		Alpha int `json:"alpha"`
	}
	err := strictjson.Unmarshal([]byte(`{"beta":1}`), &narrow)
	if want := `strictjson: unknown member: "beta"; known members: "alpha", "zeta"`; err == nil || err.Error() != want {
		t.Errorf("narrow: %v, want %s", err, want)
	}
	var empty struct{}
	err = strictjson.Unmarshal([]byte(`{"beta":1}`), &empty)
	if want := `strictjson: unknown member: "beta"; the object takes no members`; err == nil || err.Error() != want {
		t.Errorf("empty: %v, want %s", err, want)
	}
	type wide struct {
		A01, A02, A03, A04, A05, A06, A07, A08, A09, A10 int
		A11, A12, A13, A14, A15, A16, A17, A18, A19, A20 int
		A21, A22, A23, A24, A25, A26, A27, A28, A29, A30 int
	}
	err = strictjson.Unmarshal([]byte(`{"nope":1}`), &wide{})
	if err == nil || !strings.Contains(err.Error(), `"A01", "A02"`) || !strings.HasSuffix(err.Error(), " more") || len(err.Error()) > 256 {
		t.Errorf("wide: %v (%d bytes)", err, len(err.Error()))
	}
}
