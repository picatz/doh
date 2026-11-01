package strictjson_test

import (
	"encoding/json"
	"errors"
	"net/netip"
	"reflect"
	"testing"
	"unicode"

	"github.com/picatz/doh/internal/strictjson"
)

// These regression tests pin the Go type model to encoding/json's: the names
// the scanner thinks a type defines must be the names json binds.

func TestMapKeysDecodedLikeJSON(t *testing.T) {
	var ints map[int]int
	if err := strictjson.Unmarshal([]byte(`{"1":1,"01":2,"+1":3}`), &ints); err == nil {
		// json refuses "+1" itself, which stays json's error; "1" and "01" must
		// be caught first.
		t.Fatal("accepted")
	}
	for _, in := range []string{`{"1":1,"01":2}`, `{"-0":1,"0":2}`} {
		var m map[int]int
		if err := strictjson.Unmarshal([]byte(in), &m); !errors.Is(err, strictjson.ErrDuplicateMember) {
			t.Errorf("map[int] %s: %v", in, err)
		}
	}
	var u map[uint8]int
	if err := strictjson.Unmarshal([]byte(`{"7":1,"07":2}`), &u); !errors.Is(err, strictjson.ErrDuplicateMember) {
		t.Errorf("map[uint8]: %v", err)
	}
	var addrs map[netip.Addr]int
	if err := strictjson.Unmarshal([]byte(`{"::1":1,"0:0:0:0:0:0:0:1":2}`), &addrs); !errors.Is(err, strictjson.ErrDuplicateMember) {
		t.Errorf("map[netip.Addr]: %v", err)
	}
	// Distinct keys, and keys json rejects, are not this package's to refuse.
	var ok map[int]int
	if err := strictjson.Unmarshal([]byte(`{"1":1,"2":2,"-3":3}`), &ok); err != nil || len(ok) != 3 {
		t.Errorf("distinct int keys: %v %v", ok, err)
	}
	var bad map[int]int
	err := strictjson.Unmarshal([]byte(`{"x":1}`), &bad)
	var typeErr *json.UnmarshalTypeError
	if !errors.Is(err, strictjson.ErrType) || !errors.As(err, &typeErr) {
		t.Errorf("undecodable key: %v", err)
	}
	// Nested: a struct holding such a map.
	var nested struct {
		M map[int]string `json:"m"`
	}
	if err := strictjson.Unmarshal([]byte(`{"m":{"5":"a","05":"b"}}`), &nested); !errors.Is(err, strictjson.ErrDuplicateMember) {
		t.Errorf("nested: %v", err)
	}
}

type tagged struct {
	A int `json:"a b"`
	B int `json:"c\"d"`
	C int `json:"ok-name"`
	D int `json:",omitempty"`
}

func TestInvalidTagIsRefused(t *testing.T) {
	// encoding/json binds a field with an invalid tag name under its Go
	// name before Go 1.27 and under the truncated tag name after, so
	// strictjson accepts the field under neither.
	var w tagged
	if err := strictjson.Unmarshal([]byte(`{"ok-name":5,"D":6}`), &w); err != nil || w.C != 5 || w.D != 6 {
		t.Fatalf("valid names: %+v %v", w, err)
	}
	for _, input := range []string{`{"B":4}`, `{"c\"d":1}`, `{"c":1}`} {
		if err := strictjson.Unmarshal([]byte(input), new(tagged)); !errors.Is(err, strictjson.ErrUnknownMember) {
			t.Errorf("%s: invalid-tag field was accepted: %v", input, err)
		}
	}
}

type E1 struct{ V, Only1 int }
type E2 struct{ V, Only2 int }
type Ambiguous struct {
	E1
	E2
	W int
}

type Inner struct{ X, Y int }
type Shadow struct {
	Inner
	X string // shallower: wins over Inner.X
}

type TaggedA struct{ Name int }
type TaggedB struct {
	Name int `json:"Name"`
}
type TagBeats struct {
	TaggedA
	TaggedB
}

func TestEmbeddedDominance(t *testing.T) {
	var a Ambiguous
	if err := strictjson.Unmarshal([]byte(`{"V":1}`), &a); !errors.Is(err, strictjson.ErrUnknownMember) {
		t.Errorf("ambiguous name accepted: %v", err)
	}
	if err := strictjson.Unmarshal([]byte(`{"Only1":1,"Only2":2,"W":3}`), &a); err != nil {
		t.Errorf("unambiguous names: %v", err)
	}
	var s Shadow
	if err := strictjson.Unmarshal([]byte(`{"X":"s","Y":2}`), &s); err != nil || s.X != "s" || s.Y != 2 {
		t.Errorf("shadowing: %+v %v", s, err)
	}
	var tb TagBeats
	if err := strictjson.Unmarshal([]byte(`{"Name":7}`), &tb); err != nil || tb.TaggedB.Name != 7 {
		t.Errorf("tagged field should win: %+v %v", tb, err)
	}
	// An ambiguous name json drops is not a case collision either: json binds
	// nothing for "v".
	if err := strictjson.UnmarshalOpen([]byte(`{"v":1}`), &a); err != nil {
		t.Errorf("open decoding ignores an unbound name: %v", err)
	}
}

type Cyc struct {
	*Cyc
	X int
}

type CycPair struct {
	*CycB
	P int
}
type CycB struct {
	*CycPair
	Q int
}

func TestEmbeddedCycle(t *testing.T) {
	var c Cyc
	if err := strictjson.Unmarshal([]byte(`{"X":1}`), &c); err != nil || c.X != 1 {
		t.Fatalf("self pointer: %+v %v", c, err)
	}
	if err := strictjson.Unmarshal([]byte(`{"Y":1}`), &c); !errors.Is(err, strictjson.ErrUnknownMember) {
		t.Fatalf("unknown through cycle: %v", err)
	}
	var p CycPair
	if err := strictjson.Unmarshal([]byte(`{"P":1,"Q":2}`), &p); err != nil {
		t.Fatalf("mutual cycle: %v", err)
	}
}

type pointee struct{ A int }

func TestInterfaceHoldingPointer(t *testing.T) {
	var x any = &pointee{}
	if err := strictjson.Unmarshal([]byte(`{"a":1,"A":2}`), &x); !errors.Is(err, strictjson.ErrDuplicateMember) && !errors.Is(err, strictjson.ErrUnknownMember) {
		t.Errorf("case collision through interface: %v", err)
	}
	x = &pointee{}
	if err := strictjson.Unmarshal([]byte(`{"a":1}`), &x); !errors.Is(err, strictjson.ErrUnknownMember) {
		t.Errorf("case-only through interface: %v", err)
	}
	x = &pointee{}
	if err := strictjson.Unmarshal([]byte(`{"nope":1}`), &x); !errors.Is(err, strictjson.ErrUnknownMember) {
		t.Errorf("unknown through interface: %v", err)
	}
	x = &pointee{}
	if err := strictjson.Unmarshal([]byte(`{"A":1}`), &x); err != nil || x.(*pointee).A != 1 {
		t.Errorf("valid through interface: %v %v", x, err)
	}
	// An empty interface, or one holding a non-pointer, decodes to generic
	// values and has no members to check.
	var free any
	if err := strictjson.Unmarshal([]byte(`{"a":1,"A":2}`), &free); err != nil {
		t.Errorf("empty interface: %v", err)
	}
	// The same through a struct field and a slice element.
	holder := struct {
		F any   `json:"f"`
		L []any `json:"l"`
	}{F: &pointee{}, L: []any{&pointee{}}}
	if err := strictjson.Unmarshal([]byte(`{"f":{"nope":1}}`), &holder); !errors.Is(err, strictjson.ErrUnknownMember) {
		t.Errorf("field: %v", err)
	}
	if err := strictjson.Unmarshal([]byte(`{"l":[{"nope":1}]}`), &holder); !errors.Is(err, strictjson.ErrUnknownMember) {
		t.Errorf("slice element: %v", err)
	}
}

type hidden struct {
	V int
}
type withHidden struct {
	hidden `json:"h"`
	Z      int
}

type withHiddenUntagged struct {
	hidden
	Z int
}

func TestUnexportedEmbeddedStructWithTag(t *testing.T) {
	// encoding/json treats a tagged embedded struct as a named field, even
	// when its type is unexported.
	var w withHidden
	err := strictjson.Unmarshal([]byte(`{"h":{"V":1},"Z":2}`), &w)
	var plain withHidden
	jsonErr := json.Unmarshal([]byte(`{"h":{"V":1},"Z":2}`), &plain)
	if (err == nil) != (jsonErr == nil) {
		t.Fatalf("strictjson %v, encoding/json %v", err, jsonErr)
	}
	if err := strictjson.Unmarshal([]byte(`{"V":1}`), &w); !errors.Is(err, strictjson.ErrUnknownMember) {
		t.Errorf("promoted name of a tagged embedded struct: %v", err)
	}
	var u withHiddenUntagged
	if err := strictjson.Unmarshal([]byte(`{"V":1,"Z":2}`), &u); err != nil || u.V != 1 {
		t.Errorf("untagged unexported embedded struct promotes its fields: %+v %v", u, err)
	}
}

// TestAcceptedNamesAreBoundByJSON checks that every member name strictjson
// accepts for these types is one encoding/json binds to a field, so the
// type model never admits a name that json would drop or merge.
func TestAcceptedNamesAreBoundByJSON(t *testing.T) {
	for _, typ := range []reflect.Type{
		reflect.TypeFor[tagged](), reflect.TypeFor[Ambiguous](), reflect.TypeFor[Shadow](),
		reflect.TypeFor[TagBeats](), reflect.TypeFor[Cyc](), reflect.TypeFor[CycPair](),
		reflect.TypeFor[withHiddenUntagged](),
	} {
		for _, name := range []string{"A", "B", "C", "D", "V", "W", "X", "Y", "Name", "Only1", "Only2", "P", "Q", "Z", "a b", `c"d`, "ok-name", "omitempty", ""} {
			data, err := json.Marshal(map[string]int{name: 1})
			if err != nil {
				t.Fatal(err)
			}
			strict := reflect.New(typ)
			if strictjson.Unmarshal(data, strict.Interface()) != nil {
				continue
			}
			plain := reflect.New(typ)
			if err := json.Unmarshal(data, plain.Interface()); err != nil || plain.Elem().IsZero() {
				t.Errorf("%v: strictjson accepts %q but encoding/json does not bind it (%v)", typ, name, err)
			}
		}
	}
}

func TestFoldAgreesWithJSON(t *testing.T) {
	var runes []rune
	for r := rune(0); r <= unicode.MaxRune; r++ {
		if unicode.SimpleFold(r) != r {
			runes = append(runes, r)
		}
	}
	for _, name := range runes {
		if !unicode.IsLetter(name) && !unicode.IsDigit(name) {
			continue
		}
		typ := reflect.StructOf([]reflect.StructField{{Name: "A", Type: reflect.TypeFor[int](), Tag: reflect.StructTag(`json:"` + string(name) + `"`)}})
		for f := unicode.SimpleFold(name); f != name; f = unicode.SimpleFold(f) {
			data := []byte(`{"` + string(f) + `":1}`)
			v := reflect.New(typ)
			if json.Unmarshal(data, v.Interface()) != nil || v.Elem().Field(0).Int() != 1 {
				continue // json does not bind it
			}
			if err := strictjson.UnmarshalOpen(data, reflect.New(typ).Interface()); !errors.Is(err, strictjson.ErrUnknownMember) {
				t.Fatalf("%U bound by json to %U was accepted: %v", f, name, err)
			}
		}
	}
}

func TestSliceSpareCapacity(t *testing.T) {
	type holder struct {
		L []any `json:"l"`
	}
	spare := func() *holder {
		backing := make([]any, 1)
		backing[0] = &pointee{}
		return &holder{L: backing[:0]}
	}
	for in, want := range map[string]error{
		`{"l":[{"a":1,"A":2}]}`: strictjson.ErrUnknownMember,
		`{"l":[{"zzz":1}]}`:     strictjson.ErrUnknownMember,
		`{"l":[{"A":1}]}`:       nil,
	} {
		h := spare()
		err := strictjson.Unmarshal([]byte(in), h)
		if want == nil && err != nil || want != nil && !errors.Is(err, want) {
			t.Errorf("%s: %v, want %v", in, err, want)
		}
	}
	// An array's elements are always destinations.
	arr := struct {
		A [1]pointee `json:"a"`
	}{}
	if err := strictjson.Unmarshal([]byte(`{"a":[{"a":1}]}`), &arr); !errors.Is(err, strictjson.ErrUnknownMember) {
		t.Errorf("array: %v", err)
	}
}

func TestStringOption(t *testing.T) {
	type quotedString struct {
		S string `json:"s,string"`
	}
	type quotedInt struct {
		N int `json:"n,string"`
	}
	type quotedPtr struct {
		P *string `json:"p,string"`
	}
	for _, tt := range []struct {
		name string
		in   string
		v    any
		bad  bool
	}{
		{"valid string", `{"s":"\"x\""}`, new(quotedString), false},
		{"lone high surrogate", `{"s":"\"\\ud800\""}`, new(quotedString), true},
		{"lone low surrogate", `{"s":"\"\\udc00\""}`, new(quotedString), true},
		{"paired surrogates", `{"s":"\"\\ud83d\\ude00\""}`, new(quotedString), false},
		{"escaped lone surrogate", `{"s":"\"\\\\ud800\""}`, new(quotedString), false},
		{"pointer", `{"p":"\"\\ud800\""}`, new(quotedPtr), true},
		{"canonical int", `{"n":"12"}`, new(quotedInt), false},
		{"leading zero", `{"n":"01"}`, new(quotedInt), true},
		{"int with plus", `{"n":"+1"}`, new(quotedInt), true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			err := strictjson.Unmarshal([]byte(tt.in), tt.v)
			if tt.bad && !errors.Is(err, strictjson.ErrSyntax) {
				t.Fatalf("accepted or wrong error: %v", err)
			}
			if !tt.bad && err != nil {
				t.Fatal(err)
			}
		})
	}
	// A plain string member with the same lone surrogate is refused alike.
	if err := strictjson.Unmarshal([]byte(`{"s":"\ud800"}`), new(struct {
		S string `json:"s"`
	})); !errors.Is(err, strictjson.ErrSyntax) {
		t.Fatalf("plain: %v", err)
	}
}
