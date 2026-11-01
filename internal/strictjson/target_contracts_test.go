package strictjson_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"reflect"
	"testing"
	"time"

	"github.com/picatz/doh/internal/strictjson"
)

func TestUnknownEmptyName(t *testing.T) {
	for _, tt := range []struct {
		name  string
		input string
		known []string
		want  string
		found bool
	}{
		{"empty unknown", `{"":1}`, []string{"a"}, "", true},
		{"empty sorts first", `{"z":1,"":2,"a":3}`, nil, "", true},
		{"empty known", `{"":1}`, []string{""}, "", false},
		{"empty known with unknown", `{"":1,"z":2,"a":3}`, []string{""}, "a", true},
		{"all known", `{"a":1,"b":2}`, []string{"b", "a"}, "", false},
		{"nonempty minimum", `{"z":1,"b":2,"a":3}`, []string{"a"}, "b", true},
		{"empty object", `{}`, nil, "", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if err := strictjson.Check([]byte(tt.input)); err != nil {
				t.Fatal(err)
			}
			members, err := strictjson.Object([]byte(tt.input))
			if err != nil {
				t.Fatal(err)
			}
			// Exercise different map iteration orders, including when the
			// empty name precedes another unknown name.
			for range 100 {
				got, found := strictjson.Unknown(members, tt.known...)
				if got != tt.want || found != tt.found {
					t.Fatalf("Unknown = (%q, %v), want (%q, %v)", got, found, tt.want, tt.found)
				}
			}
		})
	}
	if got, found := strictjson.Unknown(nil); got != "" || found {
		t.Fatalf("Unknown(nil) = (%q, %v)", got, found)
	}
}

type extraDoc struct {
	Name string `json:"name,omitempty"`
}

type nonObjectMarshaler struct{ JSON string }

func (v nonObjectMarshaler) MarshalJSON() ([]byte, error) { return []byte(v.JSON), nil }

func TestMarshalExtraTarget(t *testing.T) {
	var nilDoc *extraDoc
	var nilDocPointer **extraDoc
	for _, tt := range []struct {
		name  string
		value any
	}{
		{"nil struct pointer", nilDoc},
		{"nil pointer chain", nilDocPointer},
		{"pointer to nil struct pointer", &nilDoc},
		{"nil interface", nil},
		{"non-struct", map[string]int{"a": 1}},
		{"custom null", nonObjectMarshaler{"null"}},
		{"custom array", nonObjectMarshaler{"[]"}},
		{"custom scalar", nonObjectMarshaler{"1"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := strictjson.MarshalExtra(tt.value, map[string]json.RawMessage{"extra": json.RawMessage(`1`)})
			if !errors.Is(err, strictjson.ErrType) || !errors.Is(err, strictjson.ErrInvalid) {
				t.Fatalf("MarshalExtra error = %v, want ErrType and ErrInvalid", err)
			}
			if got != nil {
				t.Fatalf("MarshalExtra result = %s, want nil", got)
			}
		})
	}
	for _, tt := range []struct {
		name  string
		value any
		want  string
	}{
		{"value", extraDoc{Name: "kept"}, `{"extra":1,"name":"kept"}`},
		{"pointer", &extraDoc{Name: "kept"}, `{"extra":1,"name":"kept"}`},
		{"omitted field", extraDoc{}, `{"extra":1}`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			extra := map[string]json.RawMessage{"extra": json.RawMessage(`1`), "name": json.RawMessage(`"overridden"`)}
			got, err := strictjson.MarshalExtra(tt.value, extra)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != tt.want {
				t.Fatalf("MarshalExtra = %s, want %s", got, tt.want)
			}
		})
	}
	for _, extra := range []map[string]json.RawMessage{nil, {}} {
		got, err := strictjson.MarshalExtra(nilDoc, extra)
		if err != nil || string(got) != "null" {
			t.Fatalf("nil pointer without extras = %s, %v, want null, nil", got, err)
		}
	}
}

func TestInterfaceSelfReference(t *testing.T) {
	// A regression in target traversal must fail a child process rather
	// than hang the entire suite. The test binary is already compiled.
	const childEnv = "KEYBLADE_STRICTJSON_SELF_REFERENCE_TEST"
	if os.Getenv(childEnv) != "1" {
		exe, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, exe, "-test.run=^TestInterfaceSelfReference$", "-test.timeout=5s")
		cmd.Env = append(os.Environ(), childEnv+"=1")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("self-reference subprocess: %v (context: %v)\n%s", err, ctx.Err(), out)
		}
		return
	}
	for name, decode := range map[string]func([]byte, any) error{
		"closed": strictjson.Unmarshal,
		"open":   strictjson.UnmarshalOpen,
	} {
		t.Run(name, func(t *testing.T) {
			for _, input := range []string{`{}`, `[]`, `{"a":[1]}`, `[1,{"a":2}]`} {
				t.Run(input, func(t *testing.T) {
					// The oracle decodes into a fresh interface: from Go 1.27
					// encoding/json overflows the stack on a self-reference,
					// which strictjson breaks first.
					var got, want any
					got = &got
					if err := json.Unmarshal([]byte(input), &want); err != nil {
						t.Fatal(err)
					}
					if err := decode([]byte(input), &got); err != nil {
						t.Fatal(err)
					}
					if !reflect.DeepEqual(got, want) {
						t.Fatalf("decoded = %#v, want %#v", got, want)
					}
				})
			}
			// The same direct cycle may be reached through a reused field
			// or slice element; other fields still receive strict checks.
			type holder struct {
				Field any   `json:"field"`
				List  []any `json:"list"`
			}
			makeHolder := func() *holder {
				h := &holder{List: make([]any, 1)}
				h.Field, h.List[0] = &h.Field, &h.List[0]
				return h
			}
			// The oracle decodes into a holder without the cycles, which is
			// what encoding/json before Go 1.27 does with them.
			got, want := makeHolder(), &holder{List: make([]any, 1)}
			input := []byte(`{"field":{"a":1},"list":[[2]]}`)
			if err := json.Unmarshal(input, want); err != nil {
				t.Fatal(err)
			}
			if err := decode(input, got); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("nested decode = %#v, want %#v", got, want)
			}
			if err := decode([]byte(`{"FIELD":{}}`), makeHolder()); !errors.Is(err, strictjson.ErrUnknownMember) {
				t.Fatalf("case-only field error = %v, want ErrUnknownMember", err)
			}
			var custom any = &failing{}
			if err := decode([]byte(`{"notAField":1}`), &custom); !errors.Is(err, errBoom) {
				t.Fatalf("interface-held custom method error = %v, want errBoom", err)
			}
		})
	}
}
