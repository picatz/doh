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

var redactionDecoders = []struct {
	name         string
	allowExtra   bool
	collectExtra bool
	run          func([]byte, any) (map[string]json.RawMessage, error)
}{
	{"closed", false, false, func(data []byte, v any) (map[string]json.RawMessage, error) {
		return nil, strictjson.Unmarshal(data, v)
	}},
	{"open", true, false, func(data []byte, v any) (map[string]json.RawMessage, error) {
		return nil, strictjson.UnmarshalOpen(data, v)
	}},
	{"extra", true, true, strictjson.UnmarshalExtra},
}

// Check ordinary formatting separately from the deliberately accessible cause.
func assertRedactedConversion(t *testing.T, err error, private string) {
	t.Helper()
	if err == nil {
		t.Fatal("conversion succeeded, want an error")
	}
	for _, category := range []error{strictjson.ErrType, strictjson.ErrInvalid} {
		if !errors.Is(err, category) {
			t.Errorf("error category = %T, want %v", err, category)
		}
	}
	if err.Error() != strictjson.ErrType.Error() {
		t.Error("conversion error message differs from the fixed ErrType message")
	}
	privateFragment := private[:min(len(private), 32)]
	for name, message := range map[string]string{
		"Error":   err.Error(),
		"Sprint":  fmt.Sprint(err),
		"v":       fmt.Sprintf("%v", err),
		"plus-v":  fmt.Sprintf("%+v", err),
		"s":       fmt.Sprintf("%s", err),
		"wrapped": fmt.Errorf("decode request: %w", err).Error(),
	} {
		if strings.Contains(message, privateFragment) {
			t.Errorf("%s formatting includes the synthetic private value", name)
		}
		if len(message) > 256 {
			t.Errorf("%s error length = %d, want at most 256", name, len(message))
		}
	}
}

func TestUnmarshalErrorsRedactNumericValues(t *testing.T) {
	digits := strings.Repeat("7", 4096)
	for _, decoder := range redactionDecoders {
		t.Run(decoder.name, func(t *testing.T) {
			for _, tc := range []struct {
				name   string
				target any
				quoted bool
				typ    reflect.Type
			}{
				{"integer", new(struct {
					N int8 `json:"n"`
				}), false, reflect.TypeFor[int8]()},
				{"float", new(struct {
					N float64 `json:"n"`
				}), false, reflect.TypeFor[float64]()},
				{"quoted-integer", new(struct {
					N int8 `json:"n,string"`
				}), true, reflect.TypeFor[int8]()},
				{"quoted-float", new(struct {
					N float64 `json:"n,string"`
				}), true, reflect.TypeFor[float64]()},
			} {
				t.Run(tc.name, func(t *testing.T) {
					value := digits
					if tc.quoted {
						value = `"` + value + `"`
					}
					extra, err := decoder.run([]byte(`{"n":`+value+`}`), tc.target)
					assertRedactedConversion(t, err, digits)
					if extra != nil {
						t.Error("failed conversion returned extra members")
					}
					var cause *json.UnmarshalTypeError
					if !errors.As(err, &cause) {
						t.Fatalf("cause type = %T, want *json.UnmarshalTypeError", err)
					}
					if cause.Value != "number "+digits || cause.Type != tc.typ || cause.Field != "n" || cause.Offset == 0 {
						t.Error("explicit cause inspection lost the original conversion details")
					}
				})
			}
		})
	}
}

type redactionCause struct {
	value     string
	sentinel  error
	formatted int
}

func (e *redactionCause) Error() string {
	e.formatted++
	return "custom conversion failed: " + e.value
}

func (e *redactionCause) Unwrap() error { return e.sentinel }

type redactionJSON struct {
	cause   *redactionCause
	decoded string
}

func (v *redactionJSON) UnmarshalJSON(data []byte) error {
	if err := json.Unmarshal(data, &v.decoded); err != nil {
		return err
	}
	if v.cause != nil {
		v.cause.value = v.decoded
		return v.cause
	}
	return nil
}

type redactionText struct {
	cause   *redactionCause
	decoded string
}

func (v *redactionText) UnmarshalText(data []byte) error {
	v.decoded = string(data)
	if v.cause != nil {
		v.cause.value = v.decoded
		return v.cause
	}
	return nil
}

func TestUnmarshalErrorsRedactCustomDecoderMessages(t *testing.T) {
	private := strings.Repeat("synthetic-private-value-", 256)
	for _, decoder := range redactionDecoders {
		t.Run(decoder.name, func(t *testing.T) {
			for _, tc := range []struct {
				name   string
				target func(*redactionCause) any
			}{
				{"JSON", func(cause *redactionCause) any {
					return &struct {
						Value redactionJSON `json:"value"`
					}{Value: redactionJSON{cause: cause}}
				}},
				{"text", func(cause *redactionCause) any {
					return &struct {
						Value redactionText `json:"value"`
					}{Value: redactionText{cause: cause}}
				}},
			} {
				t.Run(tc.name, func(t *testing.T) {
					sentinel := errors.New("synthetic decoder sentinel")
					original := &redactionCause{sentinel: sentinel}
					extra, err := decoder.run([]byte(`{"value":"`+private+`"}`), tc.target(original))
					assertRedactedConversion(t, err, private)
					if extra != nil {
						t.Error("failed conversion returned extra members")
					}
					if !errors.Is(err, sentinel) || !errors.Is(err, original) {
						t.Error("errors.Is cannot reach the original custom decoder error and sentinel")
					}
					var cause *redactionCause
					if !errors.As(err, &cause) || cause != original {
						t.Fatal("errors.As did not recover the exact original custom decoder error")
					}
					if cause.formatted != 0 {
						t.Errorf("custom Error method called %d times, want none", cause.formatted)
					}
					if cause.value != private || !strings.Contains(cause.Error(), private) {
						t.Error("explicit cause inspection lost the original custom decoder details")
					}
				})
			}
		})
	}
}

func TestUnmarshalErrorRedactionSuccessfulControls(t *testing.T) {
	for _, decoder := range redactionDecoders {
		t.Run(decoder.name, func(t *testing.T) {
			var target struct {
				N    int8          `json:"n"`
				JSON redactionJSON `json:"json"`
				Text redactionText `json:"text"`
			}
			data := `{"n":7,"json":"json value","text":"text value"}`
			if decoder.allowExtra {
				data = strings.TrimSuffix(data, "}") + `,"extension":{"ok":true}}`
			}
			extra, err := decoder.run([]byte(data), &target)
			if err != nil {
				t.Fatalf("valid conversion failed: %v", err)
			}
			if target.N != 7 || target.JSON.decoded != "json value" || target.Text.decoded != "text value" {
				t.Error("successful conversion did not preserve numeric and custom decoder values")
			}
			if decoder.collectExtra {
				if len(extra) != 1 || string(extra["extension"]) != `{"ok":true}` {
					t.Errorf("extra members = %v, want the extension object", extra)
				}
			} else if extra != nil {
				t.Error("decoding without extra-member collection returned members")
			}
		})
	}
}

func TestOptionalStringErrorsTruncateMemberNames(t *testing.T) {
	for _, name := range []string{strings.Repeat("k", 4096), strings.Repeat("é", 4096)} {
		value, err := strictjson.OptionalString(map[string]json.RawMessage{name: json.RawMessage(`7`)}, name)
		if value != "" || !errors.Is(err, strictjson.ErrType) || !errors.Is(err, strictjson.ErrInvalid) {
			t.Fatalf("OptionalString result = %q, error type = %T; want empty and ErrType", value, err)
		}
		message := err.Error()
		if len(message) > 256 || !strings.Contains(message, "...") || strings.Contains(message, name) || !utf8.ValidString(message) {
			t.Errorf("member-name error is not bounded and valid UTF-8: length %d", len(message))
		}
	}
}
