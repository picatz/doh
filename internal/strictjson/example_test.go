package strictjson_test

import (
	"errors"
	"fmt"

	"github.com/picatz/doh/internal/strictjson"
)

type header struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
}

func ExampleUnmarshal() {
	var h header
	err := strictjson.Unmarshal([]byte(`{"alg":"ES256","kid":"k1"}`), &h)
	fmt.Println(h.Alg, h.Kid, err)

	// encoding/json would keep the last "alg" and ignore "Kid".
	for _, in := range []string{
		`{"alg":"ES256","alg":"none"}`,
		`{"alg":"ES256","Kid":"k1"}`,
		`{"alg":"ES256","extra":1}`,
		`{"alg":"ES256"} {}`,
	} {
		err := strictjson.Unmarshal([]byte(in), new(header))
		fmt.Println(errors.Is(err, strictjson.ErrInvalid), err)
	}
	// Output:
	// ES256 k1 <nil>
	// true strictjson: duplicate member: "alg"
	// true strictjson: unknown member: "Kid" differs from a defined member only in case
	// true strictjson: unknown member: "extra"; known members: "alg", "kid"
	// true strictjson: data after the JSON value
}

func ExampleUnmarshalExtra() {
	var h header
	extra, err := strictjson.UnmarshalExtra([]byte(`{"alg":"ES256","typ":"JWT"}`), &h)
	fmt.Println(h.Alg, string(extra["typ"]), err)

	out, _ := strictjson.MarshalExtra(h, extra)
	fmt.Println(string(out))
	// Output:
	// ES256 "JWT" <nil>
	// {"alg":"ES256","kid":"","typ":"JWT"}
}

func ExampleCheck() {
	fmt.Println(strictjson.Check([]byte(`{"a":{"b":1},"c":{"b":2}}`)))
	err := strictjson.Check([]byte(`{"a":[{"b":1,"b":2}]}`))
	fmt.Println(errors.Is(err, strictjson.ErrDuplicateMember), err)
	// Output:
	// <nil>
	// true strictjson: duplicate member: "b"
}

func ExampleObject() {
	doc := []byte(`{"payloadType":"text/plain","signatures":[]}`)
	if err := strictjson.Check(doc); err != nil {
		fmt.Println(err)
		return
	}
	members, _ := strictjson.Object(doc)
	typ, _ := strictjson.String(members["payloadType"])
	unknown, found := strictjson.Unknown(members, "payloadType")
	fmt.Println(typ, unknown, found)
	// Output: text/plain signatures true
}
