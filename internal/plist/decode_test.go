package plist

import (
	"reflect"
	"strings"
	"testing"
)

func TestUnmarshal_RoundTrip(t *testing.T) {
	want := Dict{
		{"Name", String(`Kids & <friends> ]]>`)},
		{"Version", Integer(-42)},
		{"On", Bool(true)},
		{"Off", Bool(false)},
		{"Items", Array{String("a"), Dict{{"Nested", Array{}}}, Dict{}}},
	}
	got, err := Unmarshal(Marshal(want))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Unmarshal(Marshal(v)) = %#v, want %#v", got, want)
	}
	if v, ok := got.(Dict).Lookup("Version"); !ok || v != Integer(-42) {
		t.Errorf("Lookup(Version) = %v, %v", v, ok)
	}
	if _, ok := got.(Dict).Lookup("Missing"); ok {
		t.Error("Lookup found a missing key")
	}
}

func TestUnmarshal_Refuses(t *testing.T) {
	wrap := func(body string) string { return header + body + "</plist>\n" }
	for name, in := range map[string]string{
		"not a plist":        `<?xml version="1.0"?><html></html>`,
		"empty":              wrap(""),
		"two values":         wrap("<true/><false/>"),
		"data":               wrap("<data>AAAA</data>"),
		"date":               wrap("<date>2026-01-01T00:00:00Z</date>"),
		"real":               wrap("<real>1.5</real>"),
		"repeated key":       wrap("<dict><key>a</key><true/><key>a</key><false/></dict>"),
		"key without value":  wrap("<dict><key>a</key></dict>"),
		"value without key":  wrap("<dict><string>a</string></dict>"),
		"text in a dict":     wrap("<dict>hello<key>a</key><true/></dict>"),
		"bad integer":        wrap("<integer>one</integer>"),
		"element in string":  wrap("<string>a<b/></string>"),
		"non-empty true":     wrap("<true>yes</true>"),
		"unclosed":           header + "<dict><key>a</key>",
		"too deep":           wrap(strings.Repeat("<array>", MaxDepth+1) + strings.Repeat("</array>", MaxDepth+1)),
		"too big":            wrap("<string>" + strings.Repeat("x", MaxSize) + "</string>"),
		"entity declaration": `<?xml version="1.0"?><!DOCTYPE plist [<!ENTITY x "y">]><plist><string>&x;</string></plist>`,
	} {
		if v, err := Unmarshal([]byte(in)); err == nil {
			t.Errorf("%s: Unmarshal = %#v, want an error", name, v)
		}
	}
}

func FuzzUnmarshal(f *testing.F) {
	f.Add(Marshal(Dict{{"a", Array{String("b"), Integer(1), Bool(true)}}}))
	f.Fuzz(func(t *testing.T, b []byte) {
		v, err := Unmarshal(b)
		if err != nil {
			return
		}
		// Whatever parses encodes, and parses back the same.
		again, err := Unmarshal(Marshal(v))
		if err != nil || !reflect.DeepEqual(again, v) {
			t.Errorf("round trip of %#v = %#v, %v", v, again, err)
		}
	})
}
