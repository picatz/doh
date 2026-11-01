// Package plist encodes Apple XML property lists, as configuration
// profiles use, from a small set of typed values.
//
// Dictionaries keep their keys in the order given, so output is
// deterministic and diffs cleanly.
package plist

import (
	"bytes"
	"encoding/xml"
	"io"
	"strconv"
)

// Value is a property list value: [String], [Integer], [Bool], [Array],
// or [Dict].
type Value interface {
	encode(w *bytes.Buffer, depth int)
}

// String is a string value.
type String string

// Integer is an integer value.
type Integer int64

// Bool is a boolean value.
type Bool bool

// Array is an ordered list of values.
type Array []Value

// Dict is a dictionary, encoded in the order of its entries.
type Dict []Entry

// Entry is a dictionary entry.
type Entry struct {
	Key   string
	Value Value
}

// header begins every property list.
const header = xml.Header +
	`<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">` + "\n" +
	`<plist version="1.0">` + "\n"

// Encode writes v as an XML property list.
func Encode(w io.Writer, v Value) error {
	var b bytes.Buffer
	b.WriteString(header)
	v.encode(&b, 0)
	b.WriteString("</plist>\n")
	_, err := w.Write(b.Bytes())
	return err
}

// Marshal returns v as an XML property list.
func Marshal(v Value) []byte {
	var b bytes.Buffer
	_ = Encode(&b, v) // writes to a bytes.Buffer don't fail
	return b.Bytes()
}

func indent(w *bytes.Buffer, depth int) {
	for range depth {
		w.WriteByte('\t')
	}
}

// element writes <name>text</name>, escaping text.
func element(w *bytes.Buffer, depth int, name, text string) {
	indent(w, depth)
	w.WriteString("<" + name + ">")
	_ = xml.EscapeText(w, []byte(text))
	w.WriteString("</" + name + ">\n")
}

func (s String) encode(w *bytes.Buffer, depth int) { element(w, depth, "string", string(s)) }

func (i Integer) encode(w *bytes.Buffer, depth int) {
	element(w, depth, "integer", strconv.FormatInt(int64(i), 10))
}

func (b Bool) encode(w *bytes.Buffer, depth int) {
	indent(w, depth)
	if b {
		w.WriteString("<true/>\n")
	} else {
		w.WriteString("<false/>\n")
	}
}

func (a Array) encode(w *bytes.Buffer, depth int) {
	indent(w, depth)
	w.WriteString("<array>\n")
	for _, v := range a {
		v.encode(w, depth+1)
	}
	indent(w, depth)
	w.WriteString("</array>\n")
}

func (d Dict) encode(w *bytes.Buffer, depth int) {
	indent(w, depth)
	w.WriteString("<dict>\n")
	for _, e := range d {
		element(w, depth+1, "key", e.Key)
		e.Value.encode(w, depth+1)
	}
	indent(w, depth)
	w.WriteString("</dict>\n")
}
