package strictjson

import (
	"cmp"
	"encoding"
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"unicode"
)

// Container kinds a decoded type can have, for the scanner.
const (
	kindOpaque = iota // decoded by a method, or not a container: not inspected
	kindStruct
	kindMap
	kindList
)

// target is how the scanner sees a Go type that a JSON container decodes into.
type target struct {
	kind   int
	fields *structFields // kindStruct
	elem   reflect.Type  // kindMap and kindList
	// keyOf decodes a map key as encoding/json does, for maps whose key type
	// is not a string kind; ok is false when the key does not decode, which
	// encoding/json reports itself.
	keyOf func(name []byte) (key any, ok bool)
}

var (
	opaque      = &target{}
	targetCache sync.Map // reflect.Type -> *target
)

var (
	jsonUnmarshaler = reflect.TypeFor[json.Unmarshaler]()
	textUnmarshaler = reflect.TypeFor[encoding.TextUnmarshaler]()
)

func indirect(t reflect.Type) reflect.Type {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	return t
}

// resolve describes t, which must not be an interface or pointer. A nil type,
// and a type that implements [encoding/json.Unmarshaler] or
// [encoding.TextUnmarshaler], is opaque: its members are not inspected.
func resolve(t reflect.Type) *target {
	if t == nil {
		return opaque
	}
	if cached, ok := targetCache.Load(t); ok {
		return cached.(*target)
	}
	tg := opaque
	if !implementsUnmarshaler(t) {
		switch t.Kind() {
		case reflect.Struct:
			tg = &target{kind: kindStruct, fields: fieldsOf(t)}
		case reflect.Map:
			tg = &target{kind: kindMap, elem: t.Elem(), keyOf: keyDecoder(t.Key())}
		case reflect.Slice, reflect.Array:
			tg = &target{kind: kindList, elem: t.Elem()}
		}
	}
	targetCache.Store(t, tg)
	return tg
}

func implementsUnmarshaler(t reflect.Type) bool {
	pt := reflect.PointerTo(t)
	return pt.Implements(jsonUnmarshaler) || pt.Implements(textUnmarshaler)
}

// keyDecoder returns how encoding/json turns a member name into a map key of
// type kt (decode.go, in object): UnmarshalText when *kt implements it,
// otherwise the name itself for a string kind, otherwise a base-10 integer.
// It returns nil when the raw name is the key.
func keyDecoder(kt reflect.Type) func([]byte) (any, bool) {
	switch {
	case reflect.PointerTo(kt).Implements(textUnmarshaler):
		return func(name []byte) (any, bool) {
			kv := reflect.New(kt)
			if kv.Interface().(encoding.TextUnmarshaler).UnmarshalText(name) != nil || !kv.Elem().Comparable() {
				return nil, false
			}
			return kv.Elem().Interface(), true
		}
	case kt.Kind() == reflect.String:
		return nil
	}
	switch kt.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		zero := reflect.New(kt).Elem()
		return func(name []byte) (any, bool) {
			n, err := strconv.ParseInt(string(name), 10, 64)
			if err != nil || zero.OverflowInt(n) {
				return nil, false
			}
			return n, true
		}
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		zero := reflect.New(kt).Elem()
		return func(name []byte) (any, bool) {
			n, err := strconv.ParseUint(string(name), 10, 64)
			if err != nil || zero.OverflowUint(n) {
				return nil, false
			}
			return n, true
		}
	}
	return nil
}

// A field is a member name a struct type defines, with the path of struct
// field indexes that reaches it and the declared type of its last field.
type field struct {
	name   string
	tag    bool
	index  []int
	typ    reflect.Type
	quoted bool // the ,string option applies: the value is JSON text in a string
}

// structFields are the member names a struct type defines.
type structFields struct {
	byName map[string]*field
	folded map[string]struct{}
	known  string // the members an unknown-member error lists
}

var fieldCache sync.Map // reflect.Type -> *structFields

// maxKnown is roughly the most bytes of member names an unknown-member
// error lists, so errors stay short for wide structs.
const maxKnown = 160

// knownMembers names a struct's members, sorted, for an unknown-member
// error: the defined names come from the program, not the input, so they
// are safe to show and tell the author what was meant.
func knownMembers(fields []field) string {
	if len(fields) == 0 {
		return "the object takes no members"
	}
	names := make([]string, len(fields))
	for i := range fields {
		names[i] = strconv.Quote(fields[i].name)
	}
	slices.Sort(names)
	var b strings.Builder
	b.WriteString("known members: ")
	for i, name := range names {
		if i > 0 && b.Len()+len(name) > maxKnown {
			fmt.Fprintf(&b, ", and %d more", len(names)-i)
			break
		}
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(name)
	}
	return b.String()
}

func fieldsOf(t reflect.Type) *structFields {
	if cached, ok := fieldCache.Load(t); ok {
		return cached.(*structFields)
	}
	fields := typeFields(t)
	f := &structFields{byName: make(map[string]*field, len(fields)), folded: make(map[string]struct{}, len(fields))}
	for i := range fields {
		f.byName[fields[i].name] = &fields[i]
		f.folded[foldName(fields[i].name)] = struct{}{}
	}
	f.known = knownMembers(fields)
	actual, _ := fieldCache.LoadOrStore(t, f)
	return actual.(*structFields)
}

// typeFields returns the members that encoding/json decodes into the fields
// of struct type t. It mirrors typeFields in encoding/json's encode.go
// (Go 1.26) without the encoder state: it follows embedded structs breadth
// first and visits each type once, which also ends a self-embedding pointer;
// it ignores a tag of "-" and drops a field whose tag name isValidTag
// refuses, because encoding/json binds such a field under different names
// in different releases (the Go name before Go 1.27, a truncated tag name
// after); and of fields with one name keeps the shallowest, a
// tagged one over an untagged one at the same depth, and none when that
// still leaves two.
func typeFields(t reflect.Type) []field {
	// Anonymous struct fields to explore at the current level and the next.
	type queued struct {
		typ   reflect.Type
		index []int
	}
	current := []queued{}
	next := []queued{{typ: t}}
	// Count of queued names for current level and the next.
	var count, nextCount map[reflect.Type]int
	// Types already visited at an earlier level.
	visited := map[reflect.Type]bool{}
	var fields []field

	for len(next) > 0 {
		current, next = next, current[:0]
		count, nextCount = nextCount, map[reflect.Type]int{}
		for _, f := range current {
			if visited[f.typ] {
				continue
			}
			visited[f.typ] = true
			for i := 0; i < f.typ.NumField(); i++ {
				sf := f.typ.Field(i)
				if sf.Anonymous {
					t := sf.Type
					if t.Kind() == reflect.Pointer {
						t = t.Elem()
					}
					if !sf.IsExported() && t.Kind() != reflect.Struct {
						// Ignore embedded fields of unexported non-struct types.
						continue
					}
					// Do not ignore embedded fields of unexported struct types
					// since they may have exported fields.
				} else if !sf.IsExported() {
					// Ignore unexported non-embedded fields.
					continue
				}
				tag := sf.Tag.Get("json")
				if tag == "-" {
					continue
				}
				name, opts, _ := strings.Cut(tag, ",")
				if name != "" && !isValidTag(name) {
					// No name binds the same way in every release, so the
					// field accepts none.
					continue
				}
				index := make([]int, len(f.index)+1)
				copy(index, f.index)
				index[len(f.index)] = i

				ft := sf.Type
				if ft.Name() == "" && ft.Kind() == reflect.Pointer {
					// Follow pointer.
					ft = ft.Elem()
				}
				// Only strings, floats, integers, and booleans can be quoted.
				quoted := false
				if slices.Contains(strings.Split(opts, ","), "string") {
					switch ft.Kind() {
					case reflect.Bool,
						reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
						reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr,
						reflect.Float32, reflect.Float64,
						reflect.String:
						quoted = true
					}
				}
				// Record found field and index sequence.
				if name != "" || !sf.Anonymous || ft.Kind() != reflect.Struct {
					tagged := name != ""
					if name == "" {
						name = sf.Name
					}
					fields = append(fields, field{name: name, tag: tagged, index: index, typ: sf.Type, quoted: quoted})
					if count[f.typ] > 1 {
						// There were multiple instances: add a second copy so
						// that the dominance code sees a duplicate.
						fields = append(fields, fields[len(fields)-1])
					}
					continue
				}
				// Record new anonymous struct to explore in next round.
				nextCount[ft]++
				if nextCount[ft] == 1 {
					next = append(next, queued{typ: ft, index: index})
				}
			}
		}
	}

	slices.SortFunc(fields, func(a, b field) int {
		// Sort by name, breaking ties with depth, then with "name came from
		// a json tag", then with the index sequence.
		if c := strings.Compare(a.name, b.name); c != 0 {
			return c
		}
		if c := cmp.Compare(len(a.index), len(b.index)); c != 0 {
			return c
		}
		if a.tag != b.tag {
			if a.tag {
				return -1
			}
			return +1
		}
		return slices.Compare(a.index, b.index)
	})

	// Delete the fields hidden by the Go rules for embedded fields, except
	// that fields with JSON tags are promoted. The first field of a name is
	// the dominant one unless the second is as shallow and as tagged.
	out := fields[:0]
	for advance, i := 0, 0; i < len(fields); i += advance {
		fi := fields[i]
		for advance = 1; i+advance < len(fields); advance++ {
			if fields[i+advance].name != fi.name {
				break
			}
		}
		if advance == 1 {
			out = append(out, fi)
			continue
		}
		group := fields[i : i+advance]
		if len(group[0].index) == len(group[1].index) && group[0].tag == group[1].tag {
			continue
		}
		out = append(out, group[0])
	}
	return out
}

// isValidTag is isValidTag of encoding/json's encode.go.
func isValidTag(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		switch {
		case strings.ContainsRune("!#$%&()*+-./:;<=>?@[]^_{|}~ ", c):
			// Backslash and quote chars are reserved, but otherwise any
			// punctuation chars are allowed in a tag name.
		case !unicode.IsLetter(c) && !unicode.IsDigit(c):
			return false
		}
	}
	return true
}

// hasFolded reports whether name matches a defined member only when case is
// ignored, as encoding/json would silently match it.
func hasFolded(f *structFields, name []byte) bool {
	_, ok := f.folded[foldName(string(name))]
	return ok
}

// Members returns the JSON member names of struct type t, which encoding/json
// decodes into its fields, following embedded structs the way it does.
func Members(t reflect.Type) map[string]bool {
	fields := fieldsOf(indirect(t))
	out := make(map[string]bool, len(fields.byName))
	for name := range fields.byName {
		out[name] = true
	}
	return out
}

var interfaceCarrier sync.Map // reflect.Type -> bool

// mayHoldInterface reports whether decoding into a value of type t can reach
// an interface, along the pointers, struct fields and slice or array elements
// that encoding/json reuses. Map elements are decoded into fresh values.
func mayHoldInterface(t reflect.Type) bool {
	if v, ok := interfaceCarrier.Load(t); ok {
		return v.(bool)
	}
	result := holds(t, map[reflect.Type]bool{})
	interfaceCarrier.Store(t, result)
	return result
}

func holds(t reflect.Type, seen map[reflect.Type]bool) bool {
	if seen[t] {
		return false
	}
	seen[t] = true
	switch t.Kind() {
	case reflect.Interface:
		return true
	case reflect.Pointer, reflect.Slice, reflect.Array:
		return holds(t.Elem(), seen)
	case reflect.Struct:
		for f := range t.Fields() {
			if holds(f.Type, seen) {
				return true
			}
		}
	}
	return false
}

// follow resolves the type and value that a container decodes into the way
// encoding/json's indirect does: through pointers, and through an interface
// that holds a non-nil pointer. Any other interface, and a type the scanner
// has no type for, is opaque. rv is invalid when the value is not known.
// cycle is the interface it stopped at because it holds a pointer to itself.
func follow(t reflect.Type, rv reflect.Value) (_ reflect.Type, _ reflect.Value, cycle reflect.Value) {
	for t != nil {
		switch t.Kind() {
		case reflect.Pointer:
			if rv.IsValid() && !rv.IsNil() {
				// Like encoding/json's indirect, stop at an interface
				// pointing to itself (var v any; v = &v). JSON replaces
				// that interface with a generic value instead of following
				// the pointer forever.
				if e := rv.Elem(); e.Kind() == reflect.Interface && e.Elem().Equal(rv) {
					return nil, reflect.Value{}, e
				}
				rv = rv.Elem()
			} else {
				rv = reflect.Value{}
			}
			t = t.Elem()
		case reflect.Interface:
			if rv.IsValid() && !rv.IsNil() {
				if e := rv.Elem(); e.Kind() == reflect.Pointer && !e.IsNil() {
					rv, t = e, e.Type()
					continue
				}
			}
			return nil, reflect.Value{}, reflect.Value{}
		default:
			return t, rv, reflect.Value{}
		}
	}
	return nil, reflect.Value{}, reflect.Value{}
}

// fieldValue returns the field of struct value rv at index, through embedded
// pointers, or an invalid value if one of them is nil.
func fieldValue(rv reflect.Value, index []int) reflect.Value {
	for _, i := range index {
		for rv.IsValid() && rv.Kind() == reflect.Pointer {
			if rv.IsNil() {
				return reflect.Value{}
			}
			rv = rv.Elem()
		}
		if !rv.IsValid() {
			return rv
		}
		rv = rv.Field(i)
	}
	return rv
}
