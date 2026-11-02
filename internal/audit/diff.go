package audit

import (
	"encoding/json/v2"
	"fmt"
	"maps"
	"slices"
	"strings"
)

// Diff describes how after differs from before, both of which marshal to
// JSON, as details for an [Event]: for lists of strings, such as a
// profile's allow list, what was added and removed ("allow.added":
// "example.com"); for lists of objects, which were added, removed, or
// changed, by their "id", "name", or "domain"; and for anything else, its
// new value ("security.bypass": "false"). Paths are dotted JSON member
// names. It's for describing changes, so it's best effort: values that
// can't be marshaled are described as "changed".
func Diff(before, after any) map[string]string {
	a, errA := toJSONValue(before)
	b, errB := toJSONValue(after)
	if errA != nil || errB != nil {
		return map[string]string{"": "changed"}
	}
	out := make(map[string]string)
	diffValue("", a, b, out)
	return out
}

func toJSONValue(v any) (any, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var out any
	return out, json.Unmarshal(b, &out)
}

func diffValue(path string, a, b any, out map[string]string) {
	am, aIsMap := a.(map[string]any)
	bm, bIsMap := b.(map[string]any)
	if (aIsMap || a == nil) && (bIsMap || b == nil) && (aIsMap || bIsMap) {
		keys := slices.Sorted(maps.Keys(am))
		for k := range bm {
			if _, ok := am[k]; !ok {
				keys = append(keys, k)
			}
		}
		slices.Sort(keys)
		for _, k := range keys {
			diffValue(join(path, k), am[k], bm[k], out)
		}
		return
	}

	al, aIsList := a.([]any)
	bl, bIsList := b.([]any)
	if (aIsList || a == nil) && (bIsList || b == nil) && (aIsList || bIsList) {
		diffList(path, al, bl, out)
		return
	}

	if !equal(a, b) {
		out[path] = render(b)
	}
}

// diffList describes how list b differs from a, by element identity.
func diffList(path string, a, b []any, out map[string]string) {
	ai, bi := identities(a), identities(b)
	var added, removed, changed []string
	for _, id := range bi.order {
		before, ok := ai.byID[id]
		switch {
		case !ok:
			added = append(added, id)
		case !equal(before, bi.byID[id]):
			changed = append(changed, id)
		}
	}
	for _, id := range ai.order {
		if _, ok := bi.byID[id]; !ok {
			removed = append(removed, id)
		}
	}
	if len(added) > 0 {
		out[join(path, "added")] = strings.Join(added, ", ")
	}
	if len(removed) > 0 {
		out[join(path, "removed")] = strings.Join(removed, ", ")
	}
	if len(changed) > 0 {
		out[join(path, "changed")] = strings.Join(changed, ", ")
	}
}

type identified struct {
	order []string
	byID  map[string]any
}

// identities names each element of l: a string by itself, an object by its
// id, name, or domain, and anything else by its JSON.
func identities(l []any) identified {
	ids := identified{byID: make(map[string]any, len(l))}
	for _, v := range l {
		id := identity(v)
		if _, dup := ids.byID[id]; dup {
			continue
		}
		ids.order = append(ids.order, id)
		ids.byID[id] = v
	}
	return ids
}

func identity(v any) string {
	switch v := v.(type) {
	case string:
		return v
	case map[string]any:
		for _, k := range []string{"id", "name", "domain"} {
			if s, ok := v[k].(string); ok && s != "" {
				return s
			}
		}
	}
	return render(v)
}

func equal(a, b any) bool {
	ja, _ := json.Marshal(a, json.Deterministic(true))
	jb, _ := json.Marshal(b, json.Deterministic(true))
	return string(ja) == string(jb)
}

// render describes a JSON value briefly: strings as themselves, nothing as
// "", and anything else as compact JSON.
func render(v any) string {
	switch v := v.(type) {
	case nil:
		return ""
	case string:
		return v
	case bool, float64:
		return fmt.Sprint(v)
	}
	b, err := json.Marshal(v, json.Deterministic(true))
	if err != nil {
		return "changed"
	}
	return string(b)
}

func join(path, k string) string {
	if path == "" {
		return k
	}
	return path + "." + k
}
