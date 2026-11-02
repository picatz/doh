package webui

import (
	"regexp"
	"slices"
	"testing"

	"github.com/picatz/doh/internal/blocklist"
	"github.com/picatz/doh/internal/filter"
)

// TestPresets_NameRealLists checks that every list the UI's protection
// presets turn on is one of the server's preset lists, so renaming a list
// can't quietly empty a preset.
func TestPresets_NameRealLists(t *testing.T) {
	js := readStatic(t, "presets.js")
	known := blocklist.PresetNames()
	var names []string
	for _, block := range regexp.MustCompile(`lists: \[([^\]]*)\]`).FindAllStringSubmatch(js, -1) {
		for _, m := range regexp.MustCompile(`"([a-z0-9-]+)"`).FindAllStringSubmatch(block[1], -1) {
			names = append(names, m[1])
		}
	}
	if len(names) < 4 {
		t.Fatalf("found only %v in presets.js", names)
	}
	for _, name := range names {
		if !slices.Contains(known, name) {
			t.Errorf("presets.js turns on %q, which isn't a preset list (%v)", name, known)
		}
	}
}

// TestPresets_NameRealFeatures checks that every protection the presets
// manage is one of the server's features, and that Safe Browsing, which
// needs the operator's API key, is never one of them.
func TestPresets_NameRealFeatures(t *testing.T) {
	js := readStatic(t, "presets.js")
	m := regexp.MustCompile(`export const FEATURES = \[([^\]]*)\]`).FindStringSubmatch(js)
	if m == nil {
		t.Fatal("presets.js has no FEATURES")
	}
	var known []string
	for _, f := range filter.Features() {
		known = append(known, f.ID)
	}
	var names []string
	for _, n := range regexp.MustCompile(`"([a-z_]+)"`).FindAllStringSubmatch(m[1], -1) {
		names = append(names, n[1])
	}
	for _, want := range []string{"typosquatting", "dga"} {
		if !slices.Contains(names, want) {
			t.Errorf("presets don't manage %s", want)
		}
	}
	for _, name := range names {
		if !slices.Contains(known, name) {
			t.Errorf("presets.js manages %q, which isn't a feature (%v)", name, known)
		}
		if name == "safe_browsing" || name == "safe_search" {
			t.Errorf("presets.js manages %q among the security features", name)
		}
	}
}
