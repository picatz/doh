package webui

import (
	"regexp"
	"slices"
	"testing"

	"github.com/picatz/doh/internal/blocklist"
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
