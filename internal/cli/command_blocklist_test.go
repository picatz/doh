package cli_test

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/picatz/doh/internal/blocklist"
)

func TestCommand_BlocklistCheck(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())

	list := filepath.Join(t.TempDir(), "list.txt")
	if err := os.WriteFile(list, []byte("||ads.example.com^\n@@||ok.ads.example.com^\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	output := testCommand(t, "blocklist", "check", "x.ads.example.com", "ok.ads.example.com", "example.com", "--blocklist", "test="+list)

	type result struct {
		Name    string `json:"name"`
		Blocked bool   `json:"blocked"`
		Rule    *struct {
			Domain string `json:"domain"`
			Allow  bool   `json:"allow"`
		} `json:"rule"`
		Source string `json:"source"`
	}

	var results []result
	dec := json.NewDecoder(output)
	for dec.More() {
		var r result
		if err := dec.Decode(&r); err != nil {
			t.Fatal(err)
		}
		results = append(results, r)
	}

	if len(results) != 3 {
		t.Fatalf("got %d results, want 3", len(results))
	}

	if r := results[0]; !r.Blocked || r.Rule == nil || r.Rule.Domain != "ads.example.com" || r.Source != "test" {
		t.Errorf("got %+v, want blocked by ads.example.com from test", r)
	}
	if r := results[1]; r.Blocked || r.Rule == nil || !r.Rule.Allow {
		t.Errorf("got %+v, want allowed by an exception", r)
	}
	if r := results[2]; r.Blocked || r.Rule != nil {
		t.Errorf("got %+v, want no matching rule", r)
	}
}

func TestCommand_BlocklistPresets(t *testing.T) {
	out, err := io.ReadAll(testCommand(t, "blocklist", "presets"))
	if err != nil {
		t.Fatal(err)
	}
	b := string(out)

	for _, name := range blocklist.PresetNames() {
		if !strings.Contains(b, name) {
			t.Errorf("presets missing %s:\n%s", name, b)
		}
	}
	if !strings.Contains(b, blocklist.DefaultPreset+" (default)") {
		t.Errorf("presets don't mark the default:\n%s", b)
	}
}
