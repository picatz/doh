package blocklist

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRegistry(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) Source {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return Source{Name: name, Location: path}
	}
	a := write("a", "||ads.example^\n")
	b := write("b", "||tracker.example^\n")
	missing := Source{Name: "missing", Location: filepath.Join(dir, "nope")}

	r := NewRegistry(&Loader{}, nil)
	defer r.Close()
	var failed []string
	r.OnFailure(func(src Source, err error) { failed = append(failed, src.Name) }) // called with r.mu held, so serialized

	r.Sync([]Source{a, b, missing})
	if err := r.Wait(t.Context(), a, b, missing); err != nil {
		t.Fatal(err)
	}
	r.mu.Lock()
	if len(failed) != 1 || failed[0] != "missing" {
		t.Errorf("OnFailure saw %q, want only the missing list", failed)
	}
	r.mu.Unlock()

	if _, ok := r.List(a).Block("x.ads.example"); !ok {
		t.Error("list a not loaded")
	}
	if r.List(missing) != nil || r.Err(missing) == nil {
		t.Error("a missing list should fail to load, with its error kept")
	}

	status := r.Status()
	if len(status) != 3 || status[0].Name != "a" || status[0].Rules != 1 || status[1].Name != "b" || status[2].Error == "" {
		t.Errorf("Status() = %+v", status)
	}

	// Reloading picks up changes, and failures keep the current rules.
	write("a", "||other.example^\n")
	if err := os.Remove(b.Location); err != nil {
		t.Fatal(err)
	}
	if err := r.Reload(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, ok := r.List(a).Block("other.example"); !ok {
		t.Error("reload didn't pick up the new rules")
	}
	if _, ok := r.List(b).Block("tracker.example"); !ok {
		t.Error("a failed reload dropped the current rules")
	}

	// Syncing forgets lists no longer used.
	r.Sync([]Source{a})
	if r.List(b) != nil || len(r.Status()) != 1 {
		t.Errorf("unused list kept: %+v", r.Status())
	}
}

func TestList_ExceptionAndBlock(t *testing.T) {
	var b Builder
	if _, err := b.Add("test", strings.NewReader("||ads.example^\n@@||ok.ads.example^\n")); err != nil {
		t.Fatal(err)
	}
	l := b.List()

	if v, ok := l.Block("OK.ads.example."); !ok || v.Rule.Domain != "ads.example" || v.Source != "test" {
		t.Errorf("Block = %+v, %v", v, ok)
	}
	if v, ok := l.Exception("ok.ads.example"); !ok || !v.Rule.Allow {
		t.Errorf("Exception = %+v, %v", v, ok)
	}
	if _, ok := l.Exception("x.ads.example"); ok {
		t.Error("Exception matched a name without one")
	}

	var nilList *List
	if _, ok := nilList.Block("x"); ok {
		t.Error("nil list blocked")
	}
}
