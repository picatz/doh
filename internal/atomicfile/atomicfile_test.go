package atomicfile

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestWriteFile(t *testing.T) {
	name := filepath.Join(t.TempDir(), "nested", "state.json")
	for _, data := range []string{"first", "second, longer than the first"} {
		if err := WriteFile(name, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(name)
		if err != nil || string(got) != data {
			t.Fatalf("read back %q, %v; want %q", got, err, data)
		}
	}

	if runtime.GOOS != "windows" {
		fi, err := os.Stat(name)
		if err != nil || fi.Mode().Perm() != 0o600 {
			t.Errorf("mode = %v, %v; want 0600", fi.Mode().Perm(), err)
		}
		di, err := os.Stat(filepath.Dir(name))
		if err != nil || di.Mode().Perm() != 0o700 {
			t.Errorf("directory mode = %v, %v; want 0700", di.Mode().Perm(), err)
		}
	}

	// No temporary files are left behind.
	entries, _ := os.ReadDir(filepath.Dir(name))
	if len(entries) != 1 {
		t.Errorf("directory holds %d entries, want only the file", len(entries))
	}
}

func TestWriteFile_FailureLeavesOriginal(t *testing.T) {
	dir := t.TempDir()
	name := filepath.Join(dir, "state.json")
	if err := WriteFile(name, []byte("kept"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Renaming over a directory fails, after the temporary file is written.
	target := filepath.Join(dir, "is-a-dir")
	if err := os.MkdirAll(filepath.Join(target, "child"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := WriteFile(target, []byte("lost"), 0o600); err == nil {
		t.Fatal("writing over a non-empty directory succeeded")
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 2 {
		t.Errorf("a failed write left %d entries, want the original two", len(entries))
	}
	if got, _ := os.ReadFile(name); string(got) != "kept" {
		t.Errorf("unrelated file = %q", got)
	}
}
