// Package atomicfile writes files so readers see either the old contents
// or the new, never a mix, even if the writer crashes partway.
package atomicfile

import (
	"os"
	"path/filepath"
)

// WriteFile writes data to name with permissions perm, creating its
// directory (readable only by its owner) if needed.
//
// It writes a temporary file in the same directory, syncs it to disk, and
// renames it over name, which replaces a file atomically on the same file
// system. On error, name is unchanged and the temporary file is removed.
func WriteFile(name string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(name)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}

	f, err := os.CreateTemp(dir, "."+filepath.Base(name)+".*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()

	err = f.Chmod(perm)
	if err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, name)
	}
	if err != nil {
		_ = os.Remove(tmp)
	}
	return err
}
