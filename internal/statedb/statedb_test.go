package statedb

import (
	"database/sql"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"testing/fstest"
	"time"
)

// openTest opens a database in a new directory, closing it when the test
// ends.
func openTest(t testing.TB) (*DB, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), FileName)
	db, err := Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db, path
}

func TestOpen_CreatesPrivateDatabaseInWALMode(t *testing.T) {
	db, path := openTest(t)

	if runtime.GOOS != "windows" {
		fi, err := os.Stat(path)
		if err != nil || fi.Mode().Perm() != 0o600 {
			t.Errorf("state.db: mode %v, %v; want 0600", fi.Mode().Perm(), err)
		}
	}
	var mode string
	if err := db.r.QueryRowContext(t.Context(), "PRAGMA journal_mode").Scan(&mode); err != nil || mode != "wal" {
		t.Errorf("journal mode = %q, %v; want wal", mode, err)
	}
	for _, conn := range []*sql.DB{db.w, db.r} {
		var fk int
		if err := conn.QueryRowContext(t.Context(), "PRAGMA foreign_keys").Scan(&fk); err != nil || fk != 1 {
			t.Errorf("foreign keys = %d, %v; want on", fk, err)
		}
	}
	ms, _ := migrations()
	if v, err := db.Version(t.Context()); err != nil || v != len(ms) {
		t.Errorf("version = %d, %v; want %d", v, err, len(ms))
	}

	// Reads can't write, even by mistake.
	if _, err := db.r.ExecContext(t.Context(), "DELETE FROM sessions"); err == nil {
		t.Error("a read connection wrote")
	}
}

func TestOpen_TightensPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no Unix permissions")
	}
	path := filepath.Join(t.TempDir(), FileName)
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	db, err := Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Errorf("mode = %v, want 0600", fi.Mode().Perm())
	}
}

func TestOpen_RefusesNewerSchema(t *testing.T) {
	db, path := openTest(t)
	if _, err := db.w.ExecContext(t.Context(), "PRAGMA user_version = 99"); err != nil {
		t.Fatal(err)
	}
	db.Close()
	_, err := Open(t.Context(), path)
	if err == nil || !strings.Contains(err.Error(), "newer doh") {
		t.Fatalf("opening a newer schema: %v", err)
	}
}

func TestOpen_RefusesWhatIsNotADatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), FileName)
	if err := os.WriteFile(path, []byte(strings.Repeat("not a database ", 100)), 0o600); err != nil {
		t.Fatal(err)
	}
	if db, err := Open(t.Context(), path); err == nil {
		db.Close()
		t.Fatal("opened a file that isn't a database")
	}
	if b, _ := os.ReadFile(path); !strings.HasPrefix(string(b), "not a database") {
		t.Error("the file was changed")
	}
}

// The upgrade path: a database at an older schema, with data, is migrated
// in place, keeping its data and a copy of it as it was.
func TestOpen_MigratesKeepingDataAndABackup(t *testing.T) {
	ms, err := migrations()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), FileName)
	old, err := open(t.Context(), path, ms)
	if err != nil {
		t.Fatal(err)
	}
	links := old.SetupLinks()
	now := time.Now()
	if err := links.Create(t.Context(), [32]byte{1}, SetupLink{Profile: "kids", Expires: now.Add(time.Hour)}, now, 10); err != nil {
		t.Fatal(err)
	}
	old.Close()

	next := append(ms[:len(ms):len(ms)], "ALTER TABLE setup_links ADD COLUMN note TEXT NOT NULL DEFAULT '';")
	db, err := open(t.Context(), path, next)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if v, _ := db.Version(t.Context()); v != len(next) {
		t.Errorf("version = %d, want %d", v, len(next))
	}
	if link, ok, err := db.SetupLinks().Lookup(t.Context(), [32]byte{1}, now); err != nil || !ok || link.Profile != "kids" {
		t.Errorf("after migrating, link = %+v, %v, %v", link, ok, err)
	}

	backup := path + ".v" + strconv.Itoa(len(ms)) + BackupSuffix
	if runtime.GOOS != "windows" {
		if fi, err := os.Stat(backup); err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("backup: %v; want one readable only by its owner", err)
		}
	}
	b, err := open(t.Context(), backup, ms)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if link, ok, _ := b.SetupLinks().Lookup(t.Context(), [32]byte{1}, now); !ok || link.Profile != "kids" {
		t.Error("the backup doesn't have the data")
	}
}

func TestOpen_FailedMigrationChangesNothing(t *testing.T) {
	ms, _ := migrations()
	path := filepath.Join(t.TempDir(), FileName)
	db, err := open(t.Context(), path, ms)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if err := db.SetupLinks().Create(t.Context(), [32]byte{2}, SetupLink{Profile: "home", Expires: now.Add(time.Hour)}, now, 10); err != nil {
		t.Fatal(err)
	}
	db.Close()

	broken := append(ms[:len(ms):len(ms)], "CREATE TABLE half (x INTEGER); THIS IS NOT SQL;")
	if db, err := open(t.Context(), path, broken); err == nil {
		db.Close()
		t.Fatal("a broken migration succeeded")
	}
	db, err = open(t.Context(), path, ms)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if v, _ := db.Version(t.Context()); v != len(ms) {
		t.Errorf("version after a failed migration = %d, want %d", v, len(ms))
	}
	var n int
	if err := db.r.QueryRowContext(t.Context(), "SELECT count(*) FROM sqlite_schema WHERE name = 'half'").Scan(&n); err != nil || n != 0 {
		t.Errorf("a failed migration left part of itself: %d, %v", n, err)
	}
	if _, ok, _ := db.SetupLinks().Lookup(t.Context(), [32]byte{2}, now); !ok {
		t.Error("a failed migration lost data")
	}
}

func TestLoadMigrations_InOrderWithoutGaps(t *testing.T) {
	for name, files := range map[string][]string{
		"gap":        {"0001_a.sql", "0003_c.sql"},
		"unnumbered": {"init.sql"},
		"duplicate":  {"0001_a.sql", "0001_b.sql"},
	} {
		fsys := fstest.MapFS{}
		for _, f := range files {
			fsys["m/"+f] = &fstest.MapFile{Data: []byte("SELECT 1;")}
		}
		if _, err := loadMigrations(fsys, "m"); err == nil {
			t.Errorf("%s: loaded", name)
		}
	}
	ms, err := migrations()
	if err != nil || len(ms) == 0 {
		t.Fatalf("embedded migrations: %d, %v", len(ms), err)
	}
}

func TestSweep_RemovesWhatExpired(t *testing.T) {
	db, _ := openTest(t)
	ctx := t.Context()
	now := time.Now()
	links := db.SetupLinks()
	_ = links.Create(ctx, [32]byte{1}, SetupLink{Profile: "a", Expires: now.Add(time.Minute)}, now, 10)
	_ = links.Create(ctx, [32]byte{2}, SetupLink{Profile: "b", Expires: now.Add(time.Hour)}, now, 10)
	if err := db.Sweep(ctx, now.Add(30*time.Minute), SweepOptions{}); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := db.r.QueryRowContext(ctx, "SELECT count(*) FROM setup_links").Scan(&n); err != nil || n != 1 {
		t.Errorf("%d links after a sweep, want 1", n)
	}
}
