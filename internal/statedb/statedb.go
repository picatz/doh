// Package statedb keeps the state a doh server needs to outlive its
// process in a SQLite database, state.db in its data directory: browser
// sessions, setup links, DPoP replay caches, what alerts remember, and the
// audit trail.
//
// Each kind of state is behind a small interface its own package defines
// ([signin.Sessions], [alerts.Memory], [dpop.ReplayCache], [audit.Store],
// and setup links' methods here), so a networked backend could take its
// place for replicas. This one is for a single server: one writer
// connection, so writes are serialized and never contend, and a pool of
// read-only connections, which WAL mode lets read while it writes.
//
// The schema is versioned with PRAGMA user_version and changed only by
// appending migrations, embedded from migrations/, each applied in its own
// transaction. Before migrating a database that has data, [Open] keeps a
// copy of it beside it. A database from a newer doh is refused, rather than
// misread.
//
// Nothing secret is stored: sessions, setup links, and proofs are kept by
// the SHA-256 of their identifiers. The file is readable only by its owner
// (0600). Every table is bounded, by count or by expiry, and [DB.Sweep]
// removes what's expired.
//
// [signin.Sessions]: https://pkg.go.dev/github.com/picatz/doh/internal/signin#Sessions
// [alerts.Memory]: https://pkg.go.dev/github.com/picatz/doh/internal/alerts#Memory
// [dpop.ReplayCache]: https://pkg.go.dev/github.com/picatz/jose/pkg/dpop#ReplayCache
// [audit.Store]: https://pkg.go.dev/github.com/picatz/doh/internal/audit#Store
package statedb

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite" // the "sqlite" database/sql driver, in pure Go
)

// FileName is the database's name in the data directory.
const FileName = "state.db"

// busyTimeout is how long a connection waits for a lock another holds,
// such as a checkpoint, before failing.
const busyTimeout = 5 * time.Second

// readConns bounds the read-only connections.
const readConns = 4

//go:embed migrations/*.sql
var migrationFiles embed.FS

// migrations returns the embedded migrations, in order.
func migrations() ([]string, error) {
	return loadMigrations(migrationFiles, "migrations")
}

// loadMigrations reads the .sql files in dir of fsys, in name order,
// which must be 0001_..., 0002_..., and so on, without gaps.
func loadMigrations(fsys fs.FS, dir string) ([]string, error) {
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		if want := fmt.Sprintf("%04d_", len(out)+1); !strings.HasPrefix(e.Name(), want) {
			return nil, fmt.Errorf("statedb: migration %s is out of order: want a name starting %s", e.Name(), want)
		}
		b, err := fs.ReadFile(fsys, path.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		out = append(out, string(b))
	}
	return out, nil
}

// DB is a state database. It's safe for concurrent use.
type DB struct {
	path string
	w    *sql.DB // the one writer connection
	r    *sql.DB // read-only connections

	replayMu sync.Mutex
	replays  map[string]*ReplayCache

	// Statements are prepared once, on each pool: parsing SQL costs more
	// than running these.
	stmtMu sync.Mutex
	stmts  map[stmtKey]*sql.Stmt
}

type stmtKey struct {
	write bool
	query string
}

// maxStmts bounds the prepared statements kept: far more than the
// queries this package has, including each shape of audit filter.
const maxStmts = 256

// cached returns query, if it's been prepared on the writer, or the
// readers.
func (db *DB) cached(write bool, query string) (*sql.Stmt, bool) {
	db.stmtMu.Lock()
	defer db.stmtMu.Unlock()
	st, ok := db.stmts[stmtKey{write, query}]
	return st, ok
}

// prepared returns query prepared on the writer, or the readers. It must
// not be called for the writer within a write transaction, which holds
// the writer's one connection: preparing waits for it.
func (db *DB) prepared(ctx context.Context, write bool, query string) (*sql.Stmt, error) {
	if st, ok := db.cached(write, query); ok {
		return st, nil
	}
	pool := db.r
	if write {
		pool = db.w
	}
	st, err := pool.PrepareContext(ctx, query)
	if err != nil {
		return nil, err
	}
	k := stmtKey{write, query}
	db.stmtMu.Lock()
	defer db.stmtMu.Unlock()
	if prev, ok := db.stmts[k]; ok {
		st.Close() // prepared concurrently
		return prev, nil
	}
	if len(db.stmts) < maxStmts {
		db.stmts[k] = st
	}
	return st, nil
}

// readRow runs a query that returns at most one row on a read connection.
func (db *DB) readRow(ctx context.Context, query string, args ...any) *sql.Row {
	st, err := db.prepared(ctx, false, query)
	if err != nil {
		return db.r.QueryRowContext(ctx, query, args...) // fails the same way, reporting it
	}
	return st.QueryRowContext(ctx, args...)
}

// readRows runs a query on a read connection.
func (db *DB) readRows(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	st, err := db.prepared(ctx, false, query)
	if err != nil {
		return nil, err
	}
	return st.QueryContext(ctx, args...)
}

// exec runs one statement on the writer, as its own transaction.
func (db *DB) exec(ctx context.Context, query string, args ...any) (sql.Result, error) {
	st, err := db.prepared(ctx, true, query)
	if err != nil {
		return nil, err
	}
	return st.ExecContext(ctx, args...)
}

// wtx is a write transaction. Statements it runs that aren't prepared
// yet are run as they are, and prepared once it's done.
type wtx struct {
	ctx        context.Context
	db         *DB
	tx         *sql.Tx
	unprepared *[]string
}

// exec runs a statement in the transaction.
func (t wtx) exec(query string, args ...any) (sql.Result, error) {
	if st, ok := t.db.cached(true, query); ok {
		return t.tx.StmtContext(t.ctx, st).ExecContext(t.ctx, args...)
	}
	*t.unprepared = append(*t.unprepared, query)
	return t.tx.ExecContext(t.ctx, query, args...)
}

// row runs a query that returns at most one row in the transaction.
func (t wtx) row(query string, args ...any) *sql.Row {
	if st, ok := t.db.cached(true, query); ok {
		return t.tx.StmtContext(t.ctx, st).QueryRowContext(t.ctx, args...)
	}
	*t.unprepared = append(*t.unprepared, query)
	return t.tx.QueryRowContext(t.ctx, query, args...)
}

// Open opens the state database at path, creating it, readable only by
// its owner, if it doesn't exist, and migrating it to the current schema.
func Open(ctx context.Context, path string) (*DB, error) {
	ms, err := migrations()
	if err != nil {
		return nil, err
	}
	return open(ctx, path, ms)
}

func open(ctx context.Context, path string, ms []string) (*DB, error) {
	if path == "" {
		return nil, errors.New("statedb: no path")
	}
	if err := prepareFile(path); err != nil {
		return nil, err
	}

	w, err := sql.Open("sqlite", dsn(path, false))
	if err != nil {
		return nil, fmt.Errorf("statedb: %w", err)
	}
	w.SetMaxOpenConns(1)
	w.SetMaxIdleConns(1)
	w.SetConnMaxLifetime(0)
	w.SetConnMaxIdleTime(0)

	db := &DB{path: path, w: w, replays: make(map[string]*ReplayCache), stmts: make(map[stmtKey]*sql.Stmt)}
	if err := db.migrate(ctx, ms); err != nil {
		w.Close()
		return nil, err
	}

	r, err := sql.Open("sqlite", dsn(path, true))
	if err != nil {
		w.Close()
		return nil, fmt.Errorf("statedb: %w", err)
	}
	r.SetMaxOpenConns(readConns)
	r.SetMaxIdleConns(readConns)
	db.r = r
	if err := r.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("statedb: %w", err)
	}
	return db, nil
}

// prepareFile creates path, readable only by its owner, if it doesn't
// exist, and makes an existing one so, before SQLite opens it: SQLite
// gives its journal files the database's permissions.
func prepareFile(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("statedb: %w", err)
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return fmt.Errorf("statedb: %w", err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return fmt.Errorf("statedb: %w", err)
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("statedb: %s isn't a regular file", path)
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm()&0o077 != 0 {
		if err := f.Chmod(0o600); err != nil {
			return fmt.Errorf("statedb: %w", err)
		}
	}
	return nil
}

// dsn returns the driver's data source name for path: WAL mode, so reads
// don't wait for writes; synchronous=NORMAL, durable at each checkpoint
// and never corrupt; foreign keys enforced; and a busy timeout. Writers
// take the write lock when they begin (BEGIN IMMEDIATE), so a transaction
// never fails partway for want of it.
func dsn(path string, readOnly bool) string {
	q := url.Values{}
	q.Add("_pragma", fmt.Sprintf("busy_timeout(%d)", busyTimeout.Milliseconds()))
	q.Add("_pragma", "foreign_keys(1)")
	if readOnly {
		q.Add("_pragma", "query_only(1)")
	} else {
		q.Add("_pragma", "journal_mode(WAL)")
		q.Add("_pragma", "synchronous(NORMAL)")
		q.Set("_txlock", "immediate")
	}
	u := url.URL{Scheme: "file", Path: filepath.ToSlash(path), RawQuery: q.Encode()}
	if filepath.IsAbs(path) && !strings.HasPrefix(u.Path, "/") {
		u.Path = "/" + u.Path // a Windows drive letter
	}
	return u.String()
}

// Version returns the database's schema version.
func (db *DB) Version(ctx context.Context) (int, error) {
	var v int
	err := db.r.QueryRowContext(ctx, "PRAGMA user_version").Scan(&v)
	return v, err
}

// BackupSuffix is appended, with the schema version it had, to the name
// of the copy [Open] keeps of a database before migrating it, such as
// state.db.v1.bak.
const BackupSuffix = ".bak"

// migrate applies the migrations the database doesn't have yet, each in
// its own transaction with the version it brings, after keeping a copy of
// a database that has any.
func (db *DB) migrate(ctx context.Context, ms []string) error {
	var version int
	if err := db.w.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return fmt.Errorf("statedb: reading the schema version: %w", err)
	}
	switch {
	case version > len(ms):
		return fmt.Errorf("statedb: %s has schema version %d, from a newer doh than this one (which knows %d); upgrade doh, or move the file aside", db.path, version, len(ms))
	case version == len(ms):
		return nil
	case version > 0:
		backup := fmt.Sprintf("%s.v%d%s", db.path, version, BackupSuffix)
		if _, err := os.Stat(backup); err == nil {
			backup = fmt.Sprintf("%s.v%d.%d%s", db.path, version, time.Now().Unix(), BackupSuffix)
		}
		if _, err := db.w.ExecContext(ctx, "VACUUM INTO ?", backup); err != nil {
			return fmt.Errorf("statedb: keeping a copy before migrating: %w", err)
		}
		if runtime.GOOS != "windows" {
			if err := os.Chmod(backup, 0o600); err != nil {
				return fmt.Errorf("statedb: %w", err)
			}
		}
	}
	for i := version; i < len(ms); i++ {
		if err := db.apply(ctx, i+1, ms[i]); err != nil {
			return err
		}
	}
	return nil
}

// apply runs migration to version n in one transaction.
func (db *DB) apply(ctx context.Context, n int, migration string) error {
	tx, err := db.w.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("statedb: migrating to version %d: %w", n, err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, migration); err != nil {
		return fmt.Errorf("statedb: migrating to version %d: %w", n, err)
	}
	// PRAGMA takes no parameters; n is an integer this package chose.
	if _, err := tx.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version = %d", n)); err != nil {
		return fmt.Errorf("statedb: migrating to version %d: %w", n, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("statedb: migrating to version %d: %w", n, err)
	}
	return nil
}

// Close closes the database.
func (db *DB) Close() error {
	var errs []error
	db.stmtMu.Lock()
	for _, st := range db.stmts {
		errs = append(errs, st.Close())
	}
	clear(db.stmts)
	db.stmtMu.Unlock()
	if db.r != nil {
		errs = append(errs, db.r.Close())
	}
	errs = append(errs, db.w.Close())
	return errors.Join(errs...)
}

// write runs fn in a write transaction, committing if it returns nil.
func (db *DB) write(ctx context.Context, fn func(wtx) error) error {
	tx, err := db.w.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("statedb: %w", err)
	}
	var unprepared []string
	defer func() {
		_ = tx.Rollback() // after Commit, does nothing
		// The connection is free again; prepare what wasn't, for next
		// time. Failing to only costs a parse.
		for _, q := range unprepared {
			_, _ = db.prepared(ctx, true, q)
		}
	}()
	if err := fn(wtx{ctx, db, tx, &unprepared}); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("statedb: %w", err)
	}
	return nil
}

// SweepOptions say what [DB.Sweep] keeps.
type SweepOptions struct {
	// AuditRetention is how long audit events are kept. Zero keeps them
	// forever.
	AuditRetention time.Duration

	// AlertWindow is how long alerts are remembered as sent.
	AlertWindow time.Duration
}

// Sweep removes what has expired by now: sessions past their lifetime,
// setup links, DPoP proofs, alerts remembered as sent longer than
// opts.AlertWindow ago, and audit events older than opts.AuditRetention.
// Sessions idle too long are removed when sessions start, since only the
// sign-in service knows its idle timeout.
func (db *DB) Sweep(ctx context.Context, now time.Time, opts SweepOptions) error {
	n := now.UnixNano()
	stmts := []struct {
		query string
		arg   int64
	}{
		{"DELETE FROM sessions WHERE expires <= ?", n},
		{"DELETE FROM setup_links WHERE expires <= ?", n},
		{"DELETE FROM dpop_proofs WHERE expires <= ?", n},
	}
	if opts.AlertWindow > 0 {
		stmts = append(stmts, struct {
			query string
			arg   int64
		}{"DELETE FROM alert_sent WHERE sent <= ?", now.Add(-opts.AlertWindow).UnixNano()})
	}
	if opts.AuditRetention > 0 {
		stmts = append(stmts, struct {
			query string
			arg   int64
		}{"DELETE FROM audit WHERE time < ?", now.Add(-opts.AuditRetention).UnixNano()})
	}
	err := db.write(ctx, func(tx wtx) error {
		for _, st := range stmts {
			if _, err := tx.exec(st.query, st.arg); err != nil {
				return fmt.Errorf("statedb: sweeping: %w", err)
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	// The replay caches count what they hold; they recount after a sweep.
	db.replayMu.Lock()
	caches := slices.Collect(func(yield func(*ReplayCache) bool) {
		for _, c := range db.replays {
			if !yield(c) {
				return
			}
		}
	})
	db.replayMu.Unlock()
	for _, c := range caches {
		if err := c.recount(ctx); err != nil {
			return err
		}
	}
	return nil
}

// nanos returns t as Unix nanoseconds, how times are stored.
func nanos(t time.Time) int64 { return t.UnixNano() }

// fromNanos returns the time n Unix nanoseconds name, or the zero time for
// 0.
func fromNanos(n int64) time.Time {
	if n == 0 {
		return time.Time{}
	}
	return time.Unix(0, n)
}
