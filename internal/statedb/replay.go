package statedb

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"sync"
	"time"
)

// ErrReplayCacheFull is returned by a [ReplayCache] that holds its maximum
// number of unexpired proof IDs. Refusing then, rather than forgetting
// one, keeps a flood of fresh proofs from making room to replay an old
// one.
var ErrReplayCacheFull = errors.New("statedb: replay cache full")

// ReplayCache is a DPoP replay cache ([dpop.ReplayCache]) kept in the
// database, so a proof accepted once is refused after a restart too. It
// keeps at most max unexpired proof IDs, by their SHA-256, and refuses new
// ones beyond that, as the jose module's memory cache does.
//
// [dpop.ReplayCache]: https://pkg.go.dev/github.com/picatz/jose/pkg/dpop#ReplayCache
type ReplayCache struct {
	db   *DB
	name string
	max  int
	now  func() time.Time

	mu sync.Mutex
	// count is how many proofs the cache holds, expired or not, as of its
	// last write; earliest is a lower bound on when any of them expires,
	// so a full cache refuses without looking until one might have.
	count    int
	earliest time.Time
}

// ReplayCache returns the replay cache named name, holding at most max
// unexpired proof IDs (limit). Caches of different names never see each other's
// proofs. now may be nil, for [time.Now]. The same name always returns the
// same cache.
func (db *DB) ReplayCache(ctx context.Context, name string, limit int, now func() time.Time) (*ReplayCache, error) {
	db.replayMu.Lock()
	defer db.replayMu.Unlock()
	if c, ok := db.replays[name]; ok {
		return c, nil
	}
	if now == nil {
		now = time.Now
	}
	c := &ReplayCache{db: db, name: name, max: max(1, limit), now: now}
	if err := c.recount(ctx); err != nil {
		return nil, err
	}
	db.replays[name] = c
	return c, nil
}

// recount counts what the cache holds, and when the earliest expires.
func (c *ReplayCache) recount(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.recountLocked(func(query string, args ...any) *sql.Row { return c.db.w.QueryRowContext(ctx, query, args...) })
}

// recountLocked counts what the cache holds with row. c.mu must be held.
func (c *ReplayCache) recountLocked(row func(query string, args ...any) *sql.Row) error {
	var (
		n        int
		earliest sql.NullInt64
	)
	if err := row(`SELECT count(*), min(expires) FROM dpop_proofs WHERE cache = ?`, c.name).Scan(&n, &earliest); err != nil {
		return fmt.Errorf("statedb: counting proofs: %w", err)
	}
	c.count, c.earliest = n, fromNanos(earliest.Int64)
	return nil
}

// Seen records jti until expires and reports whether it was already
// recorded, and unexpired. Of two concurrent calls with the same jti,
// exactly one returns false.
func (c *ReplayCache) Seen(ctx context.Context, jti string, expires time.Time) (bool, error) {
	key := sha256.Sum256([]byte(jti))
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if c.count >= c.max && now.Before(c.earliest) {
		// Full, and nothing can have expired yet, unless jti is a replay;
		// refusing it either way is right.
		return false, ErrReplayCacheFull
	}

	var seen bool
	err := c.db.write(ctx, func(tx wtx) error {
		var exp int64
		err := tx.row(`SELECT expires FROM dpop_proofs WHERE cache = ? AND jti_hash = ?`, c.name, key[:]).Scan(&exp)
		exists := err == nil
		switch {
		case exists && now.Before(fromNanos(exp)):
			seen = true
			return nil
		case err != nil && !errors.Is(err, sql.ErrNoRows):
			return fmt.Errorf("statedb: checking a proof: %w", err)
		}
		if c.count >= c.max {
			if _, err := tx.exec(`DELETE FROM dpop_proofs WHERE cache = ? AND expires <= ?`, c.name, nanos(now)); err != nil {
				return fmt.Errorf("statedb: removing expired proofs: %w", err)
			}
			if err := c.recountLocked(tx.row); err != nil {
				return err
			}
			if c.count >= c.max {
				return ErrReplayCacheFull
			}
			exists = false // if it had expired, it's gone
		}
		_, err = tx.exec(`INSERT INTO dpop_proofs (cache, jti_hash, expires) VALUES (?, ?, ?)
			ON CONFLICT (cache, jti_hash) DO UPDATE SET expires = excluded.expires`, c.name, key[:], nanos(expires))
		if err != nil {
			return fmt.Errorf("statedb: recording a proof: %w", err)
		}
		if !exists {
			c.count++
		}
		if c.earliest.IsZero() || expires.Before(c.earliest) {
			c.earliest = expires
		}
		return nil
	})
	if err != nil {
		// What was counted inside a rolled back transaction is unknown.
		if rerr := c.recountLocked(func(query string, args ...any) *sql.Row { return c.db.w.QueryRowContext(ctx, query, args...) }); rerr != nil {
			return false, errors.Join(err, rerr)
		}
		return false, err
	}
	return seen, nil
}
