package statedb

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// SetupLink is a stored setup link: the profile, and device, it sets up,
// until it expires.
type SetupLink struct {
	Profile, Device string
	Expires         time.Time
}

// SetupLinks returns setup links kept in db.
func (db *DB) SetupLinks() *SetupLinks { return &SetupLinks{db} }

// SetupLinks keeps setup links, by the SHA-256 of their codes.
type SetupLinks struct{ db *DB }

// Create stores link under hash. If limit unexpired links already exist,
// those that expire soonest are removed first.
func (l *SetupLinks) Create(ctx context.Context, hash [sha256.Size]byte, link SetupLink, now time.Time, limit int) error {
	return l.db.write(ctx, func(tx wtx) error {
		if _, err := tx.exec(`DELETE FROM setup_links WHERE expires <= ?`, nanos(now)); err != nil {
			return fmt.Errorf("statedb: removing expired setup links: %w", err)
		}
		var n int
		if err := tx.row(`SELECT count(*) FROM setup_links`).Scan(&n); err != nil {
			return fmt.Errorf("statedb: counting setup links: %w", err)
		}
		if n >= limit {
			if _, err := tx.exec(`DELETE FROM setup_links WHERE code_hash IN
				(SELECT code_hash FROM setup_links ORDER BY expires LIMIT ?)`, n-limit+1); err != nil {
				return fmt.Errorf("statedb: making room for a setup link: %w", err)
			}
		}
		if _, err := tx.exec(`INSERT OR REPLACE INTO setup_links (code_hash, profile, device, expires) VALUES (?, ?, ?, ?)`,
			hash[:], link.Profile, link.Device, nanos(link.Expires)); err != nil {
			return fmt.Errorf("statedb: storing a setup link: %w", err)
		}
		return nil
	})
}

// Lookup returns the link stored under hash, if it hasn't expired by now.
func (l *SetupLinks) Lookup(ctx context.Context, hash [sha256.Size]byte, now time.Time) (SetupLink, bool, error) {
	var (
		link    SetupLink
		expires int64
	)
	err := l.db.readRow(ctx, `SELECT profile, device, expires FROM setup_links WHERE code_hash = ? AND expires > ?`,
		hash[:], nanos(now)).Scan(&link.Profile, &link.Device, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return SetupLink{}, false, nil
	}
	if err != nil {
		return SetupLink{}, false, fmt.Errorf("statedb: reading a setup link: %w", err)
	}
	link.Expires = fromNanos(expires)
	return link, true, nil
}
