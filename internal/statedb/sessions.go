package statedb

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/picatz/doh/internal/signin"
)

// Sessions returns browser sessions kept in db, for [signin.Config].
func (db *DB) Sessions() signin.Sessions { return sessions{db} }

// sessions implements [signin.Sessions].
type sessions struct{ db *DB }

func (s sessions) Get(ctx context.Context, id signin.SessionID) (signin.StoredSession, bool, error) {
	var (
		sess                      signin.StoredSession
		role                      string
		pending                   bool
		created, expires, lastUse int64
	)
	err := s.db.readRow(ctx,
		`SELECT person, name, role, tenant, method, pending, created, expires, last_seen FROM sessions WHERE id_hash = ?`, id[:],
	).Scan(&sess.Person, &sess.Name, &role, &sess.Tenant, &sess.Method, &pending, &created, &expires, &lastUse)
	if errors.Is(err, sql.ErrNoRows) {
		return signin.StoredSession{}, false, nil
	}
	if err != nil {
		return signin.StoredSession{}, false, fmt.Errorf("statedb: reading a session: %w", err)
	}
	sess.Role, sess.Pending = signin.Role(role), pending
	sess.Created, sess.Expires, sess.LastSeen = fromNanos(created), fromNanos(expires), fromNanos(lastUse)
	return sess, true, nil
}

func (s sessions) Put(ctx context.Context, id, replaced signin.SessionID, sess signin.StoredSession, limit int) error {
	return s.db.write(ctx, func(tx wtx) error {
		if replaced != (signin.SessionID{}) {
			if _, err := tx.exec(`DELETE FROM sessions WHERE id_hash = ?`, replaced[:]); err != nil {
				return fmt.Errorf("statedb: replacing a session: %w", err)
			}
		}
		var n int
		if err := tx.row(`SELECT count(*) FROM sessions WHERE pending = ?`, sess.Pending).Scan(&n); err != nil {
			return fmt.Errorf("statedb: counting sessions: %w", err)
		}
		if n >= limit {
			if _, err := tx.exec(`DELETE FROM sessions WHERE id_hash IN
				(SELECT id_hash FROM sessions WHERE pending = ? ORDER BY last_seen LIMIT ?)`, sess.Pending, n-limit+1); err != nil {
				return fmt.Errorf("statedb: making room for a session: %w", err)
			}
		}
		_, err := tx.exec(`INSERT OR REPLACE INTO sessions
			(id_hash, person, name, role, tenant, method, pending, created, expires, last_seen)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			id[:], sess.Person, sess.Name, string(sess.Role), sess.Tenant, sess.Method, sess.Pending,
			nanos(sess.Created), nanos(sess.Expires), nanos(sess.LastSeen))
		if err != nil {
			return fmt.Errorf("statedb: storing a session: %w", err)
		}
		return nil
	})
}

func (s sessions) Touch(ctx context.Context, id signin.SessionID, t time.Time) error {
	if _, err := s.db.exec(ctx, `UPDATE sessions SET last_seen = max(last_seen, ?) WHERE id_hash = ?`, nanos(t), id[:]); err != nil {
		return fmt.Errorf("statedb: recording a session's use: %w", err)
	}
	return nil
}

func (s sessions) Delete(ctx context.Context, id signin.SessionID) error {
	if _, err := s.db.exec(ctx, `DELETE FROM sessions WHERE id_hash = ?`, id[:]); err != nil {
		return fmt.Errorf("statedb: removing a session: %w", err)
	}
	return nil
}

func (s sessions) DeletePerson(ctx context.Context, person string) error {
	if person == "" {
		return nil
	}
	if _, err := s.db.exec(ctx, `DELETE FROM sessions WHERE person = ?`, person); err != nil {
		return fmt.Errorf("statedb: removing a person's sessions: %w", err)
	}
	return nil
}

func (s sessions) Sweep(ctx context.Context, now time.Time, idle time.Duration) error {
	if _, err := s.db.exec(ctx, `DELETE FROM sessions WHERE expires <= ? OR last_seen <= ?`,
		nanos(now), nanos(now.Add(-idle))); err != nil {
		return fmt.Errorf("statedb: removing expired sessions: %w", err)
	}
	return nil
}
