package statedb

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"maps"
	"slices"
	"time"

	"github.com/picatz/doh/internal/alerts"
)

// AlertMemory returns what alerts remember, kept in db, for
// [alerts.Options]. It's also an [alerts.DeviceImporter].
func (db *DB) AlertMemory() alerts.Memory { return alertMemory{db} }

// alertMemory implements [alerts.Memory] and [alerts.DeviceImporter].
type alertMemory struct{ db *DB }

// maxDeviceName bounds the device keys remembered. Keys are made by the
// alerts engine from profile, device, and client names, all bounded much
// lower.
const maxDeviceName = 512

func (m alertMemory) SeeDevice(ctx context.Context, scope, device string, now time.Time) (isNew bool, since time.Time, err error) {
	if len(device) > maxDeviceName || len(scope) > maxDeviceName {
		return false, time.Time{}, errors.New("statedb: device name too long")
	}
	err = m.db.write(ctx, func(tx wtx) error {
		var sinceN int64
		if err := tx.row(`INSERT INTO alert_scopes (scope, devices_since) VALUES (?, ?)
			ON CONFLICT (scope) DO UPDATE SET devices_since = devices_since RETURNING devices_since`,
			scope, nanos(now)).Scan(&sinceN); err != nil {
			return fmt.Errorf("statedb: remembering a device: %w", err)
		}
		since = fromNanos(sinceN)

		res, err := tx.exec(`UPDATE alert_devices SET last_seen = max(last_seen, ?) WHERE scope = ? AND device = ?`,
			nanos(now), scope, device)
		if err != nil {
			return fmt.Errorf("statedb: remembering a device: %w", err)
		}
		if n, _ := res.RowsAffected(); n > 0 {
			return nil
		}
		isNew = true
		if err := makeRoomForDevices(tx, scope, 1); err != nil {
			return err
		}
		if _, err := tx.exec(`INSERT INTO alert_devices (scope, device, last_seen) VALUES (?, ?, ?)`,
			scope, device, nanos(now)); err != nil {
			return fmt.Errorf("statedb: remembering a device: %w", err)
		}
		return nil
	})
	return isNew, since, err
}

// makeRoomForDevices forgets scope's least recently seen devices, so n
// more fit within [alerts.MaxSeenDevices].
func makeRoomForDevices(tx wtx, scope string, n int) error {
	var count int
	if err := tx.row(`SELECT count(*) FROM alert_devices WHERE scope = ?`, scope).Scan(&count); err != nil {
		return fmt.Errorf("statedb: counting devices: %w", err)
	}
	if over := count + n - alerts.MaxSeenDevices; over > 0 {
		if _, err := tx.exec(`DELETE FROM alert_devices WHERE scope = ? AND device IN
			(SELECT device FROM alert_devices WHERE scope = ? ORDER BY last_seen, device LIMIT ?)`, scope, scope, over); err != nil {
			return fmt.Errorf("statedb: forgetting devices: %w", err)
		}
	}
	return nil
}

func (m alertMemory) ImportDevices(ctx context.Context, scope string, since time.Time, seen map[string]time.Time) error {
	return m.db.write(ctx, func(tx wtx) error {
		if _, err := tx.exec(`INSERT INTO alert_scopes (scope, devices_since) VALUES (?, ?)
			ON CONFLICT (scope) DO UPDATE SET devices_since = min(devices_since, excluded.devices_since)`,
			scope, nanos(since)); err != nil {
			return fmt.Errorf("statedb: importing devices: %w", err)
		}
		// The most recently seen are kept, if there are too many.
		devices := slices.SortedFunc(maps.Keys(seen), func(a, b string) int { return seen[b].Compare(seen[a]) })
		if len(devices) > alerts.MaxSeenDevices {
			devices = devices[:alerts.MaxSeenDevices]
		}
		for _, d := range devices {
			if len(d) > maxDeviceName {
				continue
			}
			if _, err := tx.exec(`INSERT INTO alert_devices (scope, device, last_seen) VALUES (?, ?, ?)
				ON CONFLICT (scope, device) DO UPDATE SET last_seen = max(last_seen, excluded.last_seen)`,
				scope, d, nanos(seen[d])); err != nil {
				return fmt.Errorf("statedb: importing devices: %w", err)
			}
		}
		return makeRoomForDevices(tx, scope, 0)
	})
}

func (m alertMemory) Claim(ctx context.Context, scope, kind, key string, now time.Time, window time.Duration) (bool, error) {
	if len(key) > maxDeviceName*2 {
		return false, errors.New("statedb: alert key too long")
	}
	var claimed bool
	err := m.db.write(ctx, func(tx wtx) error {
		var sent int64
		err := tx.row(`SELECT sent FROM alert_sent WHERE scope = ? AND kind = ? AND key = ?`, scope, kind, key).Scan(&sent)
		switch {
		case err == nil && now.Sub(fromNanos(sent)) < window:
			return nil // sent within the window
		case err != nil && !errors.Is(err, sql.ErrNoRows):
			return fmt.Errorf("statedb: checking an alert: %w", err)
		case errors.Is(err, sql.ErrNoRows):
			var n int
			if err := tx.row(`SELECT count(*) FROM alert_sent`).Scan(&n); err != nil {
				return fmt.Errorf("statedb: counting alerts: %w", err)
			}
			if n >= alerts.MaxClaims {
				if _, err := tx.exec(`DELETE FROM alert_sent WHERE sent <= ?`, nanos(now.Add(-window))); err != nil {
					return fmt.Errorf("statedb: forgetting alerts: %w", err)
				}
				if err := tx.row(`SELECT count(*) FROM alert_sent`).Scan(&n); err != nil {
					return fmt.Errorf("statedb: counting alerts: %w", err)
				}
				if n >= alerts.MaxClaims {
					return alerts.ErrMemoryFull
				}
			}
		}
		if _, err := tx.exec(`INSERT INTO alert_sent (scope, kind, key, sent) VALUES (?, ?, ?, ?)
			ON CONFLICT (scope, kind, key) DO UPDATE SET sent = excluded.sent`, scope, kind, key, nanos(now)); err != nil {
			return fmt.Errorf("statedb: remembering an alert: %w", err)
		}
		claimed = true
		return nil
	})
	return claimed, err
}

func (m alertMemory) Forget(ctx context.Context, scope string) error {
	return m.db.write(ctx, func(tx wtx) error {
		// The scope's devices go with it, by foreign key.
		if _, err := tx.exec(`DELETE FROM alert_scopes WHERE scope = ?`, scope); err != nil {
			return fmt.Errorf("statedb: forgetting a scope's alerts: %w", err)
		}
		if _, err := tx.exec(`DELETE FROM alert_sent WHERE scope = ?`, scope); err != nil {
			return fmt.Errorf("statedb: forgetting a scope's alerts: %w", err)
		}
		return nil
	})
}
