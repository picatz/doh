package statedb

import (
	"context"
	"fmt"
	"time"
)

// SeenDevice is a device the server has answered: one profile, device
// name, and client address, with the tenant its profile had and the
// transport it last used.
type SeenDevice struct {
	Profile, Device, Client string
	Tenant, Transport       string
	First, Last             time.Time
}

// SeenDevices returns the devices seen kept in db.
func (db *DB) SeenDevices() *SeenDevices { return &SeenDevices{db} }

// SeenDevices keeps the devices a server has answered.
type SeenDevices struct{ db *DB }

// Save stores devices, merging each with what's stored for its profile,
// device, and client (the earliest first sighting, the latest last one),
// then keeps only the limit most recently seen.
func (d *SeenDevices) Save(ctx context.Context, devices []SeenDevice, limit int) error {
	return d.db.write(ctx, func(tx wtx) error {
		for _, s := range devices {
			if _, err := tx.exec(`INSERT INTO seen_devices (profile, device, client, tenant, transport, first_seen, last_seen)
				VALUES (?, ?, ?, ?, ?, ?, ?)
				ON CONFLICT (profile, device, client) DO UPDATE SET
					tenant = excluded.tenant, transport = excluded.transport,
					first_seen = min(first_seen, excluded.first_seen),
					last_seen = max(last_seen, excluded.last_seen)`,
				s.Profile, s.Device, s.Client, s.Tenant, s.Transport, nanos(s.First), nanos(s.Last)); err != nil {
				return fmt.Errorf("statedb: storing a device seen: %w", err)
			}
		}
		if _, err := tx.exec(`DELETE FROM seen_devices WHERE (profile, device, client) IN
			(SELECT profile, device, client FROM seen_devices ORDER BY last_seen DESC LIMIT -1 OFFSET ?)`, limit); err != nil {
			return fmt.Errorf("statedb: forgetting devices seen: %w", err)
		}
		return nil
	})
}

// Load returns at most limit devices, the most recently seen first.
func (d *SeenDevices) Load(ctx context.Context, limit int) ([]SeenDevice, error) {
	rows, err := d.db.readRows(ctx, `SELECT profile, device, client, tenant, transport, first_seen, last_seen
		FROM seen_devices ORDER BY last_seen DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("statedb: reading devices seen: %w", err)
	}
	defer rows.Close()
	var out []SeenDevice
	for rows.Next() {
		var (
			s           SeenDevice
			first, last int64
		)
		if err := rows.Scan(&s.Profile, &s.Device, &s.Client, &s.Tenant, &s.Transport, &first, &last); err != nil {
			return nil, fmt.Errorf("statedb: reading devices seen: %w", err)
		}
		s.First, s.Last = fromNanos(first), fromNanos(last)
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("statedb: reading devices seen: %w", err)
	}
	return out, nil
}
