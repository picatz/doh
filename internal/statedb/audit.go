package statedb

import (
	"context"
	"encoding/json/v2"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/picatz/doh/internal/audit"
)

// Audit returns the audit trail kept in db.
func (db *DB) Audit() audit.Store { return auditStore{db} }

// auditStore implements [audit.Store].
type auditStore struct{ db *DB }

func (a auditStore) Record(ctx context.Context, e audit.Event) error {
	e = e.Normalize()
	details := []byte("{}")
	if len(e.Details) > 0 {
		var err error
		if details, err = json.Marshal(e.Details, json.Deterministic(true)); err != nil {
			return fmt.Errorf("statedb: recording an audit event: %w", err)
		}
	}
	_, err := a.db.exec(ctx, `INSERT INTO audit
		(time, tenant, actor_kind, actor_id, actor_name, actor_tenant, actor_via, action, target_type, target_id, summary, details)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		nanos(e.Time), e.Tenant, string(e.Actor.Kind), e.Actor.ID, e.Actor.Name, e.Actor.Tenant, e.Actor.Via,
		e.Action, e.Target.Type, e.Target.ID, e.Summary, string(details))
	if err != nil {
		return fmt.Errorf("statedb: recording an audit event: %w", err)
	}
	return nil
}

func (a auditStore) List(ctx context.Context, f audit.Filter) (audit.Page, error) {
	var (
		where []string
		args  []any
	)
	if !f.AllTenants {
		where, args = append(where, "tenant = ?"), append(args, f.Tenant)
	}
	if f.Actor != "" {
		where, args = append(where, "(actor_id = ? OR actor_name = ?)"), append(args, f.Actor, f.Actor)
	}
	if f.Action != "" {
		// Exactly, or under it: never with LIKE, whose wildcards an action
		// such as service_account would trip.
		where = append(where, "(action = ? OR substr(action, 1, ?) = ?)")
		args = append(args, f.Action, utf8.RuneCountInString(f.Action)+1, f.Action+".")
	}
	if !f.Before.IsZero() {
		where, args = append(where, "time < ?"), append(args, nanos(f.Before))
	}
	if f.PageToken != "" {
		before, err := audit.DecodePageToken(f.PageToken)
		if err != nil {
			return audit.Page{}, err
		}
		where, args = append(where, "seq < ?"), append(args, int64(min(before, 1<<62)))
	}
	query := `SELECT seq, time, tenant, actor_kind, actor_id, actor_name, actor_tenant, actor_via,
		action, target_type, target_id, summary, details FROM audit`
	if len(where) > 0 {
		query += " WHERE " + strings.Join(where, " AND ")
	}
	limit := f.PageLimit()
	query += " ORDER BY seq DESC LIMIT ?"
	args = append(args, limit+1) // one more, to know if there's a next page

	rows, err := a.db.readRows(ctx, query, args...)
	if err != nil {
		return audit.Page{}, fmt.Errorf("statedb: listing audit events: %w", err)
	}
	defer rows.Close()

	page := audit.Page{Events: []audit.Event{}}
	var lastSeq int64
	for rows.Next() {
		if len(page.Events) == limit {
			page.NextPageToken = audit.EncodePageToken(uint64(lastSeq))
			break
		}
		var (
			e       audit.Event
			seq, t  int64
			kind    string
			details string
		)
		if err := rows.Scan(&seq, &t, &e.Tenant, &kind, &e.Actor.ID, &e.Actor.Name, &e.Actor.Tenant, &e.Actor.Via,
			&e.Action, &e.Target.Type, &e.Target.ID, &e.Summary, &details); err != nil {
			return audit.Page{}, fmt.Errorf("statedb: reading audit events: %w", err)
		}
		e.ID, e.Time, e.Actor.Kind = audit.EncodeID(uint64(seq)), fromNanos(t).UTC(), audit.ActorKind(kind)
		if details != "{}" {
			if err := json.Unmarshal([]byte(details), &e.Details); err != nil {
				return audit.Page{}, fmt.Errorf("statedb: reading audit event %d: %w", seq, err)
			}
		}
		page.Events = append(page.Events, e)
		lastSeq = seq
	}
	if err := rows.Err(); err != nil {
		return audit.Page{}, fmt.Errorf("statedb: reading audit events: %w", err)
	}
	return page, nil
}
