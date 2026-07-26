package store

import (
	"context"
	"database/sql"
	"time"
)

// CountEvents reports how many events are stored.
func (s *Store) CountEvents(ctx context.Context) (int64, error) {
	var n int64
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM events`).Scan(&n)
	return n, err
}

// DeleteEventsBefore removes events older than cutoff and returns how many went.
//
// The sensors table is deliberately left alone: its event_count is a lifetime
// tally and its last_seen is how an operator spots a sensor that has gone
// quiet. Neither should be rewritten by housekeeping.
func (s *Store) DeleteEventsBefore(ctx context.Context, cutoff time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM events WHERE time < ?`, cutoff.UTC().Format(timeFormat))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// TrimEvents keeps only the newest keep events and returns how many were
// removed.
//
// This is the backstop that age alone cannot provide: one sensor under a scan
// can produce a month's worth of events in an afternoon, and a console whose
// disk fills up stops recording the intrusion that filled it.
func (s *Store) TrimEvents(ctx context.Context, keep int64) (int64, error) {
	if keep <= 0 {
		return 0, nil
	}

	// The id of the newest event that is already past the limit. Everything at
	// or below it goes. AUTOINCREMENT guarantees id order matches insert order,
	// so this is stable even for events that arrive with old timestamps.
	var oldest int64
	err := s.db.QueryRowContext(ctx,
		`SELECT id FROM events ORDER BY id DESC LIMIT 1 OFFSET ?`, keep).Scan(&oldest)
	if err == sql.ErrNoRows {
		return 0, nil // fewer than keep events stored
	}
	if err != nil {
		return 0, err
	}

	res, err := s.db.ExecContext(ctx, `DELETE FROM events WHERE id <= ?`, oldest)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// Vacuum rebuilds the database file to hand freed pages back to the
// filesystem. SQLite reuses freed pages for new rows but never shrinks the file
// on its own, and "the console deletes old events but the disk still fills up"
// is not a fix anyone would accept.
//
// It rewrites the whole file and takes a write lock for the duration, so the
// janitor only calls it after a purge large enough to be worth it.
func (s *Store) Vacuum(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `VACUUM`)
	return err
}
