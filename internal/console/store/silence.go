package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/willysnow/wisp/internal/event"
)

// A sensor that stops reporting is not the same as a quiet network, and the
// console is the only place that can tell the difference: the sensor cannot
// report its own death, and silence is exactly what an attacker who found and
// killed it would produce.
//
// The alerted flag lives in the database rather than in memory so that a
// console restart does not re-alert for every sensor that is still down, and
// so that a sensor which has been silent since before the restart is still
// known to be silent.

// migrateSilence adds the tracking column to databases created before this
// existed. SQLite has no "ADD COLUMN IF NOT EXISTS", so the column list is
// checked first.
func migrateSilence(db *sql.DB) error {
	rows, err := db.Query(`PRAGMA table_info(sensors)`)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var (
			cid        int
			name, typ  string
			notNull    int
			defaultVal sql.NullString
			pk         int
		)
		if err := rows.Scan(&cid, &name, &typ, &notNull, &defaultVal, &pk); err != nil {
			return err
		}
		if name == "silent_alerted" {
			return rows.Err()
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}

	_, err = db.Exec(`ALTER TABLE sensors ADD COLUMN silent_alerted TEXT`)
	return err
}

// SilenceTransitions finds the sensors that have crossed the silence threshold
// in either direction, and records the crossing so each one is reported once.
//
// It returns the sensors that have just gone quiet and those that have just
// come back. Doing both in one transaction means a console that is restarted
// mid-check cannot alert twice or lose a transition.
func (s *Store) SilenceTransitions(ctx context.Context, cutoff time.Time) (silent, returned []Sensor, err error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, nil, err
	}
	defer tx.Rollback() //nolint:errcheck // no-op once Commit succeeds

	stamp := cutoff.UTC().Format(timeFormat)

	silent, err = sensorsWhere(ctx, tx,
		`last_seen < ? AND silent_alerted IS NULL`, stamp)
	if err != nil {
		return nil, nil, err
	}
	returned, err = sensorsWhere(ctx, tx,
		`last_seen >= ? AND silent_alerted IS NOT NULL`, stamp)
	if err != nil {
		return nil, nil, err
	}

	now := time.Now().UTC().Format(timeFormat)
	for _, sensor := range silent {
		if _, err := tx.ExecContext(ctx,
			`UPDATE sensors SET silent_alerted = ? WHERE node = ?`, now, sensor.Node,
		); err != nil {
			return nil, nil, err
		}
	}
	for _, sensor := range returned {
		if _, err := tx.ExecContext(ctx,
			`UPDATE sensors SET silent_alerted = NULL WHERE node = ?`, sensor.Node,
		); err != nil {
			return nil, nil, err
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, nil, err
	}
	return silent, returned, nil
}

// SetSensorLastSeen overrides when a sensor was last heard from.
//
// It exists for tests. Everything about silence handling is elapsed time, and
// the alternative is a test that waits out the threshold — which would mean
// either a sleepy test suite or a threshold too short to be realistic.
func (s *Store) SetSensorLastSeen(ctx context.Context, node string, at time.Time) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE sensors SET last_seen = ? WHERE node = ?`,
		at.UTC().Format(timeFormat), node)
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil {
		return err
	} else if n == 0 {
		return fmt.Errorf("no such sensor %q", node)
	}
	return nil
}

func sensorsWhere(ctx context.Context, tx *sql.Tx, condition string, args ...any) ([]Sensor, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT node, first_seen, last_seen, event_count
		FROM sensors WHERE `+condition+` ORDER BY node`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Sensor
	for rows.Next() {
		var (
			s           Sensor
			first, last string
		)
		if err := rows.Scan(&s.Node, &first, &last, &s.EventCount); err != nil {
			return nil, err
		}
		s.FirstSeen, _ = time.Parse(timeFormat, first)
		s.LastSeen, _ = time.Parse(timeFormat, last)
		out = append(out, s)
	}
	return out, rows.Err()
}

// InsertSystem writes events the console generated itself.
//
// Unlike Insert it leaves the sensors table alone, which matters more than it
// sounds: a "sensor has gone quiet" event attributed to that sensor would
// otherwise update its last_seen and immediately mark it healthy again.
func (s *Store) InsertSystem(ctx context.Context, events []event.Event) error {
	if len(events) == 0 {
		return nil
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck // no-op once Commit succeeds

	insert, err := tx.PrepareContext(ctx, `
		INSERT INTO events (time, node, service, kind, src_ip, src_port, dst_port, data, received_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer insert.Close()

	now := time.Now().UTC().Format(timeFormat)
	for _, e := range events {
		data, err := json.Marshal(e.Data)
		if err != nil {
			data = []byte("{}")
		}
		if _, err := insert.ExecContext(ctx,
			e.Time.UTC().Format(timeFormat), e.Node, e.Service, e.Kind,
			e.SrcIP, e.SrcPort, e.DstPort, string(data), now,
		); err != nil {
			return err
		}
	}
	return tx.Commit()
}
