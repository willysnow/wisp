// Package store is the console's persistence layer.
//
// SQLite is used deliberately: the console has to stay as easy to deploy as the
// sensor, and a Postgres dependency would undo that. The driver is
// modernc.org/sqlite (pure Go) rather than mattn/go-sqlite3 (cgo) — cgo would
// break cross-compilation and the single static binary, which are the two
// properties this project exists for.
package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"github.com/willysnow/wisp/internal/event"
)

// schema is applied on every open. Every statement is IF NOT EXISTS so opening
// an existing database is a no-op.
const schema = `
CREATE TABLE IF NOT EXISTS sensors (
	node        TEXT PRIMARY KEY,
	first_seen  TEXT NOT NULL,
	last_seen   TEXT NOT NULL,
	event_count INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS events (
	id          INTEGER PRIMARY KEY AUTOINCREMENT,
	time        TEXT NOT NULL,
	node        TEXT NOT NULL,
	service     TEXT NOT NULL,
	kind        TEXT NOT NULL,
	src_ip      TEXT NOT NULL,
	src_port    INTEGER NOT NULL,
	dst_port    INTEGER NOT NULL,
	data        TEXT NOT NULL,
	received_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_events_time    ON events(time DESC);
CREATE INDEX IF NOT EXISTS idx_events_node    ON events(node);
CREATE INDEX IF NOT EXISTS idx_events_src_ip  ON events(src_ip);
CREATE INDEX IF NOT EXISTS idx_events_service ON events(service);

-- Only the hash is stored. A stolen console database must not yield working
-- sensor credentials, and there is never a reason to read a token back.
CREATE TABLE IF NOT EXISTS sensor_tokens (
	node       TEXT PRIMARY KEY,
	token_hash TEXT NOT NULL UNIQUE,
	created_at TEXT NOT NULL,
	last_used  TEXT,
	revoked_at TEXT
);

-- Operators who may read the UI. Separate from sensor_tokens on purpose: a
-- sensor credential may only write events, and a stolen one must not open the
-- dashboard that holds every captured password.
CREATE TABLE IF NOT EXISTS console_users (
	username      TEXT PRIMARY KEY,
	password_hash TEXT NOT NULL,
	created_at    TEXT NOT NULL,
	last_login    TEXT
);

-- Sessions live in the database rather than in memory so that a console
-- restart does not log the whole team out, and so revoking one is possible.
CREATE TABLE IF NOT EXISTS console_sessions (
	token_hash TEXT PRIMARY KEY,
	username   TEXT NOT NULL,
	created_at TEXT NOT NULL,
	expires_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sessions_user    ON console_sessions(username);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON console_sessions(expires_at);

-- Honeytokens: lures planted inside data — a document, a kubeconfig, an MCP
-- server entry — that do nothing until someone opens or uses them, at which
-- point they call home to this console. This row is the token's definition and
-- a running tally; every firing is also written to events, so a trigger appears
-- in the timeline, search, export and notifications like any other capture.
--
-- The id is not a secret: it travels inside the planted data and is what the
-- callback carries. It is random only so it is unguessable and unique, which is
-- why the whole row can be read back (unlike a sensor token, of which only the
-- hash is kept).
CREATE TABLE IF NOT EXISTS tokens (
	id             TEXT PRIMARY KEY,
	kind           TEXT NOT NULL,
	memo           TEXT NOT NULL,
	created_at     TEXT NOT NULL,
	created_by     TEXT NOT NULL DEFAULT '',
	trigger_count  INTEGER NOT NULL DEFAULT 0,
	last_triggered TEXT,
	disabled_at    TEXT
);
`

// TokenPrefix marks a string as a wisp sensor token. It exists so the token is
// recognisable in a config file, and so secret scanners can be taught to spot
// one that has been committed by accident.
const TokenPrefix = "wisp_"

// timeFormat is what timestamps are stored as. RFC3339 with nanoseconds sorts
// lexicographically in the same order it sorts chronologically, which lets
// SQLite use the plain TEXT index for time ordering.
const timeFormat = time.RFC3339Nano

type Store struct {
	db *sql.DB
}

// Open connects to the SQLite database at path, creating it if needed.
func Open(path string) (*Store, error) {
	// _busy_timeout keeps concurrent writers from failing outright when several
	// sensors deliver at once; WAL lets the UI read while ingest writes.
	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)", path)

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("apply schema: %w", err)
	}
	// One column arrived after the first release, so it is added rather than
	// declared: an existing console must keep its events across an upgrade.
	if err := migrateSilence(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

// Insert writes a batch of events and updates the sending sensor's record. The
// whole batch is one transaction, so a sensor either delivers all of it or
// retries all of it — partial delivery would make dedup and counting wrong.
func (s *Store) Insert(ctx context.Context, events []event.Event) error {
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
	perNode := map[string]int{}

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
		perNode[e.Node]++
	}

	for node, n := range perNode {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO sensors (node, first_seen, last_seen, event_count)
			VALUES (?, ?, ?, ?)
			ON CONFLICT(node) DO UPDATE SET
				last_seen   = excluded.last_seen,
				event_count = event_count + excluded.event_count`,
			node, now, now, n,
		); err != nil {
			return err
		}
	}

	return tx.Commit()
}

// Filter narrows an event query. Zero values mean "no constraint".
type Filter struct {
	Node    string
	Service string
	Kind    string
	SrcIP   string

	// Query is free text matched against every column, including the JSON
	// data blob — so searching for a username, a probed path, or a fragment of
	// a captured prompt all work.
	Query string

	Since  time.Time
	Limit  int
	Offset int
}

// maxLimit bounds one page. The UI never asks for more; this is here so a
// hand-written URL cannot ask the console to render a million rows.
const maxLimit = 1000

// defaultLimit is one page of events.
const defaultLimit = 100

// Record is one stored event, with the database id the UI links to.
type Record struct {
	ID int64
	event.Event
}

// where builds the shared WHERE clause. Every query that takes a Filter goes
// through here, so listing, counting, and exporting can never disagree about
// what the filter meant.
func (f Filter) where() (clause string, args []any) {
	var conditions []string

	for _, c := range []struct {
		column string
		value  string
	}{
		{"node", f.Node},
		{"service", f.Service},
		{"kind", f.Kind},
		{"src_ip", f.SrcIP},
	} {
		if c.value != "" {
			conditions = append(conditions, c.column+" = ?")
			args = append(args, c.value)
		}
	}

	if !f.Since.IsZero() {
		conditions = append(conditions, "time >= ?")
		args = append(args, f.Since.UTC().Format(timeFormat))
	}

	if q := strings.TrimSpace(f.Query); q != "" {
		// LIKE over the whole row rather than a full-text index. The events
		// table is bounded by the retention policy and the time window
		// narrows it first, so a scan is affordable — and an FTS index would
		// tokenise away exactly the things worth searching for here, like
		// "10.0.0." or a fragment of a path.
		pattern := "%" + escapeLike(q) + "%"

		// The pattern is bound once per column rather than with a numbered
		// placeholder: mixing ?NNN with the bare ? used above would renumber
		// the earlier parameters and silently match the wrong values.
		conditions = append(conditions,
			`(node LIKE ? ESCAPE '\' OR service LIKE ? ESCAPE '\'
			  OR kind LIKE ? ESCAPE '\' OR src_ip LIKE ? ESCAPE '\'
			  OR data LIKE ? ESCAPE '\')`)
		for i := 0; i < 5; i++ {
			args = append(args, pattern)
		}
	}

	if len(conditions) == 0 {
		return "", nil
	}
	return " WHERE " + strings.Join(conditions, " AND "), args
}

// escapeLike neutralises the wildcards in user input, so searching for "100%"
// finds the literal string rather than everything.
func escapeLike(s string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s)
}

func (f Filter) limit() int {
	switch {
	case f.Limit <= 0:
		return defaultLimit
	case f.Limit > maxLimit:
		return maxLimit
	}
	return f.Limit
}

// List returns one page of events, newest first.
func (s *Store) List(ctx context.Context, f Filter) ([]Record, error) {
	var out []Record
	err := s.each(ctx, f, f.limit(), func(r Record) error {
		out = append(out, r)
		return nil
	})
	return out, err
}

// Each streams every matching event to fn, newest first, up to limit. Export
// uses it so a large download never has to be assembled in memory first.
func (s *Store) Each(ctx context.Context, f Filter, limit int, fn func(Record) error) error {
	return s.each(ctx, f, limit, fn)
}

// Event returns a single stored event by its database id. The bool is false
// when nothing has that id — a stale or hand-typed /event/<id> link — which the
// caller turns into a 404 rather than an error.
func (s *Store) Event(ctx context.Context, id int64) (Record, bool, error) {
	var (
		r       Record
		ts, raw string
	)
	err := s.db.QueryRowContext(ctx,
		`SELECT id, time, node, service, kind, src_ip, src_port, dst_port, data
			FROM events WHERE id = ?`, id).
		Scan(&r.ID, &ts, &r.Node, &r.Service, &r.Kind,
			&r.SrcIP, &r.SrcPort, &r.DstPort, &raw)
	if errors.Is(err, sql.ErrNoRows) {
		return Record{}, false, nil
	}
	if err != nil {
		return Record{}, false, err
	}
	r.Time, _ = time.Parse(timeFormat, ts)
	if err := json.Unmarshal([]byte(raw), &r.Data); err != nil {
		r.Data = map[string]any{}
	}
	return r, true, nil
}

func (s *Store) each(ctx context.Context, f Filter, limit int, fn func(Record) error) error {
	clause, args := f.where()

	query := `SELECT id, time, node, service, kind, src_ip, src_port, dst_port, data
		FROM events` + clause + ` ORDER BY time DESC, id DESC LIMIT ? OFFSET ?`

	offset := f.Offset
	if offset < 0 {
		offset = 0
	}
	args = append(args, limit, offset)

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var (
			r       Record
			ts, raw string
		)
		if err := rows.Scan(&r.ID, &ts, &r.Node, &r.Service, &r.Kind,
			&r.SrcIP, &r.SrcPort, &r.DstPort, &raw); err != nil {
			return err
		}
		r.Time, _ = time.Parse(timeFormat, ts)
		if err := json.Unmarshal([]byte(raw), &r.Data); err != nil {
			r.Data = map[string]any{}
		}
		if err := fn(r); err != nil {
			return err
		}
	}
	return rows.Err()
}

// Count reports how many events match, which is what turns a list into pages.
func (s *Store) Count(ctx context.Context, f Filter) (int64, error) {
	clause, args := f.where()

	var n int64
	err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM events`+clause, args...).Scan(&n)
	return n, err
}

// Sensor is one registered sensor's state.
type Sensor struct {
	Node       string
	FirstSeen  time.Time
	LastSeen   time.Time
	EventCount int64
}

// Sensors returns every sensor that has ever delivered, most recently seen
// first. A sensor that has gone quiet is as interesting as a noisy one — it may
// have been found and killed.
func (s *Store) Sensors(ctx context.Context) ([]Sensor, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT node, first_seen, last_seen, event_count
		FROM sensors ORDER BY last_seen DESC`)
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

// SensorToken is one sensor's enrollment record. The token itself is never
// stored, so it is absent here.
type SensorToken struct {
	Node      string
	CreatedAt time.Time
	LastUsed  time.Time
	Revoked   bool
	RevokedAt time.Time
}

// CreateSensorToken enrolls a node and returns its token. The token is shown
// exactly once — only its hash is kept, so a lost token must be reissued.
//
// Re-enrolling an existing node replaces its token, which is how rotation and
// "I lost the token" are both handled.
func (s *Store) CreateSensorToken(ctx context.Context, node string) (string, error) {
	if node == "" {
		return "", fmt.Errorf("node name is required")
	}

	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	token := TokenPrefix + base64.RawURLEncoding.EncodeToString(raw)

	if _, err := s.db.ExecContext(ctx, `
		INSERT INTO sensor_tokens (node, token_hash, created_at)
		VALUES (?, ?, ?)
		ON CONFLICT(node) DO UPDATE SET
			token_hash = excluded.token_hash,
			created_at = excluded.created_at,
			last_used  = NULL,
			revoked_at = NULL`,
		node, hashToken(token), time.Now().UTC().Format(timeFormat),
	); err != nil {
		return "", err
	}
	return token, nil
}

// ResolveToken returns the node a token belongs to.
//
// This is what makes per-sensor tokens worth having: the node name comes from
// the credential, not from the request body, so a compromised sensor cannot
// forge events attributed to a different one.
func (s *Store) ResolveToken(ctx context.Context, token string) (node string, ok bool, err error) {
	var revoked sql.NullString

	err = s.db.QueryRowContext(ctx, `
		SELECT node, revoked_at FROM sensor_tokens WHERE token_hash = ?`,
		hashToken(token),
	).Scan(&node, &revoked)

	switch {
	case err == sql.ErrNoRows:
		return "", false, nil
	case err != nil:
		return "", false, err
	case revoked.Valid:
		return "", false, nil
	}

	// Best-effort liveness tracking; a failure here must not reject a valid
	// delivery.
	_, _ = s.db.ExecContext(ctx,
		`UPDATE sensor_tokens SET last_used = ? WHERE node = ?`,
		time.Now().UTC().Format(timeFormat), node)

	return node, true, nil
}

// RevokeSensor disables a node's token. It reports whether a live token was
// actually revoked, so the caller can tell "done" from "there was nothing there".
func (s *Store) RevokeSensor(ctx context.Context, node string) (bool, error) {
	res, err := s.db.ExecContext(ctx, `
		UPDATE sensor_tokens SET revoked_at = ?
		WHERE node = ? AND revoked_at IS NULL`,
		time.Now().UTC().Format(timeFormat), node)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

// ListSensorTokens returns every enrollment, including revoked ones — a
// revoked sensor is part of the audit trail.
func (s *Store) ListSensorTokens(ctx context.Context) ([]SensorToken, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT node, created_at, last_used, revoked_at
		FROM sensor_tokens ORDER BY node`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []SensorToken
	for rows.Next() {
		var (
			t                 SensorToken
			created           string
			lastUsed, revoked sql.NullString
		)
		if err := rows.Scan(&t.Node, &created, &lastUsed, &revoked); err != nil {
			return nil, err
		}
		t.CreatedAt, _ = time.Parse(timeFormat, created)
		if lastUsed.Valid {
			t.LastUsed, _ = time.Parse(timeFormat, lastUsed.String)
		}
		if revoked.Valid {
			t.Revoked = true
			t.RevokedAt, _ = time.Parse(timeFormat, revoked.String)
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// HasSensorTokens reports whether any enrollment exists. The console uses this
// to decide whether the legacy shared token should still be accepted.
func (s *Store) HasSensorTokens(ctx context.Context) (bool, error) {
	var n int
	err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM sensor_tokens WHERE revoked_at IS NULL`).Scan(&n)
	return n > 0, err
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// Counts returns the number of events per service, used for the summary row.
func (s *Store) Counts(ctx context.Context, since time.Time) (map[string]int64, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT service, COUNT(*) FROM events WHERE time >= ? GROUP BY service`,
		since.UTC().Format(timeFormat))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := map[string]int64{}
	for rows.Next() {
		var (
			service string
			n       int64
		)
		if err := rows.Scan(&service, &n); err != nil {
			return nil, err
		}
		out[service] = n
	}
	return out, rows.Err()
}
