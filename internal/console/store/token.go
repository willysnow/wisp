package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base32"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/willysnow/wisp/internal/event"
)

// tokenIDBytes is the entropy in a token id. 15 bytes is 120 bits, which is
// unguessable, and base32-encodes to exactly 24 characters — well inside the
// 63-character limit on a single DNS label, which a DNS token has to live in.
const tokenIDBytes = 15

// tokenEncoding is lowercase base32 without padding: the alphabet a DNS label
// allows (letters and digits, case-insensitive) with nothing that needs
// escaping in a URL path either. Padding is dropped because '=' is neither.
var tokenEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// Token is one planted honeytoken: its definition and how often it has fired.
//
// Everything here can be read back, because none of it is a secret — the id is
// what the planted data carries home, so hiding it from the operator who
// planted it would help nobody.
type Token struct {
	ID            string
	Kind          string
	Memo          string
	CreatedAt     time.Time
	CreatedBy     string
	TriggerCount  int64
	LastTriggered time.Time
	Disabled      bool
	DisabledAt    time.Time
}

// Triggered reports whether the token has ever fired.
func (t Token) Triggered() bool { return t.TriggerCount > 0 }

// CreateToken mints a token of the given kind and returns it. The memo is the
// operator's own note — where it was planted — and is carried on every alert
// the token raises, so "which lure fired" is answerable without a lookup.
func (s *Store) CreateToken(ctx context.Context, kind, memo, createdBy string) (Token, error) {
	kind = strings.TrimSpace(kind)
	if kind == "" {
		return Token{}, fmt.Errorf("token kind is required")
	}

	id, err := newTokenID()
	if err != nil {
		return Token{}, err
	}

	now := time.Now().UTC()
	if _, err := s.db.ExecContext(ctx, `
		INSERT INTO tokens (id, kind, memo, created_at, created_by)
		VALUES (?, ?, ?, ?, ?)`,
		id, kind, memo, now.Format(timeFormat), createdBy,
	); err != nil {
		return Token{}, err
	}

	return Token{
		ID:        id,
		Kind:      kind,
		Memo:      memo,
		CreatedAt: now,
		CreatedBy: createdBy,
	}, nil
}

// GetToken returns one token by id. The boolean reports whether it exists.
func (s *Store) GetToken(ctx context.Context, id string) (Token, bool, error) {
	return scanToken(s.db.QueryRowContext(ctx, `
		SELECT id, kind, memo, created_at, created_by,
		       trigger_count, last_triggered, disabled_at
		FROM tokens WHERE id = ?`, strings.ToLower(id)))
}

// ListTokens returns every token, most recently created first.
func (s *Store) ListTokens(ctx context.Context) ([]Token, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, kind, memo, created_at, created_by,
		       trigger_count, last_triggered, disabled_at
		FROM tokens ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Token
	for rows.Next() {
		t, _, err := scanToken(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// DisableToken stops a token from recording further hits. It reports whether a
// live token was actually disabled, so the caller can tell "done" from "there
// was nothing there or it was already off".
//
// A disabled token is kept, not deleted: it is part of the record of what was
// planted, and its past firings stay in the timeline.
func (s *Store) DisableToken(ctx context.Context, id string) (bool, error) {
	res, err := s.db.ExecContext(ctx, `
		UPDATE tokens SET disabled_at = ?
		WHERE id = ? AND disabled_at IS NULL`,
		time.Now().UTC().Format(timeFormat), strings.ToLower(id))
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

// RecordTokenTrigger records a firing of the token named by id.
//
// It does two things in one transaction so the tally and the timeline can never
// disagree: it writes ev to the events table (enriched with the token's id,
// kind and memo), and it bumps the token's counter and last-fired time. It
// deliberately does not touch the sensors table — a token hit arrives at the
// console directly, from wherever the planted data ended up, not from a sensor.
//
// The caller sets ev's Time, Node, Service, Kind, addresses and any
// request-specific Data; a missing or disabled token records nothing and
// returns ok=false, which is how the caller decides an unknown id gets no
// acknowledgement.
func (s *Store) RecordTokenTrigger(ctx context.Context, id string, ev event.Event) (tok Token, ok bool, err error) {
	id = strings.ToLower(id)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Token{}, false, err
	}
	defer tx.Rollback() //nolint:errcheck // no-op once Commit succeeds

	tok, found, err := scanToken(tx.QueryRowContext(ctx, `
		SELECT id, kind, memo, created_at, created_by,
		       trigger_count, last_triggered, disabled_at
		FROM tokens WHERE id = ?`, id))
	switch {
	case err != nil:
		return Token{}, false, err
	case !found || tok.Disabled:
		// Unknown or switched off: nothing is recorded, so a scanner spraying
		// guessed ids at the callback endpoint cannot fill the database, and a
		// disabled token stays quiet.
		return Token{}, false, nil
	}

	if ev.Data == nil {
		ev.Data = map[string]any{}
	}
	// The token's own facts override anything the request tried to put under the
	// same keys: these come from the console's own records, not the caller.
	ev.Data["token"] = tok.ID
	ev.Data["token_kind"] = tok.Kind
	if tok.Memo != "" {
		ev.Data["memo"] = tok.Memo
	}

	data, err := marshalData(ev.Data)
	if err != nil {
		return Token{}, false, err
	}

	now := time.Now().UTC().Format(timeFormat)
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO events (time, node, service, kind, src_ip, src_port, dst_port, data, received_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		ev.Time.UTC().Format(timeFormat), ev.Node, ev.Service, ev.Kind,
		ev.SrcIP, ev.SrcPort, ev.DstPort, data, now,
	); err != nil {
		return Token{}, false, err
	}

	if _, err := tx.ExecContext(ctx, `
		UPDATE tokens SET trigger_count = trigger_count + 1, last_triggered = ?
		WHERE id = ?`, ev.Time.UTC().Format(timeFormat), id,
	); err != nil {
		return Token{}, false, err
	}

	if err := tx.Commit(); err != nil {
		return Token{}, false, err
	}

	// Return the token as it now stands, so a caller that reports the hit sees
	// the incremented count rather than the pre-trigger one.
	tok.TriggerCount++
	tok.LastTriggered = ev.Time.UTC()
	return tok, true, nil
}

// scanner is the read surface shared by *sql.Row and *sql.Rows.
type scanner interface {
	Scan(dest ...any) error
}

func scanToken(row scanner) (Token, bool, error) {
	var (
		t                       Token
		created                 string
		createdBy               sql.NullString
		lastTriggered, disabled sql.NullString
	)
	err := row.Scan(&t.ID, &t.Kind, &t.Memo, &created, &createdBy,
		&t.TriggerCount, &lastTriggered, &disabled)
	switch {
	case err == sql.ErrNoRows:
		return Token{}, false, nil
	case err != nil:
		return Token{}, false, err
	}

	t.CreatedAt, _ = time.Parse(timeFormat, created)
	t.CreatedBy = createdBy.String
	if lastTriggered.Valid {
		t.LastTriggered, _ = time.Parse(timeFormat, lastTriggered.String)
	}
	if disabled.Valid {
		t.Disabled = true
		t.DisabledAt, _ = time.Parse(timeFormat, disabled.String)
	}
	return t, true, nil
}

// marshalData serialises an event's data blob, falling back to an empty object
// rather than failing a record over a value that would not marshal — an event
// with a thinner detail beats a dropped one, the same trade Insert makes.
func marshalData(m map[string]any) (string, error) {
	b, err := json.Marshal(m)
	if err != nil {
		return "{}", nil
	}
	return string(b), nil
}

func newTokenID() (string, error) {
	raw := make([]byte, tokenIDBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return strings.ToLower(tokenEncoding.EncodeToString(raw)), nil
}
