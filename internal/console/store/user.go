package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"fmt"
	"strings"
	"sync"
	"time"
	"unicode"

	"golang.org/x/crypto/bcrypt"
)

// MinPasswordLength is the shortest operator password accepted.
//
// Twelve rather than the usual eight because of what is behind the login: the
// console holds every credential, prompt, and token the fleet has captured. It
// is a higher-value target than the systems it protects.
const MinPasswordLength = 12

// sessionTokenBytes is the entropy in a session cookie. 256 bits, same as a
// sensor token, so the cookie is not the weak end of the chain.
const sessionTokenBytes = 32

// User is one operator account. The password hash never leaves the store.
type User struct {
	Username  string
	CreatedAt time.Time
	LastLogin time.Time
}

// decoyHash is compared against when the username does not exist, so that a
// wrong username and a wrong password take the same time. Without it, login
// timing tells an attacker which operator accounts are real.
//
// It is computed once, lazily, because bcrypt at the default cost takes ~60ms
// and no CLI subcommand should pay for that.
var decoyHash = sync.OnceValue(func() []byte {
	h, err := bcrypt.GenerateFromPassword([]byte("decoy"), bcrypt.DefaultCost)
	if err != nil {
		// bcrypt only fails on an invalid cost, which is a constant here.
		panic(fmt.Sprintf("bcrypt decoy: %v", err))
	}
	return h
})

// CreateUser adds an operator account. It fails if the username is taken —
// changing a password is SetPassword, and doing it by accident should not be
// possible.
func (s *Store) CreateUser(ctx context.Context, username, password string) error {
	if err := ValidateUsername(username); err != nil {
		return err
	}
	if err := ValidatePassword(password); err != nil {
		return err
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	_, err = s.db.ExecContext(ctx, `
		INSERT INTO console_users (username, password_hash, created_at)
		VALUES (?, ?, ?)`,
		username, string(hash), time.Now().UTC().Format(timeFormat))
	if err != nil && strings.Contains(err.Error(), "UNIQUE") {
		return fmt.Errorf("user %q already exists", username)
	}
	return err
}

// SetPassword changes a password and invalidates every session that account
// holds. A password is changed either because it rotated or because it leaked;
// in the second case leaving the old sessions live would defeat the point.
func (s *Store) SetPassword(ctx context.Context, username, password string) error {
	if err := ValidatePassword(password); err != nil {
		return err
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	res, err := s.db.ExecContext(ctx,
		`UPDATE console_users SET password_hash = ? WHERE username = ?`,
		string(hash), username)
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil {
		return err
	} else if n == 0 {
		return fmt.Errorf("no such user %q", username)
	}

	return s.DeleteUserSessions(ctx, username)
}

// DeleteUser removes an account and its sessions. It reports whether an account
// was actually there.
func (s *Store) DeleteUser(ctx context.Context, username string) (bool, error) {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM console_users WHERE username = ?`, username)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil || n == 0 {
		return false, err
	}
	return true, s.DeleteUserSessions(ctx, username)
}

// ListUsers returns every operator account, oldest first.
func (s *Store) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT username, created_at, last_login
		FROM console_users ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []User
	for rows.Next() {
		var (
			u       User
			created string
			last    sql.NullString
		)
		if err := rows.Scan(&u.Username, &created, &last); err != nil {
			return nil, err
		}
		u.CreatedAt, _ = time.Parse(timeFormat, created)
		if last.Valid {
			u.LastLogin, _ = time.Parse(timeFormat, last.String)
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// CountUsers reports how many operator accounts exist. The console uses this at
// startup to decide whether it needs to bootstrap one.
func (s *Store) CountUsers(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM console_users`).Scan(&n)
	return n, err
}

// VerifyPassword checks a login. An unknown username costs the same as a wrong
// password, and neither is distinguished in the return value: the caller has
// nothing to leak even if it wanted to.
func (s *Store) VerifyPassword(ctx context.Context, username, password string) (bool, error) {
	var hash string
	err := s.db.QueryRowContext(ctx,
		`SELECT password_hash FROM console_users WHERE username = ?`,
		username).Scan(&hash)

	switch {
	case err == sql.ErrNoRows:
		_ = bcrypt.CompareHashAndPassword(decoyHash(), []byte(password))
		return false, nil
	case err != nil:
		return false, err
	}

	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) != nil {
		return false, nil
	}

	// Best-effort: a failure to record the login must not fail the login.
	_, _ = s.db.ExecContext(ctx,
		`UPDATE console_users SET last_login = ? WHERE username = ?`,
		time.Now().UTC().Format(timeFormat), username)

	return true, nil
}

// CreateSession issues a session token for username, valid for ttl. Only the
// hash is stored, for the same reason sensor tokens are hashed: a database that
// leaks must not hand over live access.
func (s *Store) CreateSession(ctx context.Context, username string, ttl time.Duration) (string, error) {
	raw := make([]byte, sessionTokenBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	token := base64.RawURLEncoding.EncodeToString(raw)

	now := time.Now().UTC()
	if _, err := s.db.ExecContext(ctx, `
		INSERT INTO console_sessions (token_hash, username, created_at, expires_at)
		VALUES (?, ?, ?, ?)`,
		hashToken(token), username,
		now.Format(timeFormat), now.Add(ttl).Format(timeFormat),
	); err != nil {
		return "", err
	}
	return token, nil
}

// ResolveSession returns the operator a session cookie belongs to. An expired
// session resolves to nothing and is deleted on the way out.
func (s *Store) ResolveSession(ctx context.Context, token string) (username string, ok bool, err error) {
	if token == "" {
		return "", false, nil
	}
	hash := hashToken(token)

	var expires string
	err = s.db.QueryRowContext(ctx,
		`SELECT username, expires_at FROM console_sessions WHERE token_hash = ?`,
		hash).Scan(&username, &expires)

	switch {
	case err == sql.ErrNoRows:
		return "", false, nil
	case err != nil:
		return "", false, err
	}

	exp, perr := time.Parse(timeFormat, expires)
	if perr != nil || !time.Now().Before(exp) {
		_, _ = s.db.ExecContext(ctx,
			`DELETE FROM console_sessions WHERE token_hash = ?`, hash)
		return "", false, nil
	}
	return username, true, nil
}

// DeleteSession ends one session — this is what logout does.
func (s *Store) DeleteSession(ctx context.Context, token string) error {
	if token == "" {
		return nil
	}
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM console_sessions WHERE token_hash = ?`, hashToken(token))
	return err
}

// DeleteUserSessions ends every session an operator holds.
func (s *Store) DeleteUserSessions(ctx context.Context, username string) error {
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM console_sessions WHERE username = ?`, username)
	return err
}

// PurgeExpiredSessions clears sessions that have timed out. Expired rows are
// harmless — ResolveSession rejects them — but they accumulate forever
// otherwise.
func (s *Store) PurgeExpiredSessions(ctx context.Context) (int64, error) {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM console_sessions WHERE expires_at <= ?`,
		time.Now().UTC().Format(timeFormat))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// ValidateUsername keeps account names to something that can be typed into a
// login form and read back out of a log line.
func ValidateUsername(name string) error {
	switch {
	case name == "":
		return fmt.Errorf("username is required")
	case len(name) > 64:
		return fmt.Errorf("username is too long (max 64 characters)")
	}
	for _, r := range name {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return fmt.Errorf("username must not contain spaces or control characters")
		}
	}
	return nil
}

// ValidatePassword enforces the length floor. Length is the only rule: the
// composition rules ("one digit, one symbol") push people towards Passw0rd!
// and buy nothing.
func ValidatePassword(password string) error {
	if len([]rune(password)) < MinPasswordLength {
		return fmt.Errorf("password must be at least %d characters", MinPasswordLength)
	}
	return nil
}

// GeneratePassword returns a random password, used when the console bootstraps
// its first account and when an operator would rather not invent one.
func GeneratePassword() (string, error) {
	raw := make([]byte, 18) // 144 bits -> 24 base64 characters
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}
