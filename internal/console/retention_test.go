package console

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/willysnow/wisp/internal/console/store"
	"github.com/willysnow/wisp/internal/event"
)

func newTestStore(t *testing.T) *store.Store {
	t.Helper()

	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

// insertAged writes n events, the i-th one aged by ages[i].
func insertAged(t *testing.T, st *store.Store, ages ...time.Duration) {
	t.Helper()

	events := make([]event.Event, 0, len(ages))
	for i, age := range ages {
		events = append(events, event.Event{
			Time:    time.Now().Add(-age),
			Node:    "sensor-1",
			Service: "ssh",
			Kind:    "login_password",
			SrcIP:   fmt.Sprintf("10.0.0.%d", i%250),
			Data:    map[string]any{"username": "root"},
		})
	}
	if err := st.Insert(context.Background(), events); err != nil {
		t.Fatalf("insert: %v", err)
	}
}

func countEvents(t *testing.T, st *store.Store) int64 {
	t.Helper()

	n, err := st.CountEvents(context.Background())
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	return n
}

// TestRetentionByAge is the policy most operators will set: keep a month.
func TestRetentionByAge(t *testing.T) {
	st := newTestStore(t)
	insertAged(t, st, 48*time.Hour, 36*time.Hour, 2*time.Hour, time.Minute)

	sweep, err := NewJanitor(st, Retention{MaxAge: 24 * time.Hour}, nil).
		Sweep(context.Background())
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}

	if sweep.ByAge != 2 {
		t.Errorf("removed %d events by age, want 2", sweep.ByAge)
	}
	if n := countEvents(t, st); n != 2 {
		t.Errorf("%d events remain, want 2", n)
	}
}

// TestRetentionByCount is the backstop age cannot provide: one sensor under a
// scan produces a month of events in an afternoon, and the console's disk is
// not the attacker's to fill.
func TestRetentionByCount(t *testing.T) {
	st := newTestStore(t)

	ages := make([]time.Duration, 50)
	for i := range ages {
		ages[i] = time.Duration(50-i) * time.Minute
	}
	insertAged(t, st, ages...)

	sweep, err := NewJanitor(st, Retention{MaxEvents: 10}, nil).Sweep(context.Background())
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}

	if sweep.ByCount != 40 {
		t.Errorf("removed %d events by count, want 40", sweep.ByCount)
	}
	if n := countEvents(t, st); n != 10 {
		t.Errorf("%d events remain, want 10", n)
	}

	// The newest are the ones kept: history is dropped from the far end, never
	// from the end an operator is looking at.
	events, err := st.List(context.Background(), store.Filter{Limit: 100})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	cutoff := time.Now().Add(-11 * time.Minute)
	for _, e := range events {
		if e.Time.Before(cutoff) {
			t.Fatalf("kept an event from %s — trimming dropped the wrong end", e.Time)
		}
	}
}

// TestRetentionDisabledKeepsEverything: an unset policy must not quietly
// discard an operator's evidence.
func TestRetentionDisabledKeepsEverything(t *testing.T) {
	st := newTestStore(t)
	insertAged(t, st, 3000*time.Hour, time.Minute)

	policy := Retention{}
	if policy.Enabled() {
		t.Fatal("the zero policy reports itself enabled")
	}

	sweep, err := NewJanitor(st, policy, nil).Sweep(context.Background())
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if sweep.Events() != 0 {
		t.Errorf("removed %d events with no policy set, want 0", sweep.Events())
	}
	if n := countEvents(t, st); n != 2 {
		t.Errorf("%d events remain, want 2", n)
	}
}

// TestSweepPurgesExpiredSessions — housekeeping runs even with no event policy.
func TestSweepPurgesExpiredSessions(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	if err := st.CreateUser(ctx, testUser, testPassword); err != nil {
		t.Fatalf("create user: %v", err)
	}
	if _, err := st.CreateSession(ctx, testUser, -time.Minute); err != nil {
		t.Fatalf("create session: %v", err)
	}
	live, err := st.CreateSession(ctx, testUser, time.Hour)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	sweep, err := NewJanitor(st, Retention{}, nil).Sweep(ctx)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if sweep.Sessions != 1 {
		t.Errorf("purged %d sessions, want 1", sweep.Sessions)
	}
	if _, ok, err := st.ResolveSession(ctx, live); err != nil || !ok {
		t.Errorf("the live session was purged too: ok=%v err=%v", ok, err)
	}
}

// TestParseDuration covers the days-and-weeks extension. Retention is written
// in days by everyone who writes a retention policy.
func TestParseDuration(t *testing.T) {
	for _, tc := range []struct {
		in      string
		want    time.Duration
		wantErr bool
	}{
		{in: "30d", want: 30 * 24 * time.Hour},
		{in: "2w", want: 14 * 24 * time.Hour},
		{in: "720h", want: 720 * time.Hour},
		{in: "15m", want: 15 * time.Minute},
		{in: "0d", want: 0},
		{in: "d", wantErr: true},
		{in: "thirty days", wantErr: true},
		{in: "", wantErr: true},
	} {
		got, err := ParseDuration(tc.in)
		switch {
		case tc.wantErr && err == nil:
			t.Errorf("ParseDuration(%q) = %v, want an error", tc.in, got)
		case !tc.wantErr && err != nil:
			t.Errorf("ParseDuration(%q) failed: %v", tc.in, err)
		case !tc.wantErr && got != tc.want:
			t.Errorf("ParseDuration(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}
