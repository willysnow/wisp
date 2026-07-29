package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/willysnow/wisp/internal/event"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	st, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func tokenTriggerEvent(srcIP string) event.Event {
	return event.Event{
		Time:    time.Now().UTC(),
		Node:    "console",
		Service: "token",
		Kind:    "token_triggered",
		SrcIP:   srcIP,
		Data:    map[string]any{"via": "http"},
	}
}

func TestCreateAndGetToken(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	tok, err := st.CreateToken(ctx, "docx", "finance share", "admin")
	if err != nil {
		t.Fatalf("CreateToken: %v", err)
	}
	if tok.ID == "" {
		t.Fatal("CreateToken returned an empty id")
	}
	// The id has to fit in a single DNS label, since a DNS token lives in one.
	if len(tok.ID) > 63 {
		t.Errorf("token id is %d chars, too long for a DNS label", len(tok.ID))
	}

	got, found, err := st.GetToken(ctx, tok.ID)
	if err != nil || !found {
		t.Fatalf("GetToken = (%v, %v), want (found, nil)", found, err)
	}
	if got.Kind != "docx" || got.Memo != "finance share" || got.CreatedBy != "admin" {
		t.Errorf("GetToken = %+v, fields do not round-trip", got)
	}
	if got.Triggered() {
		t.Error("a fresh token reports as triggered")
	}
}

// TestRecordTokenTrigger is the property the whole service turns on: a firing
// both increments the token's tally and lands in the events table, enriched
// with what the operator needs to read it — and it does not invent a sensor.
func TestRecordTokenTrigger(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	tok, err := st.CreateToken(ctx, "docx", "finance share", "")
	if err != nil {
		t.Fatalf("CreateToken: %v", err)
	}

	got, ok, err := st.RecordTokenTrigger(ctx, tok.ID, tokenTriggerEvent("203.0.113.7"))
	if err != nil || !ok {
		t.Fatalf("RecordTokenTrigger = (%v, %v), want (true, nil)", ok, err)
	}
	if got.TriggerCount != 1 {
		t.Errorf("returned TriggerCount = %d, want 1", got.TriggerCount)
	}
	if got.LastTriggered.IsZero() {
		t.Error("LastTriggered not set on the returned token")
	}

	// The firing is in the timeline, enriched from the token's own record.
	events, err := st.List(ctx, Filter{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("stored %d events, want 1", len(events))
	}
	e := events[0]
	if e.Service != "token" || e.Kind != "token_triggered" || e.SrcIP != "203.0.113.7" {
		t.Errorf("stored event = %+v, wrong shape", e)
	}
	if e.Data["token"] != tok.ID {
		t.Errorf("event data token = %v, want %q", e.Data["token"], tok.ID)
	}
	if e.Data["token_kind"] != "docx" {
		t.Errorf("event data token_kind = %v, want docx", e.Data["token_kind"])
	}
	if e.Data["memo"] != "finance share" {
		t.Errorf("event data memo = %v, want finance share", e.Data["memo"])
	}
	if e.Data["via"] != "http" {
		t.Errorf("event data via = %v, want http — caller data was dropped", e.Data["via"])
	}

	// A token has no sensor behind it. If a hit created a sensor row, the
	// silence watcher would start watching a machine that never existed.
	sensors, err := st.Sensors(ctx)
	if err != nil {
		t.Fatalf("Sensors: %v", err)
	}
	if len(sensors) != 0 {
		t.Errorf("a token hit created %d phantom sensor(s)", len(sensors))
	}

	// A second hit accumulates rather than resetting.
	got2, ok, err := st.RecordTokenTrigger(ctx, tok.ID, tokenTriggerEvent("203.0.113.8"))
	if err != nil || !ok {
		t.Fatalf("second RecordTokenTrigger = (%v, %v)", ok, err)
	}
	if got2.TriggerCount != 2 {
		t.Errorf("TriggerCount after two hits = %d, want 2", got2.TriggerCount)
	}
}

// TestRecordUnknownTokenIsIgnored keeps the callback endpoint from being a way
// to fill the database: a guessed or stale id records nothing.
func TestRecordUnknownTokenIsIgnored(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	_, ok, err := st.RecordTokenTrigger(ctx, "nosuchtoken", tokenTriggerEvent("203.0.113.7"))
	if err != nil {
		t.Fatalf("RecordTokenTrigger(unknown): %v", err)
	}
	if ok {
		t.Error("an unknown token id was recorded as a hit")
	}

	events, err := st.List(ctx, Filter{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(events) != 0 {
		t.Errorf("an unknown token id wrote %d events", len(events))
	}
}

// TestDisabledTokenStopsRecording checks disable actually disables: past
// firings stay, new ones are dropped.
func TestDisabledTokenStopsRecording(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	tok, err := st.CreateToken(ctx, "http", "", "")
	if err != nil {
		t.Fatalf("CreateToken: %v", err)
	}

	disabled, err := st.DisableToken(ctx, tok.ID)
	if err != nil || !disabled {
		t.Fatalf("DisableToken = (%v, %v), want (true, nil)", disabled, err)
	}
	// Disabling again reports nothing changed.
	if again, _ := st.DisableToken(ctx, tok.ID); again {
		t.Error("DisableToken on an already-disabled token reported a change")
	}

	_, ok, err := st.RecordTokenTrigger(ctx, tok.ID, tokenTriggerEvent("203.0.113.7"))
	if err != nil {
		t.Fatalf("RecordTokenTrigger: %v", err)
	}
	if ok {
		t.Error("a disabled token still recorded a hit")
	}

	got, _, _ := st.GetToken(ctx, tok.ID)
	if !got.Disabled {
		t.Error("GetToken does not report the token as disabled")
	}
}

func TestListTokensNewestFirst(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	first, _ := st.CreateToken(ctx, "http", "one", "")
	time.Sleep(2 * time.Millisecond) // distinct created_at
	second, _ := st.CreateToken(ctx, "dns", "two", "")

	tokens, err := st.ListTokens(ctx)
	if err != nil {
		t.Fatalf("ListTokens: %v", err)
	}
	if len(tokens) != 2 {
		t.Fatalf("ListTokens returned %d, want 2", len(tokens))
	}
	if tokens[0].ID != second.ID || tokens[1].ID != first.ID {
		t.Errorf("ListTokens not newest-first: got %s then %s", tokens[0].ID, tokens[1].ID)
	}
}

// TestTokenLookupIsCaseInsensitive matters because DNS is case-insensitive and
// some resolvers randomise case in the query (0x20 encoding): the id that comes
// back in a callback may not match the stored casing.
func TestTokenLookupIsCaseInsensitive(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	tok, _ := st.CreateToken(ctx, "dns", "", "")
	upper := ""
	for _, r := range tok.ID {
		if r >= 'a' && r <= 'z' {
			upper += string(r - 32)
		} else {
			upper += string(r)
		}
	}

	_, ok, err := st.RecordTokenTrigger(ctx, upper, tokenTriggerEvent("203.0.113.7"))
	if err != nil {
		t.Fatalf("RecordTokenTrigger: %v", err)
	}
	if !ok {
		t.Errorf("an upper-cased token id (%s) did not resolve to the stored token", upper)
	}
}
