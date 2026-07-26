package console

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/willysnow/wisp/internal/console/store"
	"github.com/willysnow/wisp/internal/event"
)

func newTestServer(t *testing.T, sharedToken string) (*Server, *store.Store) {
	t.Helper()

	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	srv, err := New(st, Options{IngestToken: sharedToken})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	return srv, st
}

// post delivers a batch the way a sensor would.
func post(t *testing.T, srv *Server, token string, events []event.Event) int {
	t.Helper()

	body, err := json.Marshal(events)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/events", bytes.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	return w.Code
}

func sample(node string) []event.Event {
	return []event.Event{{
		Time:    time.Now(),
		Node:    node,
		Service: "ssh",
		Kind:    "login_password",
		SrcIP:   "10.0.0.5",
		Data:    map[string]any{"username": "root"},
	}}
}

// TestPerSensorTokenStampsNode is the property per-sensor tokens exist for.
//
// A sensor's identity must come from its credential, not from the body it
// sends. Without this, one compromised sensor can attribute events to any
// other, and an operator chasing an alert investigates the wrong machine.
func TestPerSensorTokenStampsNode(t *testing.T) {
	srv, st := newTestServer(t, "")
	ctx := context.Background()

	token, err := st.CreateSensorToken(ctx, "sensor-real")
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}

	// The payload lies about which sensor it came from.
	if code := post(t, srv, token, sample("sensor-impersonated")); code != http.StatusOK {
		t.Fatalf("ingest returned %d, want 200", code)
	}

	events, err := st.List(ctx, store.Filter{})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("stored %d events, want 1", len(events))
	}
	if events[0].Node != "sensor-real" {
		t.Errorf("Node = %q, want %q — the payload's claim overrode the token",
			events[0].Node, "sensor-real")
	}
}

// TestRevokedTokenIsRejected covers the operational half: revoking has to
// actually stop deliveries, or it is decoration.
func TestRevokedTokenIsRejected(t *testing.T) {
	srv, st := newTestServer(t, "")
	ctx := context.Background()

	token, err := st.CreateSensorToken(ctx, "sensor-1")
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	if code := post(t, srv, token, sample("sensor-1")); code != http.StatusOK {
		t.Fatalf("pre-revoke ingest returned %d, want 200", code)
	}

	revoked, err := st.RevokeSensor(ctx, "sensor-1")
	if err != nil || !revoked {
		t.Fatalf("revoke = (%v, %v), want (true, nil)", revoked, err)
	}

	if code := post(t, srv, token, sample("sensor-1")); code != http.StatusUnauthorized {
		t.Errorf("post-revoke ingest returned %d, want 401", code)
	}
}

// TestReenrollInvalidatesOldToken checks that rotation actually rotates.
func TestReenrollInvalidatesOldToken(t *testing.T) {
	srv, st := newTestServer(t, "")
	ctx := context.Background()

	old, err := st.CreateSensorToken(ctx, "sensor-1")
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	fresh, err := st.CreateSensorToken(ctx, "sensor-1")
	if err != nil {
		t.Fatalf("re-enroll: %v", err)
	}
	if old == fresh {
		t.Fatal("re-enrolling returned the same token")
	}

	if code := post(t, srv, old, sample("sensor-1")); code != http.StatusUnauthorized {
		t.Errorf("old token returned %d, want 401", code)
	}
	if code := post(t, srv, fresh, sample("sensor-1")); code != http.StatusOK {
		t.Errorf("new token returned %d, want 200", code)
	}
}

// TestBadTokensRejected covers the obvious ways in.
func TestBadTokensRejected(t *testing.T) {
	srv, st := newTestServer(t, "")
	if _, err := st.CreateSensorToken(context.Background(), "sensor-1"); err != nil {
		t.Fatalf("enroll: %v", err)
	}

	for _, tc := range []struct{ name, token string }{
		{"empty", ""},
		{"wrong", "wisp_totally-made-up-value"},
		{"prefix only", "wisp_"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if code := post(t, srv, tc.token, sample("sensor-1")); code != http.StatusUnauthorized {
				t.Errorf("returned %d, want 401", code)
			}
		})
	}
}

// TestSharedTokenLeavesNodeAlone documents the legacy path: it authenticates
// but names nobody, so the payload's claim stands. This is exactly why the
// console warns about it at startup.
func TestSharedTokenLeavesNodeAlone(t *testing.T) {
	srv, st := newTestServer(t, "shared-secret")

	if code := post(t, srv, "shared-secret", sample("whatever-it-claims")); code != http.StatusOK {
		t.Fatalf("ingest returned %d, want 200", code)
	}

	events, err := st.List(context.Background(), store.Filter{})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(events) != 1 || events[0].Node != "whatever-it-claims" {
		t.Errorf("shared-token path did not preserve the payload node")
	}
}
