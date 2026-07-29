package console

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/willysnow/wisp/internal/console/store"
	"github.com/willysnow/wisp/internal/token"
)

// getToken drives a token callback the way an intruder's client would.
func getToken(t *testing.T, srv *Server, path, userAgent string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if userAgent != "" {
		req.Header.Set("User-Agent", userAgent)
	}
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	return w
}

// TestTokenCallbackRecordsHit is the core property: fetching a live token's URL
// records a token_triggered event and answers with the pixel, so a document's
// linked image resolves and shows nothing.
func TestTokenCallbackRecordsHit(t *testing.T) {
	srv, st := newTestServer(t, "")
	ctx := context.Background()

	tok, err := st.CreateToken(ctx, "docx", "finance share", "")
	if err != nil {
		t.Fatalf("CreateToken: %v", err)
	}

	w := getToken(t, srv, "/t/"+tok.ID, "curl/8.0")
	if w.Code != http.StatusOK {
		t.Fatalf("callback returned %d, want 200", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "image/gif" {
		t.Errorf("Content-Type = %q, want image/gif", ct)
	}
	if !bytesHasGIF(w.Body.Bytes()) {
		t.Errorf("callback body is not a GIF")
	}

	events, err := st.List(ctx, store.Filter{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("stored %d events, want 1", len(events))
	}
	e := events[0]
	if e.Service != TokenService || e.Kind != KindTokenTriggered {
		t.Errorf("event = %s/%s, want %s/%s", e.Service, e.Kind, TokenService, KindTokenTriggered)
	}
	if e.Data["user_agent"] != "curl/8.0" {
		t.Errorf("user_agent = %v, want curl/8.0", e.Data["user_agent"])
	}
	if e.Data["via"] != "http" {
		t.Errorf("via = %v, want http", e.Data["via"])
	}

	got, _, _ := st.GetToken(ctx, tok.ID)
	if got.TriggerCount != 1 {
		t.Errorf("token TriggerCount = %d, want 1", got.TriggerCount)
	}
}

// TestTokenCallbackSubpathFires covers the kubeconfig and MCP kinds: their
// clients append their own path (/api, /sse) to the token URL, and the token
// must fire all the same.
func TestTokenCallbackSubpathFires(t *testing.T) {
	srv, st := newTestServer(t, "")
	ctx := context.Background()

	tok, _ := st.CreateToken(ctx, "kubeconfig", "", "")

	w := getToken(t, srv, "/t/"+tok.ID+"/api?timeout=32s", "kubectl/v1.29")
	if w.Code != http.StatusOK {
		t.Fatalf("subpath callback returned %d, want 200", w.Code)
	}
	got, _, _ := st.GetToken(ctx, tok.ID)
	if got.TriggerCount != 1 {
		t.Errorf("subpath callback did not fire the token (count %d)", got.TriggerCount)
	}
}

// TestUnknownTokenIs404 keeps the console from being a generic pixel host and
// from recording guessed ids.
func TestUnknownTokenIs404(t *testing.T) {
	srv, st := newTestServer(t, "")

	w := getToken(t, srv, "/t/doesnotexist", "")
	if w.Code != http.StatusNotFound {
		t.Errorf("unknown token returned %d, want 404", w.Code)
	}

	events, _ := st.List(context.Background(), store.Filter{})
	if len(events) != 0 {
		t.Errorf("unknown token wrote %d events", len(events))
	}
}

// TestDisabledTokenIs404 checks a disabled token neither records nor answers as
// if live.
func TestDisabledTokenIs404(t *testing.T) {
	srv, st := newTestServer(t, "")
	ctx := context.Background()

	tok, _ := st.CreateToken(ctx, "http", "", "")
	if _, err := st.DisableToken(ctx, tok.ID); err != nil {
		t.Fatalf("DisableToken: %v", err)
	}

	w := getToken(t, srv, "/t/"+tok.ID, "")
	if w.Code != http.StatusNotFound {
		t.Errorf("disabled token returned %d, want 404", w.Code)
	}
}

// TestTokensPageRequiresLogin keeps the monitoring view behind the same login
// as the rest of the UI — it lists memos that say where lures are planted.
func TestTokensPageRequiresLogin(t *testing.T) {
	srv, _ := newTestServer(t, "")

	req := httptest.NewRequest(http.MethodGet, "/tokens", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("/tokens without a session returned %d, want 303", w.Code)
	}
	if loc := w.Header().Get("Location"); loc == "" || loc[:6] != "/login" {
		t.Errorf("redirect Location = %q, want the login page", loc)
	}
}

func TestTokenIDFromPath(t *testing.T) {
	cases := map[string]string{
		"/t/abc123":            "abc123",
		"/t/abc123/api":        "abc123",
		"/t/abc123/sse":        "abc123",
		"/t/abc123.gif":        "abc123",
		"/t/ABC123":            "abc123", // lowercased for lookup
		"/t/":                  "",
		"/t":                   "",
		"/other":               "",
		"/t/abc123/deep/path/": "abc123",
	}
	for path, want := range cases {
		if got := tokenIDFromPath(path); got != want {
			t.Errorf("tokenIDFromPath(%q) = %q, want %q", path, got, want)
		}
	}
}

// TestTokensPageRenders exercises the template end to end — both the "never
// fired" and "triggered" rows, and the locator column — because a template that
// parses can still fail on a missing field or method at render time.
func TestTokensPageRenders(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	ctx := context.Background()
	if err := st.CreateUser(ctx, testUser, testPassword); err != nil {
		t.Fatalf("create user: %v", err)
	}

	srv, err := New(st, Options{TokenConfig: token.Config{
		BaseURL: "https://console.example.com",
		DNSZone: "tokens.example.com",
	}})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	httpTok, _ := st.CreateToken(ctx, "http", "wiki page", "")
	dnsTok, _ := st.CreateToken(ctx, "dns", "allowlist entry", "")

	// Fire the HTTP token once so the "triggered" branch of the row renders.
	getToken(t, srv, "/t/"+httpTok.ID, "curl/8.0")

	session := cookieNamed(login(t, srv, testUser, testPassword), sessionCookieName)
	res := get(t, srv, "/tokens", session)
	if res.Code != http.StatusOK {
		t.Fatalf("/tokens returned %d, want 200", res.Code)
	}
	body := res.Body.String()

	for _, want := range []string{
		httpTok.ID,
		dnsTok.ID,
		"https://console.example.com/t/" + httpTok.ID, // http locator
		dnsTok.ID + ".tokens.example.com",             // dns locator
		"wiki page",                                   // memo
	} {
		if !strings.Contains(body, want) {
			t.Errorf("tokens page is missing %q", want)
		}
	}
}

func bytesHasGIF(b []byte) bool {
	return len(b) >= 6 && string(b[:6]) == "GIF89a"
}
