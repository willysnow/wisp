package console

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/willysnow/wisp/internal/console/store"
)

const (
	testUser     = "operator"
	testPassword = "correct-horse-battery-staple"
)

// get issues a UI request carrying the given cookies.
func get(t *testing.T, srv *Server, path string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequest(http.MethodGet, path, nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	return w
}

func cookieNamed(res *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, c := range res.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// login performs the whole browser dance: fetch the form for a CSRF token,
// then post credentials. It returns the response to the POST.
func login(t *testing.T, srv *Server, username, password string) *httptest.ResponseRecorder {
	t.Helper()

	form := get(t, srv, "/login")
	csrf := cookieNamed(form, csrfCookieName)
	if csrf == nil {
		t.Fatal("login page did not set a CSRF cookie")
	}

	body := url.Values{
		"username":    {username},
		"password":    {password},
		csrfFormField: {csrf.Value},
	}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(body.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(csrf)

	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	return w
}

func newUIServer(t *testing.T) (*Server, *store.Store) {
	t.Helper()

	srv, st := newTestServer(t, "")
	if err := st.CreateUser(context.Background(), testUser, testPassword); err != nil {
		t.Fatalf("create user: %v", err)
	}
	return srv, st
}

// TestUIRequiresLogin is the whole point of this file.
//
// The console holds every credential, prompt, and token the fleet has captured.
// An unauthenticated GET / must never return any of it.
func TestUIRequiresLogin(t *testing.T) {
	srv, st := newUIServer(t)

	if err := st.Insert(context.Background(), sample("sensor-1")); err != nil {
		t.Fatalf("insert: %v", err)
	}

	res := get(t, srv, "/?service=ssh")
	if res.Code != http.StatusSeeOther {
		t.Fatalf("GET / returned %d, want 303 to the login page", res.Code)
	}
	if body := res.Body.String(); strings.Contains(body, "login_password") ||
		strings.Contains(body, "sensor-1") {
		t.Error("the redirect body leaked event data")
	}
	if loc := res.Header().Get("Location"); !strings.HasPrefix(loc, "/login") {
		t.Errorf("Location = %q, want the login page", loc)
	}
}

// TestLoginGrantsAccess covers the happy path end to end.
func TestLoginGrantsAccess(t *testing.T) {
	srv, st := newUIServer(t)
	if err := st.Insert(context.Background(), sample("sensor-1")); err != nil {
		t.Fatalf("insert: %v", err)
	}

	res := login(t, srv, testUser, testPassword)
	if res.Code != http.StatusSeeOther {
		t.Fatalf("login returned %d, want 303", res.Code)
	}
	session := cookieNamed(res, sessionCookieName)
	if session == nil || session.Value == "" {
		t.Fatal("login did not set a session cookie")
	}
	if !session.HttpOnly {
		t.Error("session cookie is not HttpOnly — script on the page could read it")
	}
	if session.SameSite != http.SameSiteLaxMode {
		t.Error("session cookie is not SameSite=Lax")
	}

	page := get(t, srv, "/", session)
	if page.Code != http.StatusOK {
		t.Fatalf("authenticated GET / returned %d, want 200", page.Code)
	}
	if !strings.Contains(page.Body.String(), "sensor-1") {
		t.Error("authenticated page did not render the events")
	}
	if cc := page.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store — the page holds captured passwords", cc)
	}
}

// TestLoginRejectsBadCredentials checks both halves, and that the answer does
// not say which half was wrong.
func TestLoginRejectsBadCredentials(t *testing.T) {
	srv, _ := newUIServer(t)

	for _, tc := range []struct{ name, user, pass string }{
		{"wrong password", testUser, "not-the-password"},
		{"unknown user", "nobody", testPassword},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := login(t, srv, tc.user, tc.pass)
			if res.Code != http.StatusUnauthorized {
				t.Fatalf("login returned %d, want 401", res.Code)
			}
			if c := cookieNamed(res, sessionCookieName); c != nil && c.Value != "" {
				t.Error("a failed login issued a session cookie")
			}
			if !strings.Contains(res.Body.String(), "Incorrect username or password") {
				t.Error("error message named which half was wrong, or was missing")
			}
		})
	}
}

// TestLoginRequiresCSRF: without the double-submit token a third-party page
// could log an operator into an account the attacker controls.
func TestLoginRequiresCSRF(t *testing.T) {
	srv, _ := newUIServer(t)

	body := url.Values{"username": {testUser}, "password": {testPassword}}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(body.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("login without a CSRF token returned %d, want 403", w.Code)
	}
	if c := cookieNamed(w, sessionCookieName); c != nil && c.Value != "" {
		t.Error("a login without a CSRF token issued a session cookie")
	}
}

// TestLogoutEndsSession — a sign-out that leaves the cookie working is theatre.
func TestLogoutEndsSession(t *testing.T) {
	srv, _ := newUIServer(t)

	res := login(t, srv, testUser, testPassword)
	session := cookieNamed(res, sessionCookieName)
	csrf := cookieNamed(get(t, srv, "/", session), csrfCookieName)
	if csrf == nil {
		// The cookie was issued on the login page and the browser still holds
		// it; re-fetch it from there.
		csrf = cookieNamed(get(t, srv, "/login"), csrfCookieName)
	}

	body := url.Values{csrfFormField: {csrf.Value}}
	req := httptest.NewRequest(http.MethodPost, "/logout", strings.NewReader(body.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(session)
	req.AddCookie(csrf)

	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("logout returned %d, want 303", w.Code)
	}

	if page := get(t, srv, "/", session); page.Code != http.StatusSeeOther {
		t.Errorf("the session still worked after logout (GET / returned %d)", page.Code)
	}
}

// TestPasswordChangeEndsSessions covers the case the feature exists for: a
// password is changed because it leaked, and the sessions opened with it must
// not outlive it.
func TestPasswordChangeEndsSessions(t *testing.T) {
	srv, st := newUIServer(t)

	session := cookieNamed(login(t, srv, testUser, testPassword), sessionCookieName)
	if page := get(t, srv, "/", session); page.Code != http.StatusOK {
		t.Fatalf("pre-change GET / returned %d, want 200", page.Code)
	}

	if err := st.SetPassword(context.Background(), testUser, "a-brand-new-password"); err != nil {
		t.Fatalf("set password: %v", err)
	}

	if page := get(t, srv, "/", session); page.Code != http.StatusSeeOther {
		t.Errorf("the old session survived a password change (GET / returned %d)", page.Code)
	}
}

// TestSensorTokenCannotOpenUI and its mirror below are the separation the two
// credential types exist for: a sensor deployed on a hostile segment holds a
// token that can write events and nothing else.
func TestSensorTokenCannotOpenUI(t *testing.T) {
	srv, st := newUIServer(t)

	token, err := st.CreateSensorToken(context.Background(), "sensor-1")
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})

	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusSeeOther {
		t.Errorf("a sensor token opened the UI (GET / returned %d)", w.Code)
	}
}

func TestSessionCannotIngest(t *testing.T) {
	srv, _ := newUIServer(t)

	session := cookieNamed(login(t, srv, testUser, testPassword), sessionCookieName)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/events", strings.NewReader("[]"))
	req.AddCookie(session)

	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("a UI session was accepted by the ingest API (returned %d)", w.Code)
	}
}

// TestLoginLockout keeps the login form from being a password oracle you can
// query at network speed.
func TestLoginLockout(t *testing.T) {
	srv, _ := newUIServer(t)

	for i := 0; i < maxLoginFailures; i++ {
		if code := login(t, srv, testUser, "wrong").Code; code != http.StatusUnauthorized {
			t.Fatalf("attempt %d returned %d, want 401", i+1, code)
		}
	}

	// Locked out, and the correct password does not get you past it either —
	// otherwise the lockout is only a speed bump for the guess that lands.
	if code := login(t, srv, testUser, testPassword).Code; code != http.StatusTooManyRequests {
		t.Errorf("attempt after the limit returned %d, want 429", code)
	}
}

// TestExpiredSessionIsRejected checks the TTL is enforced at use, not only
// swept in the background.
func TestExpiredSessionIsRejected(t *testing.T) {
	srv, st := newUIServer(t)
	ctx := context.Background()

	token, err := st.CreateSession(ctx, testUser, -time.Minute)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	res := get(t, srv, "/", &http.Cookie{Name: sessionCookieName, Value: token})
	if res.Code != http.StatusSeeOther {
		t.Errorf("an expired session was accepted (GET / returned %d)", res.Code)
	}

	if _, ok, err := st.ResolveSession(ctx, token); err != nil || ok {
		t.Errorf("expired session still resolves: ok=%v err=%v", ok, err)
	}
}

// TestNextIsNotAnOpenRedirect: the post-login redirect target comes from the
// URL, so it has to stay on this site.
func TestNextIsNotAnOpenRedirect(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"", "/"},
		{"/?service=ssh", "/?service=ssh"},
		{"//evil.example.com/", "/"},
		{"https://evil.example.com/", "/"},
		{"http:/evil.example.com", "/"},
		{"evil.example.com", "/"},
	} {
		if got := safeNext(tc.in); got != tc.want {
			t.Errorf("safeNext(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestHealthzStaysOpen — a health check behind a login is not a health check.
func TestHealthzStaysOpen(t *testing.T) {
	srv, _ := newUIServer(t)

	if res := get(t, srv, "/healthz"); res.Code != http.StatusOK {
		t.Errorf("GET /healthz returned %d, want 200", res.Code)
	}
}

// newRequest builds a bare GET for tests that only need the parsed URL.
func newRequest(t *testing.T, target string) *http.Request {
	t.Helper()
	return httptest.NewRequest(http.MethodGet, target, nil)
}
