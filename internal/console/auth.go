package console

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Cookie names. Both are prefixed so they cannot collide with anything else
// served from the same host when the console sits under a shared domain.
const (
	sessionCookieName = "wisp_session"
	csrfCookieName    = "wisp_csrf"
	csrfFormField     = "csrf_token"
)

// DefaultSessionTTL is how long a login lasts. Long enough to work a shift
// without re-typing a password, short enough that a forgotten browser session
// on a laptop does not stay valid for a month.
const DefaultSessionTTL = 12 * time.Hour

// CookieMode decides whether cookies are marked Secure.
type CookieMode string

const (
	// CookieAuto sets Secure when the request arrived over TLS, directly or
	// through a proxy that said so. This is the default: it works behind the
	// reverse proxy the console is meant to run behind, and still allows a
	// plain-HTTP session against localhost while you are setting it up.
	CookieAuto CookieMode = "auto"
	// CookieAlways always sets Secure. Correct for any real deployment, and the
	// right answer if a proxy terminates TLS without forwarding the header.
	CookieAlways CookieMode = "always"
	// CookieNever never sets Secure. For local development only.
	CookieNever CookieMode = "never"
)

// Login throttling. Ten wrong passwords in fifteen minutes from one address is
// not a person who forgot theirs.
const (
	maxLoginFailures = 10
	loginLockWindow  = 15 * time.Minute
)

// loginLimiter counts recent failed logins per client address.
//
// It is deliberately not a global counter: an attacker should never be able to
// lock the operator out by failing logins on purpose.
type loginLimiter struct {
	mu       sync.Mutex
	failures map[string]*failureRecord
}

type failureRecord struct {
	count   int
	expires time.Time
}

func newLoginLimiter() *loginLimiter {
	return &loginLimiter{failures: map[string]*failureRecord{}}
}

// allowed reports whether key may attempt a login right now.
func (l *loginLimiter) allowed(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	rec, ok := l.failures[key]
	if !ok || time.Now().After(rec.expires) {
		return true
	}
	return rec.count < maxLoginFailures
}

// fail records a failed attempt.
func (l *loginLimiter) fail(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	rec, ok := l.failures[key]
	if !ok || now.After(rec.expires) {
		rec = &failureRecord{}
		l.failures[key] = rec
	}
	rec.count++
	rec.expires = now.Add(loginLockWindow)

	// Bound the map. A scanner rotating source addresses would otherwise make
	// the console allocate one record per address, forever.
	if len(l.failures) > 4096 {
		for k, r := range l.failures {
			if now.After(r.expires) {
				delete(l.failures, k)
			}
		}
	}
}

// succeed clears the record for key, so one good login ends the lockout.
func (l *loginLimiter) succeed(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.failures, key)
}

// requireLogin wraps a UI handler so it is only reachable with a live session.
func (s *Server) requireLogin(next func(http.ResponseWriter, *http.Request, string)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(sessionCookieName)
		if err != nil {
			s.redirectToLogin(w, r)
			return
		}

		user, ok, err := s.store.ResolveSession(r.Context(), cookie.Value)
		if err != nil {
			http.Error(w, "session lookup failed", http.StatusInternalServerError)
			return
		}
		if !ok {
			// The cookie is stale or forged; clear it so the browser stops
			// sending it on every request from here on.
			s.clearCookie(w, r, sessionCookieName)
			s.redirectToLogin(w, r)
			return
		}

		next(w, r, user)
	}
}

// redirectToLogin sends the browser to the login form, remembering where it was
// headed so a bookmarked filter still works after signing in.
func (s *Server) redirectToLogin(w http.ResponseWriter, r *http.Request) {
	target := "/login"
	if r.Method == http.MethodGet {
		if next := r.URL.RequestURI(); next != "/" {
			target += "?next=" + url.QueryEscape(next)
		}
	}
	http.Redirect(w, r, target, http.StatusSeeOther)
}

type loginPage struct {
	Error string
	Next  string
	CSRF  string
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	next := safeNext(r.FormValue("next"))

	switch r.Method {
	case http.MethodGet:
		// Already signed in: no reason to show the form again.
		if c, err := r.Cookie(sessionCookieName); err == nil {
			if _, ok, _ := s.store.ResolveSession(r.Context(), c.Value); ok {
				http.Redirect(w, r, next, http.StatusSeeOther)
				return
			}
		}
		s.renderLogin(w, r, loginPage{Next: next}, http.StatusOK)

	case http.MethodPost:
		s.processLogin(w, r, next)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) processLogin(w http.ResponseWriter, r *http.Request, next string) {
	if err := r.ParseForm(); err != nil {
		s.renderLogin(w, r, loginPage{Error: "Malformed request.", Next: next},
			http.StatusBadRequest)
		return
	}

	// Login CSRF matters here too: an attacker who can log a browser into an
	// account they control can watch what the operator does next.
	if !s.checkCSRF(r) {
		s.renderLogin(w, r,
			loginPage{Error: "Session expired. Try again.", Next: next},
			http.StatusForbidden)
		return
	}

	client := s.clientKey(r)
	if !s.limiter.allowed(client) {
		s.renderLogin(w, r,
			loginPage{Error: "Too many failed attempts. Wait a few minutes.", Next: next},
			http.StatusTooManyRequests)
		return
	}

	username := strings.TrimSpace(r.PostFormValue("username"))
	password := r.PostFormValue("password")

	ok, err := s.store.VerifyPassword(r.Context(), username, password)
	if err != nil {
		http.Error(w, "login failed", http.StatusInternalServerError)
		return
	}
	if !ok {
		s.limiter.fail(client)
		// One message for both wrong username and wrong password: the login
		// page must not be a way to find out which operators exist.
		s.renderLogin(w, r,
			loginPage{Error: "Incorrect username or password.", Next: next},
			http.StatusUnauthorized)
		return
	}
	s.limiter.succeed(client)

	token, err := s.store.CreateSession(r.Context(), username, s.sessionTTL)
	if err != nil {
		http.Error(w, "login failed", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.secureCookie(r),
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Now().Add(s.sessionTTL),
		MaxAge:   int(s.sessionTTL / time.Second),
	})
	http.Redirect(w, r, next, http.StatusSeeOther)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.checkCSRF(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	if c, err := r.Cookie(sessionCookieName); err == nil {
		if err := s.store.DeleteSession(r.Context(), c.Value); err != nil {
			http.Error(w, "logout failed", http.StatusInternalServerError)
			return
		}
	}
	s.clearCookie(w, r, sessionCookieName)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (s *Server) renderLogin(w http.ResponseWriter, r *http.Request, data loginPage, code int) {
	data.CSRF = s.issueCSRF(w, r)

	s.uiHeaders(w)
	w.WriteHeader(code)
	_ = s.tmpl.ExecuteTemplate(w, "login", data)
}

// uiHeaders are set on every page the UI serves.
//
// no-store is not decoration: these pages contain captured passwords, and a
// shared machine's disk cache is a second copy of them nobody is watching.
func (s *Server) uiHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	// The UI is one self-contained document: no scripts, no external anything.
	// unsafe-inline covers the inlined stylesheet, which is the whole point of
	// shipping the UI inside the binary.
	h.Set("Content-Security-Policy",
		"default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:; "+
			"form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
}

// issueCSRF returns the token to embed in a form, reusing the browser's current
// one so that two tabs do not invalidate each other.
func (s *Server) issueCSRF(w http.ResponseWriter, r *http.Request) string {
	if c, err := r.Cookie(csrfCookieName); err == nil && len(c.Value) >= 16 {
		return c.Value
	}

	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return ""
	}
	token := base64.RawURLEncoding.EncodeToString(raw)

	http.SetCookie(w, &http.Cookie{
		Name:     csrfCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.secureCookie(r),
		SameSite: http.SameSiteLaxMode,
	})
	return token
}

// checkCSRF verifies the double-submit token: a cross-site form can send the
// cookie but cannot read it, so it cannot put a matching value in the body.
func (s *Server) checkCSRF(r *http.Request) bool {
	c, err := r.Cookie(csrfCookieName)
	if err != nil || c.Value == "" {
		return false
	}
	sent := r.PostFormValue(csrfFormField)
	return subtle.ConstantTimeCompare([]byte(c.Value), []byte(sent)) == 1
}

func (s *Server) clearCookie(w http.ResponseWriter, r *http.Request, name string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   s.secureCookie(r),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

func (s *Server) secureCookie(r *http.Request) bool {
	switch s.cookieMode {
	case CookieAlways:
		return true
	case CookieNever:
		return false
	}
	if r.TLS != nil {
		return true
	}
	return s.trustProxy &&
		strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

// clientKey identifies the client for rate limiting.
//
// Behind a reverse proxy every request arrives from the proxy's address, so
// without trustProxy one attacker would lock out the whole team. X-Forwarded-For
// is only believed when the operator has said a proxy is in front — otherwise
// it is an attacker-controlled header and any limit built on it is decorative.
func (s *Server) clientKey(r *http.Request) string {
	if s.trustProxy {
		if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
			if first, _, ok := strings.Cut(fwd, ","); ok {
				return strings.TrimSpace(first)
			}
			return strings.TrimSpace(fwd)
		}
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

// safeNext keeps post-login redirects on this site. An open redirect on a login
// page is how a phishing link gets to wear your console's domain.
func safeNext(next string) string {
	if next == "" || !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") {
		return "/"
	}
	if u, err := url.Parse(next); err != nil || u.Host != "" || u.Scheme != "" {
		return "/"
	}
	return next
}
