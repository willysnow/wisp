package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// The container image has no shell, so this subcommand is the only thing an
// orchestrator can use to decide whether the console is alive. It is worth
// testing for the same reason: nothing else will notice if it starts lying.
func TestHealthcheck(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/healthz":
			_, _ = w.Write([]byte("ok"))
		case "/redirect":
			// What every UI path answers to a signed-out request.
			http.Redirect(w, r, "/login", http.StatusSeeOther)
		default:
			http.Error(w, "boom", http.StatusInternalServerError)
		}
	}))
	defer srv.Close()

	for _, tc := range []struct {
		name string
		url  string
		want int
	}{
		{"healthy", srv.URL + "/healthz", 0},
		{"server error", srv.URL + "/broken", 1},
		{"redirect is not healthy", srv.URL + "/redirect", 1},
		{"nothing listening", "http://127.0.0.1:1/healthz", 1},
		{"malformed url", "://nope", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := runHealthcheck([]string{"-url", tc.url, "-timeout", "5s"})
			if got != tc.want {
				t.Errorf("runHealthcheck(%q) = %d, want %d", tc.url, got, tc.want)
			}
		})
	}
}
