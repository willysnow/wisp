// Package console is the self-hosted aggregation server.
//
// It does the one thing a fleet of sensors cannot do for itself: put every
// alert in one place. Sensors deliver over HTTPS with a bearer token; the
// console stores, lists, and (later) notifies.
//
// It is deliberately self-hostable with no dependencies beyond a file on disk,
// because the sensor's whole pitch is "one binary, no setup" and a console that
// needed Postgres and Redis would undo that.
package console

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/willysnow/wisp/internal/console/notify"
	"github.com/willysnow/wisp/internal/console/store"
	"github.com/willysnow/wisp/internal/event"
	"github.com/willysnow/wisp/internal/token"
)

// maxBatch bounds one delivery. Sensors batch events; a single request should
// never be able to make the console allocate without limit.
const maxBatch = 4 << 20 // 4 MiB

// Server serves both the ingest API and the operator UI.
type Server struct {
	store    *store.Store
	token    string
	tmpl     *template.Template
	dispatch *notify.Dispatcher

	sessionTTL time.Duration
	cookieMode CookieMode
	trustProxy bool
	limiter    *loginLimiter

	// silenceAfter is the threshold the UI uses to mark a sensor as quiet. It
	// mirrors the watcher's policy so the page and the alerts agree.
	silenceAfter time.Duration

	// tokenCfg tells the UI where the console can be reached, so it can show the
	// URL or hostname to plant for each token. The callback endpoint itself does
	// not need it — a firing token carries its own id.
	tokenCfg token.Config
}

// Options configures the server. The zero value is usable: it means no
// notifications, no shared ingest token, and default session handling.
type Options struct {
	// IngestToken is the legacy shared token. Empty means per-sensor tokens
	// only, which is the supported path.
	IngestToken string

	// Dispatch may be nil, in which case the console is a pure aggregator with
	// no notifications.
	Dispatch *notify.Dispatcher

	// SessionTTL is how long a UI login lasts. Zero means DefaultSessionTTL.
	SessionTTL time.Duration

	// CookieMode decides when cookies are marked Secure. Empty means CookieAuto.
	CookieMode CookieMode

	// TrustProxy makes the console believe X-Forwarded-For and
	// X-Forwarded-Proto. Only set this when a reverse proxy you control is in
	// front — otherwise the headers are attacker-controlled.
	TrustProxy bool

	// SilenceAfter is how long a sensor may be quiet before the UI marks it.
	// Zero leaves sensors unmarked, matching a console with no silence policy.
	SilenceAfter time.Duration

	// TokenConfig is where this console can be reached, used to render the
	// locator to plant for each token. The zero value is fine — the tokens page
	// then explains that tokens.base_url has to be set before it can show one.
	TokenConfig token.Config
}

// New builds the server.
func New(st *store.Store, opts Options) (*Server, error) {
	funcs := template.FuncMap{
		"ago":      humanAgo,
		"kv":       sortedPairs,
		"shortval": shortValue,
		// The UI's highlighting comes from the same list the notifier and the
		// sensor's rate limiter use, so a new event kind is emphasised
		// everywhere at once rather than in whichever place someone remembered.
		"highvalue":  event.IsHighValue,
		"credential": isCredentialKind,
	}

	tmpl := template.New("console").Funcs(funcs)
	for _, page := range []struct{ name, body string }{
		{"index", indexHTML},
		{"login", loginHTML},
		{"tokens", tokensHTML},
	} {
		if _, err := tmpl.New(page.name).Parse(page.body); err != nil {
			return nil, err
		}
	}

	if opts.SessionTTL <= 0 {
		opts.SessionTTL = DefaultSessionTTL
	}
	if opts.CookieMode == "" {
		opts.CookieMode = CookieAuto
	}

	return &Server{
		store:        st,
		token:        opts.IngestToken,
		tmpl:         tmpl,
		dispatch:     opts.Dispatch,
		sessionTTL:   opts.SessionTTL,
		cookieMode:   opts.CookieMode,
		trustProxy:   opts.TrustProxy,
		limiter:      newLoginLimiter(),
		silenceAfter: opts.SilenceAfter,
		tokenCfg:     opts.TokenConfig,
	}, nil
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// Sensors authenticate with a bearer token, not a session: an ingest
	// credential must never be able to open the UI, and the reverse.
	mux.HandleFunc("/api/v1/events", s.handleIngest)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})

	// Token callbacks are public by construction: an intruder trips them, and an
	// intruder has no session. Everything they carry is treated as untrusted and
	// only recorded, never acted on.
	mux.HandleFunc("/t/", s.handleTokenTrigger)

	mux.HandleFunc("/login", s.handleLogin)
	mux.HandleFunc("/logout", s.handleLogout)
	mux.HandleFunc("/tokens", s.requireLogin(s.handleTokens))
	mux.HandleFunc("/export.csv", s.requireLogin(s.handleExport))
	mux.HandleFunc("/export.json", s.requireLogin(s.handleExport))
	mux.HandleFunc("/", s.requireLogin(s.handleIndex))
	return mux
}

// handleIngest accepts a batch of events from a sensor.
func (s *Server) handleIngest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	node, ok := s.authenticate(ctx, r)
	if !ok {
		// No detail in the response: an attacker who finds the console should
		// not learn whether the token was close, or whether a node exists.
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxBatch)
	var events []event.Event
	if err := json.NewDecoder(r.Body).Decode(&events); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	// With a per-sensor token the node comes from the credential, overriding
	// whatever the payload claimed. Otherwise one compromised sensor could
	// forge events attributed to another — and an operator chasing an alert
	// would be looking at the wrong machine.
	if node != "" {
		for i := range events {
			events[i].Node = node
		}
	}

	if err := s.store.Insert(ctx, events); err != nil {
		http.Error(w, "storage error", http.StatusInternalServerError)
		return
	}

	// Notify after the events are durably stored, and without blocking the
	// response: a sensor waiting on an SMTP handshake will time out and retry
	// events it has already delivered.
	if s.dispatch != nil {
		s.dispatch.Handle(events)
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"accepted": len(events)})
}

// authenticate validates the bearer token and returns the node it identifies.
//
// A per-sensor token names its node. The legacy shared token authenticates but
// names nobody, so it returns an empty node and the payload's own claim stands.
func (s *Server) authenticate(ctx context.Context, r *http.Request) (node string, ok bool) {
	const prefix = "Bearer "
	got := r.Header.Get("Authorization")
	if len(got) <= len(prefix) {
		return "", false
	}
	presented := got[len(prefix):]

	// Per-sensor tokens are looked up by hash. The lookup is not
	// constant-time, but the token is 256 bits of entropy and only its SHA-256
	// reaches the database, so there is nothing to walk byte by byte.
	if node, found, err := s.store.ResolveToken(ctx, presented); err == nil && found {
		return node, true
	}

	// Shared token: compared in constant time, since it is compared directly.
	if s.token != "" &&
		subtle.ConstantTimeCompare([]byte(presented), []byte(s.token)) == 1 {
		return "", true
	}

	return "", false
}

// pageSize is one screen of events. Small enough to render fast on a console
// that may be behind a slow link, large enough that scrolling is usually
// enough to find what you came for.
const pageSize = 100

type pageData struct {
	Events  []store.Record
	Sensors []sensorView
	Counts  []countRow
	Filter  store.Filter
	Total   int64
	Since   string
	Hours   int
	Now     time.Time
	User    string
	CSRF    string

	// Matched is how many events the current filter selects, across all pages.
	Matched int64
	Page    int
	Pages   int
	PrevURL string
	NextURL string

	// ExportCSV and ExportJSON carry the current filter, so a download is what
	// the operator is looking at rather than everything.
	ExportCSV  string
	ExportJSON string

	// Filtered says whether anything narrows the view, which decides whether
	// the "clear" control is worth showing.
	Filtered bool
}

// sensorView is a sensor plus what the console has concluded about it.
type sensorView struct {
	store.Sensor
	// Silent means it has not reported within the configured threshold. This
	// is the one thing on the page that is interesting because nothing
	// happened.
	Silent bool
}

type countRow struct {
	Service string
	Count   int64
}

// filterFrom reads the query parameters shared by the page and the exports, so
// a download can never disagree with the screen it was started from.
func (s *Server) filterFrom(r *http.Request) (store.Filter, time.Duration) {
	q := r.URL.Query()

	window := 24 * time.Hour
	if h, err := strconv.Atoi(q.Get("hours")); err == nil && h > 0 && h <= 24*90 {
		window = time.Duration(h) * time.Hour
	}

	page := 1
	if p, err := strconv.Atoi(q.Get("page")); err == nil && p > 1 {
		page = p
	}

	return store.Filter{
		Node:    q.Get("node"),
		Service: q.Get("service"),
		Kind:    q.Get("kind"),
		SrcIP:   q.Get("src_ip"),
		Query:   strings.TrimSpace(q.Get("q")),
		Since:   time.Now().Add(-window),
		Limit:   pageSize,
		Offset:  (page - 1) * pageSize,
	}, window
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request, user string) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	ctx := r.Context()

	filter, window := s.filterFrom(r)
	page := filter.Offset/pageSize + 1

	events, err := s.store.List(ctx, filter)
	if err != nil {
		http.Error(w, "query failed", http.StatusInternalServerError)
		return
	}
	matched, err := s.store.Count(ctx, filter)
	if err != nil {
		http.Error(w, "query failed", http.StatusInternalServerError)
		return
	}
	sensors, err := s.store.Sensors(ctx)
	if err != nil {
		http.Error(w, "query failed", http.StatusInternalServerError)
		return
	}
	counts, err := s.store.Counts(ctx, filter.Since)
	if err != nil {
		http.Error(w, "query failed", http.StatusInternalServerError)
		return
	}

	rows := make([]countRow, 0, len(counts))
	var total int64
	for svc, n := range counts {
		rows = append(rows, countRow{Service: svc, Count: n})
		total += n
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Count > rows[j].Count })

	pages := int((matched + pageSize - 1) / pageSize)
	if pages == 0 {
		pages = 1
	}

	data := pageData{
		Events:     events,
		Sensors:    s.sensorViews(sensors),
		Counts:     rows,
		Filter:     filter,
		Total:      total,
		Since:      window.String(),
		Hours:      int(window.Hours()),
		Now:        time.Now(),
		User:       user,
		CSRF:       s.issueCSRF(w, r),
		Matched:    matched,
		Page:       page,
		Pages:      pages,
		ExportCSV:  withParams(r, "/export.csv", "page", ""),
		ExportJSON: withParams(r, "/export.json", "page", ""),
		Filtered: filter.Node != "" || filter.Service != "" || filter.Kind != "" ||
			filter.SrcIP != "" || filter.Query != "",
	}
	if page > 1 {
		data.PrevURL = withParams(r, "/", "page", strconv.Itoa(page-1))
	}
	if page < pages {
		data.NextURL = withParams(r, "/", "page", strconv.Itoa(page+1))
	}

	s.uiHeaders(w)
	if err := s.tmpl.ExecuteTemplate(w, "index", data); err != nil {
		// Headers are already written by this point; log-and-continue is all
		// that is left.
		return
	}
}

// sensorViews marks the sensors that have gone quiet. With no policy
// configured nothing is marked: the console should not imply it is watching
// for something it was not asked to watch for.
func (s *Server) sensorViews(sensors []store.Sensor) []sensorView {
	out := make([]sensorView, 0, len(sensors))
	for _, sensor := range sensors {
		v := sensorView{Sensor: sensor}
		if s.silenceAfter > 0 {
			v.Silent = time.Since(sensor.LastSeen) > s.silenceAfter
		}
		out = append(out, v)
	}
	return out
}

// withParams rebuilds the current URL against a different path, replacing one
// parameter. An empty value removes it.
func withParams(r *http.Request, path, key, value string) string {
	q := r.URL.Query()
	if value == "" {
		q.Del(key)
	} else {
		q.Set(key, value)
	}
	if len(q) == 0 {
		return path
	}
	return path + "?" + q.Encode()
}

// isCredentialKind reports whether an event turned on a credential — one
// offered to us, or one taken from us. Those are shown in red: they are the
// events an operator scans the page for.
func isCredentialKind(kind string) bool {
	switch kind {
	case "login_password", "login_pubkey", "login_form", "login_basic", "auth_attempt":
		return true

	// Not a credential offered but a credential collected. Nothing benign asks
	// 169.254.169.254 for the instance role's keys, so this belongs with the
	// events worth interrupting someone for rather than a tier below them.
	case "credential_request":
		return true
	}
	return false
}

// sortedPairs renders an event's data map in a stable order, so the same event
// shape always reads the same way down the page.
func sortedPairs(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, k+"="+shortValue(m[k]))
	}
	return out
}

func shortValue(v any) string {
	s := fmt.Sprint(v)
	const limit = 160
	if len(s) <= limit {
		return s
	}
	return s[:limit] + "..."
}

func humanAgo(t time.Time) string {
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds ago", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	}
	return fmt.Sprintf("%dd ago", int(d.Hours()/24))
}
