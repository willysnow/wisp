package console

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/willysnow/wisp/internal/console/store"
	"github.com/willysnow/wisp/internal/event"
	"github.com/willysnow/wisp/internal/token"
)

// Token callbacks land here rather than on a sensor, because a token fires from
// wherever the data it was planted in ended up — which is exactly why the
// console, not the segment, is the place to receive them.

// TokenService is the service name a token firing carries. Filtering the UI by
// service=token shows every lure that has been touched.
const TokenService = "token"

// TokenNode is the node name a token event is attributed to. A token has no
// sensor behind it — the console received the callback directly — so the events
// are stamped with the console itself rather than a machine that never saw them.
const TokenNode = "console"

// KindTokenTriggered is raised when a planted token calls home.
const KindTokenTriggered = "token_triggered"

// tokenCallbackTimeout bounds the work one callback may do. A token hit does two
// small indexed writes; anything longer is a database in trouble, and a slow
// callback should not tie up a connection an intruder opened.
const tokenCallbackTimeout = 10 * time.Second

// handleTokenTrigger is the public HTTP callback every HTTP-shaped token fires:
// a bare URL token, a document's linked image, a kubeconfig's apiserver, an MCP
// client's server. It authenticates nobody — the whole point is that an
// intruder trips it — and it records the hit as an ordinary event so it flows
// through the timeline, search, export and notifications like any other capture.
func (s *Server) handleTokenTrigger(w http.ResponseWriter, r *http.Request) {
	id := tokenIDFromPath(r.URL.Path)
	if id == "" {
		http.NotFound(w, r)
		return
	}

	ev := event.Event{
		Time:    time.Now().UTC(),
		Node:    TokenNode,
		Service: TokenService,
		Kind:    KindTokenTriggered,
		SrcIP:   s.clientKey(r),
		Data: map[string]any{
			"via":    "http",
			"method": r.Method,
			"path":   r.URL.Path,
		},
	}
	if ua := r.UserAgent(); ua != "" {
		ev.Data["user_agent"] = ua
	}
	if ref := r.Header.Get("Referer"); ref != "" {
		ev.Data["referer"] = ref
	}
	// The forwarded chain is attacker-controllable, so it never decides the
	// source IP — but recorded alongside it, it can show a token was tripped
	// through a proxy or SSRF hop rather than opened directly.
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		ev.Data["x_forwarded_for"] = fwd
	}

	ctx, cancel := context.WithTimeout(r.Context(), tokenCallbackTimeout)
	defer cancel()

	// RecordTokenTrigger enriches ev.Data in place with the token's id, kind and
	// memo, so the event handed to the dispatcher below is the one that was
	// stored.
	_, ok, err := s.store.RecordTokenTrigger(ctx, id, ev)
	if err != nil {
		// The hit happened whether or not we could record it. Still answer with
		// the pixel so the caller sees nothing unusual, and leave the error for
		// the operator to notice in the logs rather than the attacker in the
		// response.
		s.serveTokenPixel(w)
		return
	}
	if !ok {
		// Unknown or disabled id. The id space is 120 bits of randomness, so a
		// 404 here is not an oracle worth defending, and it keeps the console
		// from acting as a generic pixel host for anyone who finds the path.
		http.NotFound(w, r)
		return
	}

	if s.dispatch != nil {
		s.dispatch.Handle([]event.Event{ev})
	}

	s.serveTokenPixel(w)
}

// serveTokenPixel answers a token callback with a 1x1 GIF. A document's linked
// image resolves to a valid picture and shows nothing; a kubeconfig or MCP
// client gets a body it will discard. Either way the response is unremarkable.
func (s *Server) serveTokenPixel(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "image/gif")
	w.Header().Set("Cache-Control", "no-store")
	// net/http fills in Content-Length for a small body written before the
	// handler returns, so there is nothing to set by hand.
	_, _ = w.Write(token.GIFPixel())
}

// tokenIDFromPath pulls the token id out of a callback path. The id is the first
// segment under /t/; a client that appends its own suffix — kubectl asking for
// /api, an MCP client for /sse, an image loader tacking on an extension — still
// resolves to the same token.
func tokenIDFromPath(path string) string {
	rest := strings.TrimPrefix(path, "/t/")
	if rest == path { // prefix was absent
		return ""
	}
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		rest = rest[:i]
	}
	if i := strings.IndexByte(rest, '.'); i >= 0 {
		rest = rest[:i]
	}
	return strings.ToLower(rest)
}

// tokensPage is the data behind the tokens view.
type tokensPage struct {
	Tokens []tokenView
	User   string
	CSRF   string
	// Configured reports whether the console knows its own address well enough
	// to render a plantable locator. When it does not, the page says so instead
	// of showing blanks.
	Configured bool
}

// tokenView is a token plus the locator an operator plants.
type tokenView struct {
	store.Token
	// Locator is the URL or hostname the token fires — what to plant for the
	// URL and DNS kinds, and where the document/kubeconfig/MCP kinds call home.
	Locator string
}

func (s *Server) handleTokens(w http.ResponseWriter, r *http.Request, user string) {
	if r.URL.Path != "/tokens" {
		http.NotFound(w, r)
		return
	}

	tokens, err := s.store.ListTokens(r.Context())
	if err != nil {
		http.Error(w, "query failed", http.StatusInternalServerError)
		return
	}

	views := make([]tokenView, 0, len(tokens))
	for _, t := range tokens {
		views = append(views, tokenView{Token: t, Locator: s.tokenLocator(t)})
	}

	data := tokensPage{
		Tokens:     views,
		User:       user,
		CSRF:       s.issueCSRF(w, r),
		Configured: s.tokenConfigured(),
	}

	s.uiHeaders(w)
	if err := s.tmpl.ExecuteTemplate(w, "tokens", data); err != nil {
		return
	}
}

// tokenLocator renders the URL or hostname for a token, best-effort: an
// unconfigured console yields an empty locator, which the page explains rather
// than showing a broken link.
func (s *Server) tokenLocator(t store.Token) string {
	switch t.Kind {
	case token.KindDNS:
		if name, err := token.DNSName(s.tokenCfg, t.ID); err == nil {
			return name
		}
	default:
		if u, err := token.HTTPURL(s.tokenCfg, t.ID); err == nil {
			return u
		}
	}
	return ""
}

// tokenConfigured reports whether the console has enough address configuration
// to render a plantable locator for the common (HTTP) kinds.
func (s *Server) tokenConfigured() bool {
	_, err := token.HTTPURL(s.tokenCfg, "probe")
	return err == nil
}
