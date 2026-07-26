// Package httpdecoy is the machinery the HTTP-shaped decoys share.
//
// Most of what an intruder reaches for on a 2026 network answers HTTP and
// speaks JSON: the kubelet, the Docker socket, cloud IMDS, Elasticsearch,
// Jenkins, GitLab. Each needs the same four things — a server that shuts down
// with the context, a record of who asked for what, a bounded read of the body,
// and a credential lifted out of whichever header this particular product
// happens to use.
//
// Written once per service, the copies would differ in exactly the places that
// matter: whether a token is truncated before it reaches the log, whether a
// body large enough to exhaust memory is refused, whether an offered password
// is recorded at all. So it is written here instead.
package httpdecoy

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/willysnow/wisp/internal/event"
)

// MaxBody caps how much of a request body a decoy will read. Every body these
// services care about — a search query, a container spec, a prompt — is small.
// Anything larger is an attack on the sensor rather than a message to it.
const MaxBody = 256 << 10

// FieldLimit bounds how much of any one attacker-supplied string reaches the
// event log, so a single request cannot bloat every downstream sink.
const FieldLimit = 4000

// TokenLimit is the same bound for credentials. A Kubernetes service-account
// JWT is ~800 bytes and a GitLab PAT is 26; the identifying part of anything
// longer is at the front.
const TokenLimit = 1024

// Serve runs an HTTP decoy on ln until ctx is cancelled. A non-nil tlsCfg wraps
// the listener — for the services that only exist over TLS, where a plaintext
// listener on the real port would be the tell.
func Serve(ctx context.Context, ln net.Listener, handler http.Handler, tlsCfg *tls.Config) error {
	if tlsCfg != nil {
		ln = tls.NewListener(ln, tlsCfg)
	}

	srv := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
	}
	go func() {
		<-ctx.Done()
		_ = srv.Close()
	}()

	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// Recorder turns requests into events for one service on one listener.
type Recorder struct {
	service string
	dstPort int
	emit    event.Emitter
}

// NewRecorder binds a recorder to the port a service actually ended up on,
// which is not always the configured one — tests listen on :0.
func NewRecorder(service string, ln net.Listener, emit event.Emitter) *Recorder {
	_, dstPort := event.SplitAddr(ln.Addr())
	return &Recorder{service: service, dstPort: dstPort, emit: emit}
}

// Event builds the record for one request: what was asked for, by whom, and
// with which credential.
//
// A credential found in the request promotes kind to `auth_attempt` (or
// `login_basic`), but only when the caller's own kind is not already a
// high-value one. "Someone offered a password" is the most important thing
// about an otherwise ordinary probe, and the least important thing about a
// request that also carried a search query or a command — those name what the
// intruder was trying to do, and the credential rides along in the data.
func (rec *Recorder) Event(r *http.Request, kind string) event.Event {
	srcIP, srcPort := event.SplitHostPortString(r.RemoteAddr)
	ev := event.NewRaw(rec.service, kind, srcIP, srcPort, rec.dstPort)
	ev.Data["method"] = r.Method
	ev.Data["path"] = Truncate(r.URL.RequestURI(), FieldLimit)
	ev.Data["user_agent"] = r.UserAgent()

	if user, pass, ok := r.BasicAuth(); ok {
		Promote(&ev, "login_basic")
		ev.Data["username"] = Truncate(user, FieldLimit)
		ev.Data["password"] = Truncate(pass, FieldLimit)
	} else if auth := r.Header.Get("Authorization"); auth != "" {
		scheme, credential, _ := strings.Cut(auth, " ")
		Promote(&ev, "auth_attempt")
		ev.Data["auth_scheme"] = scheme
		ev.Data["token"] = Truncate(credential, TokenLimit)
	}

	if r.TLS != nil {
		// The name in SNI is what the client expected to find here, which is
		// often more informative than the path: a scanner sweeping addresses
		// sends none, while someone who came looking for a specific host sends
		// the name they were given.
		if r.TLS.ServerName != "" {
			ev.Data["sni"] = r.TLS.ServerName
		}
		// A client certificate is the other way in, and names the subject
		// directly.
		if len(r.TLS.PeerCertificates) > 0 {
			Promote(&ev, "auth_attempt")
			ev.Data["client_cert_subject"] = r.TLS.PeerCertificates[0].Subject.String()
		}
	}

	return ev
}

// Emit sends a finished event on.
func (rec *Recorder) Emit(ev event.Event) { rec.emit.Emit(ev) }

// Credential records a credential carried by something other than the
// Authorization header — GitLab's `PRIVATE-TOKEN`, Docker's `X-Registry-Auth`,
// IMDSv2's session token — and promotes the kind the same way Event does.
func Credential(ev *event.Event, field, value string) {
	if value == "" {
		return
	}
	ev.Data[field] = Truncate(value, TokenLimit)
	Promote(ev, "auth_attempt")
}

// Promote raises an event to kind unless it already names something at least
// as important. See Event for why.
func Promote(ev *event.Event, kind string) {
	if event.IsHighValue(ev.Kind) {
		return
	}
	ev.Kind = kind
}

// Body reads at most MaxBody of the request body. A read error yields what
// arrived before it: a truncated container spec still names the image.
func Body(w http.ResponseWriter, r *http.Request) []byte {
	if r.Body == nil {
		return nil
	}
	r.Body = http.MaxBytesReader(w, r.Body, MaxBody)
	b, _ := io.ReadAll(r.Body)
	return b
}

// Form parses a posted form, bounded the same way Body is.
//
// net/http's own ParseForm caps a urlencoded body at 10 MiB, which is forty
// times more than any credential form needs and forty times more than a decoy
// should let a stranger decide to allocate.
func Form(w http.ResponseWriter, r *http.Request) url.Values {
	r.Body = http.MaxBytesReader(w, r.Body, MaxBody)
	if err := r.ParseForm(); err != nil {
		// A form that would not parse is still a recorded interaction; the
		// query-string half of PostForm's input survives either way.
		return r.Form
	}
	return r.PostForm
}

// JSONBody decodes the request body as a JSON object, returning nil on any
// problem. A malformed body is still a recorded interaction — there is simply
// less to say about it.
func JSONBody(w http.ResponseWriter, r *http.Request) map[string]any {
	var m map[string]any
	if err := json.Unmarshal(Body(w, r), &m); err != nil {
		return nil
	}
	return m
}

// WriteJSON sends a JSON response with the given status.
func WriteJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// WriteText sends a plain-text response, which several of these APIs prefer:
// `_cat` in Elasticsearch, every scalar in AWS IMDS, Prometheus metrics.
func WriteText(w http.ResponseWriter, code int, body string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(code)
	_, _ = io.WriteString(w, body)
}

// Truncate bounds a string for the event log, marking where it was cut so a
// reader never mistakes a clipped value for a complete one.
func Truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "...[truncated]"
}

// StableID derives an n-character hex identifier from a seed.
//
// The decoys need identifiers — pod UIDs, container IDs, cluster UUIDs — that
// look real and, more importantly, do not change. A node whose identifiers are
// regenerated every time anyone looks is a honeypot fingerprint in exactly the
// way a rotating TLS certificate is, and an intruder who connects twice would
// see it.
//
// FNV-1a over the whole seed, then one avalanche step per output character.
// Not a hash anything should rely on; it exists to make identifiers stable and
// plausible, and for nothing else.
//
// The avalanche step is not decoration. A first attempt emitted the top nibble
// of the FNV state directly, and because a one-byte XOR barely moves the high
// bits of a 64-bit accumulator, every identifier the sensor produced began with
// the same two characters — a cluster whose indices were all `a0…` is a tell
// that costs nothing to remove.
func StableID(seed string, n int) string {
	const hexDigits = "0123456789abcdef"

	h := uint64(14695981039346656037)
	for i := 0; i < len(seed); i++ {
		h ^= uint64(seed[i])
		h *= 1099511628211
	}

	out := make([]byte, 0, n)
	for i := 0; i < n; i++ {
		h ^= uint64(i) + 1
		h *= 1099511628211

		// splitmix64's finalizer: spreads the low bits of the state across the
		// whole word, so consecutive characters do not correlate.
		x := h
		x ^= x >> 33
		x *= 0xff51afd7ed558ccd
		x ^= x >> 29
		out = append(out, hexDigits[x&0xf])
	}
	return string(out)
}

// StringField returns the first key present as a non-empty string. Products
// disagree about what to call the same thing — `model` or `name`, `Image` or
// `image` — and a decoy that only knows one spelling loses the field.
func StringField(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k].(string); ok && v != "" {
			return v
		}
	}
	return ""
}

// StringsField returns the first key present as a list of strings. Command
// lines arrive this way: `"Cmd": ["sh", "-c", "curl … | sh"]`.
func StringsField(m map[string]any, keys ...string) []string {
	for _, k := range keys {
		raw, ok := m[k].([]any)
		if !ok {
			continue
		}
		out := make([]string, 0, len(raw))
		for _, v := range raw {
			if s, ok := v.(string); ok {
				out = append(out, s)
			}
		}
		if len(out) > 0 {
			return out
		}
	}
	return nil
}

// MapField returns the first key present as a nested object.
func MapField(m map[string]any, keys ...string) map[string]any {
	for _, k := range keys {
		if v, ok := m[k].(map[string]any); ok {
			return v
		}
	}
	return nil
}

// BoolField reports whether any of the keys is present and true. The flags
// worth knowing about — `Privileged`, `snapshot` — are all false by default,
// so an absent key and a false one mean the same thing.
func BoolField(m map[string]any, keys ...string) bool {
	for _, k := range keys {
		if v, ok := m[k].(bool); ok && v {
			return true
		}
	}
	return false
}
