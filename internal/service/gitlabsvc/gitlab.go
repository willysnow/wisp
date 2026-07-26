// Package gitlabsvc emulates a self-hosted GitLab.
//
// A GitLab instance holds the source, the deployment pipelines, and the
// credentials those pipelines run with, and the key that opens all of it is a
// personal access token — a 26-character string beginning `glpat-` that people
// paste into scripts, commit by accident, and leave in `~/.netrc`. Finding one
// and trying it against every GitLab on the network is a standard lateral
// movement step, which makes this decoy's job the same as the Kubernetes one:
//
//	gitlab  auth_attempt  path=/api/v4/projects/14/variables
//	        private_token=glpat-[the twenty characters they stole]
//
// Knowing *which* token was used is what turns an alert into an incident with a
// scope. The token names its owner, and the path names what they thought it
// would open — CI/CD variables, in that example, which is where the deployment
// secrets live.
//
// Public endpoints answer, because that is what a real GitLab does and because
// an intruder who gets a project list has a reason to send the token. Anything
// needing authentication returns GitLab's own `401 Unauthorized`; no token is
// ever accepted.
package gitlabsvc

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/willysnow/wisp/internal/event"
	"github.com/willysnow/wisp/internal/service/httpdecoy"
)

const name = "gitlab"

type Service struct {
	addr    string
	version string
}

func New(addr, version string) *Service {
	if version == "" {
		version = "16.11.2"
	}
	return &Service{addr: addr, version: version}
}

func (s *Service) Name() string { return name }
func (s *Service) Addr() string { return s.addr }

func (s *Service) Serve(ctx context.Context, ln net.Listener, emit event.Emitter) error {
	rec := httpdecoy.NewRecorder(name, ln, emit)
	return httpdecoy.Serve(ctx, ln, s.handler(rec), nil)
}

func (s *Service) handler(rec *httpdecoy.Recorder) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		s.header(w)
		path := strings.TrimSuffix(r.URL.Path, "/")

		switch {
		case strings.HasPrefix(path, "/api/v4"):
			s.api(w, r, rec, strings.TrimPrefix(path, "/api/v4"))

		case path == "/users/sign_in", path == "/users/sign_up":
			if r.Method == http.MethodPost {
				s.signIn(w, r, rec)
				return
			}
			rec.Emit(s.event(rec, r, "probe"))
			s.signInPage(w, false)

		// The OAuth resource-owner grant takes a raw username and password over
		// the API. Tooling that has a credential pair rather than a token comes
		// here, and the pair arrives in the request body.
		case path == "/oauth/token":
			s.oauth(w, r, rec)

		case path == "/-/health":
			rec.Emit(s.event(rec, r, "probe"))
			httpdecoy.WriteText(w, http.StatusOK, "GitLab OK")

		case path == "/-/readiness", path == "/-/liveness":
			rec.Emit(s.event(rec, r, "probe"))
			httpdecoy.WriteJSON(w, http.StatusOK, map[string]any{"status": "ok"})

		case path == "/-/metrics":
			// Requires a token from the monitoring allowlist, and says so.
			rec.Emit(s.event(rec, r, "resource_access"))
			httpdecoy.WriteText(w, http.StatusUnauthorized, "")

		case path == "", path == "/explore", path == "/help", path == "/dashboard":
			rec.Emit(s.event(rec, r, "probe"))
			redirect(w, "/users/sign_in")

		default:
			rec.Emit(s.event(rec, r, "probe"))
			redirect(w, "/users/sign_in")
		}
	})
	return mux
}

// event builds the record and lifts out every credential GitLab accepts, of
// which there are four: the Authorization header (handled by the shared
// recorder), the PRIVATE-TOKEN header, a CI job token, and a token in the query
// string — which is the one that ends up in proxy logs and browser history, and
// therefore the one most often stolen.
func (s *Service) event(rec *httpdecoy.Recorder, r *http.Request, kind string) event.Event {
	ev := rec.Event(r, kind)

	httpdecoy.Credential(&ev, "private_token", r.Header.Get("PRIVATE-TOKEN"))
	httpdecoy.Credential(&ev, "job_token", r.Header.Get("JOB-TOKEN"))
	httpdecoy.Credential(&ev, "private_token", r.URL.Query().Get("private_token"))
	httpdecoy.Credential(&ev, "access_token", r.URL.Query().Get("access_token"))

	return ev
}

// api routes the v4 REST surface. rest is the path with /api/v4 removed.
func (s *Service) api(w http.ResponseWriter, r *http.Request, rec *httpdecoy.Recorder, rest string) {
	seg := segments(rest)
	if len(seg) == 0 {
		rec.Emit(s.event(rec, r, "probe"))
		unauthorized(w)
		return
	}

	switch seg[0] {
	case "version":
		// An instance that answers this anonymously is one whose API is open to
		// unauthenticated reads. That configuration exists, it is the one worth
		// imitating, and the version string is what makes a scanner decide this
		// host is worth coming back to.
		rec.Emit(s.event(rec, r, "probe"))
		httpdecoy.WriteJSON(w, http.StatusOK, map[string]any{
			"version":  s.version,
			"revision": httpdecoy.StableID(s.version, 11),
		})

	case "projects":
		s.projects(w, r, rec, seg[1:])

	// Everything here needs a credential. The reply is always GitLab's own 401,
	// but the request is recorded with the kind that names what they were
	// after: a token tried against `personal_access_tokens` is someone
	// enumerating what else that token can reach.
	case "user", "users", "personal_access_tokens", "keys", "admin", "runners", "snippets":
		rec.Emit(s.event(rec, r, "resource_read"))
		unauthorized(w)

	case "groups", "namespaces", "topics", "avatar", "broadcast_messages":
		rec.Emit(s.event(rec, r, "resource_access"))
		unauthorized(w)

	default:
		rec.Emit(s.event(rec, r, "resource_access"))
		unauthorized(w)
	}
}

func (s *Service) projects(w http.ResponseWriter, r *http.Request, rec *httpdecoy.Recorder, seg []string) {
	// The public project list. Anonymous callers genuinely get this from a real
	// GitLab, and it is what gives an intruder a project id to put in the next
	// request — the one that carries the token.
	if len(seg) == 0 {
		rec.Emit(s.event(rec, r, "resource_access"))
		httpdecoy.WriteJSON(w, http.StatusOK, publicProjects())
		return
	}

	project := seg[0]
	sub := ""
	if len(seg) > 1 {
		sub = seg[1]
	}

	switch sub {
	// CI/CD variables are the deployment secrets in plain text, and the single
	// most valuable thing a stolen token opens.
	case "variables", "secure_files", "deploy_tokens", "deploy_keys", "hooks", "triggers":
		ev := s.event(rec, r, "resource_read")
		ev.Data["project"] = project
		ev.Data["resource"] = sub
		rec.Emit(ev)
		unauthorized(w)

	case "repository":
		ev := s.event(rec, r, "resource_read")
		ev.Data["project"] = project
		ev.Data["resource"] = strings.Join(seg[1:], "/")
		rec.Emit(ev)
		unauthorized(w)

	case "":
		ev := s.event(rec, r, "resource_access")
		ev.Data["project"] = project
		rec.Emit(ev)
		httpdecoy.WriteJSON(w, http.StatusOK, projectByID(project))

	default:
		ev := s.event(rec, r, "resource_access")
		ev.Data["project"] = project
		ev.Data["resource"] = sub
		rec.Emit(ev)
		unauthorized(w)
	}
}

// signIn records a posted credential. GitLab's form nests its fields as
// `user[login]` and `user[password]`, which is exactly the shape a generic
// credential scraper misses.
func (s *Service) signIn(w http.ResponseWriter, r *http.Request, rec *httpdecoy.Recorder) {
	form := httpdecoy.Form(w, r)

	ev := s.event(rec, r, "login_form")
	ev.Data["username"] = httpdecoy.Truncate(
		firstNonEmpty(form.Get("user[login]"), form.Get("username"), form.Get("user[email]")),
		httpdecoy.FieldLimit)
	ev.Data["password"] = httpdecoy.Truncate(
		firstNonEmpty(form.Get("user[password]"), form.Get("password")),
		httpdecoy.FieldLimit)
	rec.Emit(ev)

	// Always the same message, never "no such user" — anything else would let
	// an intruder enumerate accounts for free.
	s.signInPage(w, true)
}

func (s *Service) oauth(w http.ResponseWriter, r *http.Request, rec *httpdecoy.Recorder) {
	ev := s.event(rec, r, "login_password")

	body := httpdecoy.Body(w, r)
	// The grant accepts both JSON and form encoding, and tooling uses both.
	if fields, err := url.ParseQuery(string(body)); err == nil && fields.Get("username") != "" {
		ev.Data["username"] = httpdecoy.Truncate(fields.Get("username"), httpdecoy.FieldLimit)
		ev.Data["password"] = httpdecoy.Truncate(fields.Get("password"), httpdecoy.FieldLimit)
		ev.Data["grant_type"] = fields.Get("grant_type")
	} else if m := jsonObject(body); m != nil {
		ev.Data["username"] = httpdecoy.Truncate(httpdecoy.StringField(m, "username"), httpdecoy.FieldLimit)
		ev.Data["password"] = httpdecoy.Truncate(httpdecoy.StringField(m, "password"), httpdecoy.FieldLimit)
		ev.Data["grant_type"] = httpdecoy.StringField(m, "grant_type")
	}
	rec.Emit(ev)

	httpdecoy.WriteJSON(w, http.StatusUnauthorized, map[string]any{
		"error":             "invalid_grant",
		"error_description": "The provided authorization grant is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client.",
	})
}

// unauthorized is GitLab's refusal, word for word. Tooling matches on it.
func unauthorized(w http.ResponseWriter) {
	httpdecoy.WriteJSON(w, http.StatusUnauthorized, map[string]any{"message": "401 Unauthorized"})
}

func redirect(w http.ResponseWriter, to string) {
	w.Header().Set("Location", to)
	w.WriteHeader(http.StatusFound)
}

// header sets what a GitLab behind its bundled nginx puts on every response.
func (s *Service) header(w http.ResponseWriter) {
	w.Header().Set("Server", "nginx")
	w.Header().Set("Cache-Control", "max-age=0, private, must-revalidate")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "SAMEORIGIN")
	w.Header().Set("X-Request-Id", httpdecoy.StableID("request", 32))
	w.Header().Set("X-Runtime", "0.081294")
	w.Header().Set("Gitlab-Lb", "haproxy-main-01")
	w.Header().Set("Gitlab-Sv", "gitlab-web-01")
	w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
}

func segments(path string) []string {
	trimmed := strings.Trim(path, "/")
	if trimmed == "" {
		return nil
	}
	return strings.Split(trimmed, "/")
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
