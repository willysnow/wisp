// Package jenkinssvc emulates a Jenkins controller.
//
// Jenkins is where an internal network keeps its deployment credentials, and it
// has a feature that turns read access into arbitrary code execution on the
// controller: the Groovy script console at /script. That is not a vulnerability
// either — it is an administration tool — which is why it is the first place an
// intruder who reaches a Jenkins goes.
//
// The capture that matters is the script:
//
//	jenkins  command  path=/scriptText
//	         script=println new File("/var/lib/jenkins/credentials.xml").text
//
// Like the Ollama prompt and the kubelet command, that is intent in the
// intruder's own words, and it says which credential store they knew to ask
// for. The other capture is the login form, because `/j_spring_security_check`
// is one of the most-brute-forced endpoints on any internal network.
//
// Nothing is executed. The script console records and returns nothing.
package jenkinssvc

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/willysnow/wisp/internal/event"
	"github.com/willysnow/wisp/internal/service/httpdecoy"
)

const name = "jenkins"

// scriptLimit bounds how much of a submitted script reaches the log. Groovy
// payloads are usually one line and occasionally a whole file; the first eight
// kilobytes identify either.
const scriptLimit = 8000

type Service struct {
	addr    string
	version string
}

func New(addr, version string) *Service {
	if version == "" {
		version = "2.440.3"
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
		// The script console. Both spellings: /script is the HTML form a person
		// uses, /scriptText is the one every exploit script posts to.
		case path == "/script", path == "/scriptText":
			s.script(w, r, rec)

		// The CLI endpoint. Its argument parser is what CVE-2024-23897 turned
		// into an arbitrary file read, and scanners still hammer it.
		case strings.HasPrefix(path, "/cli"):
			ev := rec.Event(r, "command")
			if body := httpdecoy.Body(w, r); len(body) > 0 {
				ev.Data["cli_payload"] = httpdecoy.Truncate(string(body), scriptLimit)
			}
			rec.Emit(ev)
			w.Header().Set("X-Jenkins-CLI-Port", "50000")
			httpdecoy.WriteText(w, http.StatusOK, "")

		case path == "/j_spring_security_check", path == "/j_acegi_security_check":
			s.login(w, r, rec)

		case path == "/login", path == "/loginError":
			rec.Emit(rec.Event(r, "probe"))
			s.loginPage(w, path == "/loginError")

		case path == "/logout":
			rec.Emit(rec.Event(r, "probe"))
			redirect(w, "/login")

		// Anything under /credentials is the store itself. Jenkins does not
		// return the secret values through the UI, but an intruder asking is
		// telling you what they came for.
		case strings.HasPrefix(path, "/credentials"),
			path == "/systemInfo", path == "/env-vars.html",
			strings.HasPrefix(path, "/manage"), strings.HasPrefix(path, "/configure"):
			rec.Emit(rec.Event(r, "resource_read"))
			httpdecoy.WriteText(w, http.StatusOK, managePage)

		// Triggering a build runs whatever the job's pipeline says on whatever
		// agent picks it up. It is the slower road to the same place /script
		// goes.
		case strings.Contains(path, "/build"), strings.Contains(path, "/buildWithParameters"):
			ev := rec.Event(r, "command")
			ev.Data["job"] = jobFrom(path)
			rec.Emit(ev)
			w.Header().Set("Location", "/queue/item/128/")
			w.WriteHeader(http.StatusCreated)

		case path == "/crumbIssuer/api/json":
			// Scanners fetch a crumb before posting anywhere. Refusing would
			// stop the POST that carries the script.
			rec.Emit(rec.Event(r, "probe"))
			httpdecoy.WriteJSON(w, http.StatusOK, map[string]any{
				"_class":            "hudson.security.csrf.DefaultCrumbIssuer",
				"crumb":             httpdecoy.StableID("crumb", 32),
				"crumbRequestField": "Jenkins-Crumb",
			})

		case strings.HasSuffix(path, "/api/json"), strings.HasSuffix(path, "/api/xml"):
			s.api(w, r, rec, path)

		case path == "":
			rec.Emit(rec.Event(r, "probe"))
			redirect(w, "/login?from=%2F")

		default:
			rec.Emit(rec.Event(r, "probe"))
			httpdecoy.WriteText(w, http.StatusNotFound, notFoundPage)
		}
	})
	return mux
}

// script records a submitted Groovy script and runs nothing.
//
// The reply is empty on purpose. Every other decoy in wisp that answers
// plausibly can do so because the space of sensible answers is small — a model
// list, a pod list, `uid=0(root)`. Groovy is a general-purpose language, so
// there is no table of plausible outputs to write, and inventing one would
// produce contradictions faster than it produced credibility. An empty result
// is what a script that printed nothing returns, and it costs nothing: the
// script was captured before the reply was written.
func (s *Service) script(w http.ResponseWriter, r *http.Request, rec *httpdecoy.Recorder) {
	if r.Method != http.MethodPost {
		rec.Emit(rec.Event(r, "resource_access"))
		httpdecoy.WriteText(w, http.StatusOK, scriptConsolePage)
		return
	}

	ev := rec.Event(r, "command")
	if script := httpdecoy.Form(w, r).Get("script"); script != "" {
		ev.Data["script"] = httpdecoy.Truncate(script, scriptLimit)
	} else if body := httpdecoy.Body(w, r); len(body) > 0 {
		// Not form-encoded — some clients post the script raw. Whatever arrived
		// is what they sent.
		ev.Data["script"] = httpdecoy.Truncate(string(body), scriptLimit)
	}
	rec.Emit(ev)

	if r.URL.Path == "/scriptText" {
		httpdecoy.WriteText(w, http.StatusOK, "")
		return
	}
	httpdecoy.WriteText(w, http.StatusOK, scriptConsolePage)
}

// login records a form credential. Jenkins never says which half was wrong, and
// neither does this — an error that distinguished "no such user" from "wrong
// password" would let an intruder enumerate accounts.
func (s *Service) login(w http.ResponseWriter, r *http.Request, rec *httpdecoy.Recorder) {
	form := httpdecoy.Form(w, r)

	ev := rec.Event(r, "login_form")
	ev.Data["username"] = httpdecoy.Truncate(form.Get("j_username"), httpdecoy.FieldLimit)
	ev.Data["password"] = httpdecoy.Truncate(form.Get("j_password"), httpdecoy.FieldLimit)
	if from := form.Get("from"); from != "" {
		// Where they were trying to get to before the login page caught them,
		// which is often /script.
		ev.Data["from"] = httpdecoy.Truncate(from, httpdecoy.FieldLimit)
	}
	rec.Emit(ev)

	redirect(w, "/loginError")
}

// api answers the REST endpoints. Anonymous read is on, because a controller
// that returns 403 to everything gives an intruder nothing to reach for — and
// the job list is what tells them which pipeline holds the deployment key.
func (s *Service) api(w http.ResponseWriter, r *http.Request, rec *httpdecoy.Recorder, path string) {
	rec.Emit(rec.Event(r, "resource_access"))

	switch {
	case strings.HasPrefix(path, "/computer"):
		httpdecoy.WriteJSON(w, http.StatusOK, s.computerList())
	case strings.HasPrefix(path, "/whoAmI"):
		httpdecoy.WriteJSON(w, http.StatusOK, map[string]any{
			"_class": "hudson.security.WhoAmI", "name": "anonymous",
			"authenticated": false, "anonymous": true,
			"authorities": []string{"anonymous"},
		})
	case strings.HasPrefix(path, "/pluginManager"):
		httpdecoy.WriteJSON(w, http.StatusOK, s.pluginList())
	case strings.HasPrefix(path, "/job/"):
		httpdecoy.WriteJSON(w, http.StatusOK, s.job(jobFrom(path)))
	default:
		httpdecoy.WriteJSON(w, http.StatusOK, s.root())
	}
}

// jobFrom pulls the job name out of a path like /job/deploy-production/build.
func jobFrom(path string) string {
	_, rest, ok := strings.Cut(path, "/job/")
	if !ok {
		return ""
	}
	job, _, _ := strings.Cut(rest, "/")
	return job
}

func redirect(w http.ResponseWriter, to string) {
	w.Header().Set("Location", to)
	w.WriteHeader(http.StatusFound)
}

// header sets what a Jenkins controller puts on every response. X-Jenkins is
// the version, in the clear, on every request — it is how every scanner in
// existence identifies one.
func (s *Service) header(w http.ResponseWriter) {
	w.Header().Set("Server", "Jetty(10.0.20)")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Jenkins", s.version)
	w.Header().Set("X-Jenkins-Session", httpdecoy.StableID("session", 8))
	w.Header().Set("X-Hudson", "1.395")
	w.Header().Set("X-Hudson-CLI-Port", "50000")
	w.Header().Set("X-Jenkins-CLI2-Port", "50000")
	w.Header().Set("X-Instance-Identity", instanceIdentity)
}

func (s *Service) loginPage(w http.ResponseWriter, failed bool) {
	errorBlock := ""
	if failed {
		errorBlock = `<div class="app-sign-in-register__error">Invalid username or password</div>`
	}
	httpdecoy.WriteText(w, http.StatusOK,
		fmt.Sprintf(loginPage, s.version, errorBlock, s.version))
}
