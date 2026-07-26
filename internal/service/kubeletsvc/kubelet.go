// Package kubeletsvc emulates a Kubernetes kubelet's API on 10250.
//
// The apiserver is the control plane and the kubelet is the thing that actually
// runs containers, which makes 10250 the more useful of the two to an intruder:
// a kubelet that trusts anonymous requests will list every pod on the node and
// then run a command inside any of them, no cluster credential involved. That
// misconfiguration is old, is still shipped by more than one installer, and has
// a dedicated tool — `kubeletctl` — whose entire purpose is finding it.
//
// So this decoy answers. It lists plausible pods, and when the intruder picks
// one and POSTs a command to /run, it records the command and replies with
// something short enough to be believable. Nothing executes; the reply comes
// from a table. The command itself is the artifact worth having — like the
// Ollama prompt, it is the intruder describing their intent in their own words:
//
//	kubelet  command  pod=payments-api-7d4f9c8b5-2xk4n
//	         cmd=cat /var/run/secrets/kubernetes.io/serviceaccount/token
//
// The other half is the bearer token. A kubelet with webhook authorization
// rejects anonymous requests, so tooling that meets one falls back to whatever
// service-account token it has already stolen — and that token names the
// account, which is what an incident responder actually needs.
package kubeletsvc

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/willysnow/wisp/internal/event"
	"github.com/willysnow/wisp/internal/service/httpdecoy"
	"github.com/willysnow/wisp/internal/tlsutil"
)

const name = "kubelet"

// commandLimit bounds how much of a submitted command reaches the log. Real
// ones are short; a very long one is a payload being pasted in, and its first
// few kilobytes identify it.
const commandLimit = 8000

type Service struct {
	addr     string
	nodeName string
	tlsCert  tls.Certificate
}

// New loads or creates the kubelet's serving certificate. A real one is issued
// to `system:node:<name>` by the cluster CA; ours is self-signed, which is also
// what an unbootstrapped kubelet presents, so the shape is right even though
// the chain is not.
func New(addr, nodeName, certPath, keyPath string) (*Service, error) {
	if nodeName == "" {
		nodeName, _ = os.Hostname()
	}
	if nodeName == "" {
		nodeName = "node-1"
	}

	cert, err := tlsutil.LoadOrCreate(certPath, keyPath, "system:node:"+nodeName, []string{
		nodeName,
		"localhost",
		"127.0.0.1",
	})
	if err != nil {
		return nil, fmt.Errorf("kubelet certificate: %w", err)
	}
	return &Service{addr: addr, nodeName: nodeName, tlsCert: cert}, nil
}

func (s *Service) Name() string { return name }
func (s *Service) Addr() string { return s.addr }

func (s *Service) Serve(ctx context.Context, ln net.Listener, emit event.Emitter) error {
	rec := httpdecoy.NewRecorder(name, ln, emit)

	return httpdecoy.Serve(ctx, ln, s.handler(rec), &tls.Config{
		Certificates: []tls.Certificate{s.tlsCert},
		// A kubelet asks for a client certificate without requiring one, so
		// that x509 authentication can work when it is configured. Asking gets
		// us the subject of whatever the client offers, for free.
		ClientAuth: tls.RequestClientCert,
		MinVersion: tls.VersionTLS12,
	})
}

func (s *Service) handler(rec *httpdecoy.Recorder) http.Handler {
	mux := http.NewServeMux()

	// /run is the endpoint that matters: one POST, one command, output back in
	// the response body. It is what kubeletctl uses by default and what every
	// write-up of this misconfiguration demonstrates.
	mux.HandleFunc("POST /run/{namespace}/{pod}/{container}", func(w http.ResponseWriter, r *http.Request) {
		cmd := commandFromForm(w, r)

		ev := rec.Event(r, "command")
		ev.Data["namespace"] = r.PathValue("namespace")
		ev.Data["pod"] = r.PathValue("pod")
		ev.Data["container"] = r.PathValue("container")
		ev.Data["cmd"] = httpdecoy.Truncate(cmd, commandLimit)
		rec.Emit(ev)

		httpdecoy.WriteText(w, http.StatusOK, output(cmd, r.PathValue("pod")))
	})

	// /exec is the streaming form. It needs a SPDY or websocket upgrade that
	// this decoy has no intention of completing — but the command arrives in
	// the query string, before any of that, so it is captured all the same and
	// the client gets the same 400 a real kubelet gives a plain HTTP request.
	for _, pattern := range []string{
		"/exec/{namespace}/{pod}/{container}",
		"/attach/{namespace}/{pod}/{container}",
	} {
		mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
			ev := rec.Event(r, "command")
			ev.Data["namespace"] = r.PathValue("namespace")
			ev.Data["pod"] = r.PathValue("pod")
			ev.Data["container"] = r.PathValue("container")
			if cmd := strings.Join(r.URL.Query()["command"], " "); cmd != "" {
				ev.Data["cmd"] = httpdecoy.Truncate(cmd, commandLimit)
			}
			rec.Emit(ev)

			httpdecoy.WriteText(w, http.StatusBadRequest, "Upgrade request required\n")
		})
	}

	// Container logs are the quiet way to the same place. Applications log
	// tokens, connection strings, and authorization headers far more often than
	// anyone admits, so reading them is a credential hunt.
	mux.HandleFunc("/containerLogs/{namespace}/{pod}/{container}", func(w http.ResponseWriter, r *http.Request) {
		ev := rec.Event(r, "resource_read")
		ev.Data["namespace"] = r.PathValue("namespace")
		ev.Data["pod"] = r.PathValue("pod")
		ev.Data["container"] = r.PathValue("container")
		rec.Emit(ev)

		httpdecoy.WriteText(w, http.StatusOK, containerLog)
	})

	// A checkpoint is a full memory dump of a running container written to the
	// node's disk. Anyone asking for one is after whatever the process is
	// holding in memory, which is every secret it has ever decrypted.
	mux.HandleFunc("POST /checkpoint/{namespace}/{pod}/{container}", func(w http.ResponseWriter, r *http.Request) {
		ev := rec.Event(r, "resource_read")
		ev.Data["namespace"] = r.PathValue("namespace")
		ev.Data["pod"] = r.PathValue("pod")
		ev.Data["container"] = r.PathValue("container")
		rec.Emit(ev)

		httpdecoy.WriteJSON(w, http.StatusOK, map[string]any{
			"items": []string{"/var/lib/kubelet/checkpoints/checkpoint-" +
				r.PathValue("pod") + "_" + r.PathValue("namespace") + "-" +
				r.PathValue("container") + "-2026-07-26T09:14:02Z.tar"},
		})
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimSuffix(r.URL.Path, "/")

		switch {
		// The inventory. This is the reconnaissance call — "what is running on
		// this node, and which of it is worth getting into" — and the reply is
		// what makes the next request a command rather than another scan.
		case path == "/pods", path == "/runningpods":
			ev := rec.Event(r, "pod_list")
			rec.Emit(ev)
			httpdecoy.WriteJSON(w, http.StatusOK, s.podList())
			return

		case path == "/healthz", strings.HasPrefix(path, "/healthz/"):
			rec.Emit(rec.Event(r, "probe"))
			httpdecoy.WriteText(w, http.StatusOK, "ok")
			return

		case path == "/metrics", strings.HasPrefix(path, "/metrics/"):
			rec.Emit(rec.Event(r, "probe"))
			httpdecoy.WriteText(w, http.StatusOK, metricsText)
			return

		case path == "/spec":
			rec.Emit(rec.Event(r, "probe"))
			httpdecoy.WriteJSON(w, http.StatusOK, machineSpec)
			return

		case path == "/stats/summary":
			rec.Emit(rec.Event(r, "resource_access"))
			httpdecoy.WriteJSON(w, http.StatusOK, s.statsSummary())
			return

		// /configz reports the kubelet's own settings, including whether
		// anonymous authentication is on. An intruder reads it to confirm the
		// door they just walked through is really open.
		case path == "/configz":
			rec.Emit(rec.Event(r, "resource_access"))
			httpdecoy.WriteJSON(w, http.StatusOK, configz)
			return

		// /logs/ serves the node's own /var/log over HTTP. Directory listing
		// included.
		case strings.HasPrefix(path, "/logs"):
			ev := rec.Event(r, "resource_read")
			ev.Data["log_path"] = strings.TrimPrefix(path, "/logs")
			rec.Emit(ev)
			httpdecoy.WriteText(w, http.StatusOK, logIndex)
			return
		}

		rec.Emit(rec.Event(r, "probe"))
		httpdecoy.WriteText(w, http.StatusNotFound, "404 page not found\n")
	})

	return mux
}

// commandFromForm pulls the command out of a /run request. kubeletctl posts it
// as a form field; curl users often put it in the query string instead, and a
// decoy that only understood one of those would lose half the captures.
func commandFromForm(w http.ResponseWriter, r *http.Request) string {
	if cmd := r.URL.Query().Get("cmd"); cmd != "" {
		return cmd
	}

	body := string(httpdecoy.Body(w, r))
	if values, err := url.ParseQuery(body); err == nil {
		if cmd := values.Get("cmd"); cmd != "" {
			return cmd
		}
	}
	// Not form-encoded, or no cmd field in it. Whatever arrived is what they
	// sent, and an unparsed command is still a recorded one.
	return body
}
