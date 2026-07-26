// Package k8ssvc emulates a Kubernetes API server.
//
// The apiserver is the single highest-value target on a cluster network: it is
// the control plane, it is reachable from every pod by default, and stolen
// service-account tokens are the standard way in. That last part is what this
// decoy is built around.
//
// It answers discovery endpoints (/version, /api, /apis) so the endpoint looks
// live, then returns 403 rather than 401 for everything else. That is what an
// anonymous-auth-enabled cluster does, and the distinction matters: 401 reads
// as "wrong door" and ends the interaction, while 403 reads as "right door,
// wrong credentials" — so the attacker retries with a stolen bearer token, and
// the token lands in the log. Knowing *which* service account was compromised
// is far more actionable than knowing someone knocked.
package k8ssvc

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/willysnow/wisp/internal/event"
	"github.com/willysnow/wisp/internal/tlsutil"
)

const name = "k8s"

// tokenLogLimit bounds how much of a bearer token reaches the event log. A
// service-account JWT is ~800 bytes; the header and claims are at the front, so
// a prefix is enough to identify the account.
const tokenLogLimit = 1024

type Service struct {
	addr    string
	version string
	tlsCert tls.Certificate
}

// New loads or creates the server certificate. The SANs match what a real
// apiserver presents, so anything that inspects the certificate sees the right
// shape even though it will not chain to a trusted CA.
func New(addr, version, certPath, keyPath string) (*Service, error) {
	cert, err := tlsutil.LoadOrCreate(certPath, keyPath, "kube-apiserver", []string{
		"kubernetes",
		"kubernetes.default",
		"kubernetes.default.svc",
		"kubernetes.default.svc.cluster.local",
		"localhost",
		"127.0.0.1",
		"10.96.0.1",
	})
	if err != nil {
		return nil, fmt.Errorf("k8s certificate: %w", err)
	}
	return &Service{addr: addr, version: version, tlsCert: cert}, nil
}

func (s *Service) Name() string { return name }
func (s *Service) Addr() string { return s.addr }

func (s *Service) Serve(ctx context.Context, ln net.Listener, emit event.Emitter) error {
	_, dstPort := event.SplitAddr(ln.Addr())

	// The apiserver is TLS-only; a plaintext listener on 6443 would be an
	// immediate tell, and kubectl would refuse to talk to it at all.
	tlsLn := tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{s.tlsCert}})

	srv := &http.Server{
		Handler:           s.handler(dstPort, emit),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
	}
	go func() {
		<-ctx.Done()
		_ = srv.Close()
	}()

	if err := srv.Serve(tlsLn); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func (s *Service) handler(dstPort int, emit event.Emitter) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		ev := s.baseEvent(r, dstPort, "resource_access")

		switch {
		case r.URL.Path == "/version":
			ev.Kind = "probe"
			emit.Emit(ev)
			writeJSON(w, http.StatusOK, s.versionInfo())
			return

		case r.URL.Path == "/api":
			ev.Kind = "discovery"
			emit.Emit(ev)
			writeJSON(w, http.StatusOK, apiVersions)
			return

		case r.URL.Path == "/apis":
			ev.Kind = "discovery"
			emit.Emit(ev)
			writeJSON(w, http.StatusOK, apiGroups)
			return

		case r.URL.Path == "/healthz", r.URL.Path == "/livez", r.URL.Path == "/readyz":
			ev.Kind = "probe"
			emit.Emit(ev)
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			_, _ = w.Write([]byte("ok"))
			return
		}

		// Everything else is an attempt to reach a real resource.
		resource := resourceFrom(r.URL.Path)
		ev.Data["resource"] = resource
		emit.Emit(ev)

		writeJSON(w, http.StatusForbidden, forbidden(resource, r.URL.Path))
	})

	return mux
}

func (s *Service) baseEvent(r *http.Request, dstPort int, kind string) event.Event {
	srcIP, srcPort := event.SplitHostPortString(r.RemoteAddr)
	ev := event.NewRaw(name, kind, srcIP, srcPort, dstPort)
	ev.Data["method"] = r.Method
	ev.Data["path"] = r.URL.RequestURI()
	ev.Data["user_agent"] = r.UserAgent()

	// The credential. A presented bearer token means someone is using stolen
	// cluster access, which is a categorically different event from a scan —
	// so it gets its own kind rather than hiding in the request data.
	if auth := r.Header.Get("Authorization"); auth != "" {
		ev.Kind = "auth_attempt"
		scheme, credential, _ := strings.Cut(auth, " ")
		ev.Data["auth_scheme"] = scheme
		ev.Data["token"] = truncate(credential, tokenLogLimit)
	}

	// A client certificate is the other way in, and identifies the subject
	// directly.
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		ev.Kind = "auth_attempt"
		ev.Data["client_cert_subject"] = r.TLS.PeerCertificates[0].Subject.String()
	}

	return ev
}

func (s *Service) versionInfo() map[string]any {
	major, minor, _ := strings.Cut(strings.TrimPrefix(s.version, "v"), ".")
	minor, _, _ = strings.Cut(minor, ".")
	return map[string]any{
		"major":        major,
		"minor":        minor,
		"gitVersion":   s.version,
		"gitCommit":    "55f1d5b3e46a37f0d2c3d3eb0e4a4c5f6b7c8d9e",
		"gitTreeState": "clean",
		"buildDate":    "2026-04-16T10:22:31Z",
		"goVersion":    "go1.21.9",
		"compiler":     "gc",
		"platform":     "linux/amd64",
	}
}

// resourceFrom extracts the resource name an attacker was reaching for, so the
// 403 message names it the way a real apiserver would. Paths look like
// /api/v1/namespaces/default/pods or /apis/apps/v1/deployments.
func resourceFrom(path string) string {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) == 0 {
		return "resource"
	}
	last := parts[len(parts)-1]
	if last == "" {
		return "resource"
	}
	return last
}

// forbidden builds the apiserver's real 403 body. The exact wording matters:
// tooling and attackers both pattern-match on it.
func forbidden(resource, path string) map[string]any {
	group := ""
	if strings.HasPrefix(path, "/apis/") {
		if parts := strings.Split(strings.Trim(path, "/"), "/"); len(parts) > 1 {
			group = parts[1]
		}
	}
	msg := fmt.Sprintf(
		"%s is forbidden: User \"system:anonymous\" cannot list resource \"%s\" in API group \"%s\" at the cluster scope",
		resource, resource, group)

	return map[string]any{
		"kind":       "Status",
		"apiVersion": "v1",
		"metadata":   map[string]any{},
		"status":     "Failure",
		"message":    msg,
		"reason":     "Forbidden",
		"details":    map[string]any{"kind": resource, "group": group},
		"code":       403,
	}
}

var apiVersions = map[string]any{
	"kind":     "APIVersions",
	"versions": []string{"v1"},
	"serverAddressByClientCIDRs": []map[string]string{
		{"clientCIDR": "0.0.0.0/0", "serverAddress": "10.0.0.1:6443"},
	},
}

var apiGroups = map[string]any{
	"kind":       "APIGroupList",
	"apiVersion": "v1",
	"groups":     buildGroups(),
}

func buildGroups() []map[string]any {
	specs := []struct{ name, version string }{
		{"apps", "v1"},
		{"batch", "v1"},
		{"rbac.authorization.k8s.io", "v1"},
		{"networking.k8s.io", "v1"},
		{"apiextensions.k8s.io", "v1"},
	}
	groups := make([]map[string]any, 0, len(specs))
	for _, s := range specs {
		gv := s.name + "/" + s.version
		groups = append(groups, map[string]any{
			"name":             s.name,
			"versions":         []map[string]string{{"groupVersion": gv, "version": s.version}},
			"preferredVersion": map[string]string{"groupVersion": gv, "version": s.version},
		})
	}
	return groups
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "...[truncated]"
}
