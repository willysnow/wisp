// Package proxysvc emulates an HTTP forward proxy, the kind an intruder scans
// for to borrow someone else's egress.
//
// Two signals come out of it. The first is intent: a proxy request states where
// the client wanted to go — a CONNECT to a host and port, or an absolute-form
// GET for a URL. That target is often the whole story. A CONNECT to an internal
// address or to 169.254.169.254 is an SSRF pivot using the decoy as the hop; a
// GET for a well-known site is an open-proxy checker confirming the relay works.
// The decoy records the target and never makes the connection — it is a sensor,
// not an open relay.
//
// The second is credentials. The decoy answers every request with 407 Proxy
// Authentication Required, the way a closed proxy does, which invites a client
// that has credentials to send them. A Proxy-Authorization Basic header is
// base64, not a hash, so what comes out is the cleartext proxy password, logged
// as a login_password event like any other captured credential.
//
// Nothing is ever proxied. Every request ends in 407, so the decoy never opens
// an outbound connection on an intruder's behalf.
package proxysvc

import (
	"context"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/willysnow/wisp/internal/event"
	"github.com/willysnow/wisp/internal/service/httpdecoy"
)

const name = "http-proxy"

// logLimit bounds any single captured field before it reaches the event log.
const logLimit = 2048

type Service struct {
	addr string
	// serverHeader and realm shape the disguise: what product the proxy claims
	// to be, and the realm named in its authentication challenge.
	serverHeader string
	realm        string
}

// New builds the decoy. Empty values fall back to a Squid proxy, the most common
// thing found on 3128.
func New(addr, serverHeader, realm string) *Service {
	if serverHeader == "" {
		serverHeader = "squid/5.7"
	}
	if realm == "" {
		realm = "Squid proxy-caching web server"
	}
	return &Service{addr: addr, serverHeader: serverHeader, realm: realm}
}

func (s *Service) Name() string { return name }
func (s *Service) Addr() string { return s.addr }

func (s *Service) Serve(ctx context.Context, ln net.Listener, emit event.Emitter) error {
	_, dstPort := event.SplitAddr(ln.Addr())

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

	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func (s *Service) handler(dstPort int, emit event.Emitter) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		srcIP, srcPort := event.SplitHostPortString(r.RemoteAddr)

		ev := event.NewRaw(name, "proxy_request", srcIP, srcPort, dstPort)
		ev.Data["method"] = r.Method
		if ua := r.UserAgent(); ua != "" {
			ev.Data["user_agent"] = truncate(ua)
		}

		switch {
		case r.Method == http.MethodConnect:
			// CONNECT authority-form: the host:port the client wanted to tunnel.
			ev.Data["target"] = truncate(r.Host)
		case r.URL.IsAbs():
			// Absolute-form: the full URL the client wanted fetched through us.
			ev.Data["target"] = truncate(r.URL.String())
			ev.Data["target_host"] = truncate(r.URL.Host)
		default:
			// A direct hit on the proxy port with no proxy semantics — still a
			// probe worth recording, just with nothing to forward.
			ev.Data["direct"] = true
		}

		// Proxy-Authorization Basic is base64, not a hash, so the decoy recovers
		// the cleartext proxy password.
		if user, pass, ok := basicProxyAuth(r.Header.Get("Proxy-Authorization")); ok {
			ev.Kind = "login_password"
			ev.Data["username"] = truncate(user)
			ev.Data["password"] = truncate(pass)
		} else if pa := r.Header.Get("Proxy-Authorization"); pa != "" {
			// A non-Basic scheme (Digest, Negotiate) — no cleartext, but the
			// scheme is still worth noting.
			ev.Data["proxy_auth"] = truncate(schemeOf(pa))
		}

		emit.Emit(ev)

		// Always demand authentication and never forward. A closed proxy is what
		// makes a client offer its credentials; opening the tunnel would make the
		// decoy an actual relay.
		w.Header().Set("Server", s.serverHeader)
		w.Header().Set("Proxy-Authenticate", `Basic realm="`+s.realm+`"`)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusProxyAuthRequired)
		_, _ = w.Write([]byte("Proxy authentication required.\n"))
	})
}

// basicProxyAuth decodes a "Basic base64(user:pass)" Proxy-Authorization value.
func basicProxyAuth(header string) (user, pass string, ok bool) {
	const prefix = "Basic "
	if len(header) < len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
		return "", "", false
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(header[len(prefix):]))
	if err != nil {
		return "", "", false
	}
	u, p, found := strings.Cut(string(raw), ":")
	if !found {
		return "", "", false
	}
	return u, p, true
}

// schemeOf returns the first token of an authorization header — its scheme.
func schemeOf(header string) string {
	if i := strings.IndexByte(header, ' '); i >= 0 {
		return header[:i]
	}
	return header
}

func truncate(s string) string { return httpdecoy.Truncate(s, logLimit) }
