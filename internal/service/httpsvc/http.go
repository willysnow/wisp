// Package httpsvc serves a fake device administration login.
//
// Two distinct signals come out of this: credentials POSTed to the form, and
// the set of paths probed. The path list alone often identifies the scanner
// (/shell?, /.env, /wp-login.php, /cgi-bin/…) before anyone types a password.
package httpsvc

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/willysnow/wisp/internal/event"
	"github.com/willysnow/wisp/internal/tlsutil"
)

const (
	name    = "http"
	tlsName = "https"
)

// maxBody caps how much of a request body we read. Credential forms are tiny;
// anything larger is either a probe or an attempt to exhaust our memory.
const maxBody = 64 << 10

type Service struct {
	name         string
	addr         string
	serverHeader string
	realm        string
	tlsConfig    *tls.Config
}

func New(addr, serverHeader, realm string) *Service {
	return &Service{name: name, addr: addr, serverHeader: serverHeader, realm: realm}
}

// NewTLS is the same decoy behind TLS, reported as a separate service so an
// operator can tell which door was tried.
//
// It is its own listener rather than a redirect from the plain one because the
// two attract different traffic: a scanner sweeping 443 never touches 80, and
// the certificate itself is part of the disguise — the SANs are what an
// attacker sees when they look at what this box claims to be.
func NewTLS(addr, serverHeader, realm, certPath, keyPath string, names []string) (*Service, error) {
	if len(names) == 0 {
		// Whatever the machine calls itself. A device's own admin panel
		// presenting a certificate for its hostname is the ordinary case.
		host, _ := os.Hostname()
		if host == "" {
			host = "localhost"
		}
		names = []string{host, "localhost", "127.0.0.1", "::1"}
	}

	cert, err := tlsutil.LoadOrCreate(certPath, keyPath, names[0], names)
	if err != nil {
		return nil, fmt.Errorf("https certificate: %w", err)
	}

	s := New(addr, serverHeader, realm)
	s.name = tlsName
	s.tlsConfig = &tls.Config{
		Certificates: []tls.Certificate{cert},
		// Deliberately permissive. Appliances with self-signed admin panels are
		// exactly the machines still speaking old TLS, and refusing a scanner's
		// handshake ends the interaction before it says anything.
		MinVersion: tls.VersionTLS10,
	}
	return s, nil
}

func (s *Service) Name() string { return s.name }
func (s *Service) Addr() string { return s.addr }

func (s *Service) Serve(ctx context.Context, ln net.Listener, emit event.Emitter) error {
	_, dstPort := event.SplitAddr(ln.Addr())

	if s.tlsConfig != nil {
		ln = tls.NewListener(ln, s.tlsConfig)
	}

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
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxBody)

		srcIP, srcPort := event.SplitHostPortString(r.RemoteAddr)
		kind := "probe"
		ev := event.NewRaw(s.name, kind, srcIP, srcPort, dstPort)
		ev.Data["method"] = r.Method
		ev.Data["path"] = r.URL.RequestURI()
		ev.Data["user_agent"] = r.UserAgent()

		// The name in SNI is what the client expected to find here, which is
		// often more informative than the path: a scanner sweeping addresses
		// sends none, while someone who came looking for a specific host sends
		// the name they were given.
		if r.TLS != nil && r.TLS.ServerName != "" {
			ev.Data["sni"] = r.TLS.ServerName
		}

		// HTTP Basic auth: some scanners try it before finding the form.
		if user, pass, ok := r.BasicAuth(); ok {
			ev.Kind = "login_basic"
			ev.Data["username"] = user
			ev.Data["password"] = pass
		}

		if r.Method == http.MethodPost {
			if err := r.ParseForm(); err == nil {
				if u, p, ok := credentialsFrom(r); ok {
					ev.Kind = "login_form"
					ev.Data["username"] = u
					ev.Data["password"] = p
				}
			}
		}
		emit.Emit(ev)

		w.Header().Set("Server", s.serverHeader)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")

		// Always "wrong password" — never grant access, never say the account
		// does not exist. Both would let the attacker enumerate.
		if ev.Kind == "login_form" || ev.Kind == "login_basic" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(strings.Replace(loginPage, "{{ERROR}}",
				`<p class="err">Invalid username or password.</p>`, 1)))
			return
		}
		_, _ = w.Write([]byte(strings.Replace(loginPage, "{{ERROR}}", "", 1)))
	})
	return mux
}

// credentialsFrom pulls a username/password pair out of a posted form,
// tolerating the field names common admin panels use.
func credentialsFrom(r *http.Request) (user, pass string, ok bool) {
	userKeys := []string{"username", "user", "login", "uname", "email", "account"}
	passKeys := []string{"password", "pass", "passwd", "pwd"}

	for _, k := range userKeys {
		if v := r.PostForm.Get(k); v != "" {
			user = v
			break
		}
	}
	for _, k := range passKeys {
		if v := r.PostForm.Get(k); v != "" {
			pass = v
			break
		}
	}
	return user, pass, user != "" || pass != ""
}

const loginPage = `<!doctype html>
<html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Administration</title>
<style>
body{font:14px/1.5 -apple-system,Segoe UI,Roboto,sans-serif;background:#eef1f4;margin:0;
display:flex;min-height:100vh;align-items:center;justify-content:center}
.box{background:#fff;padding:32px 36px;border-radius:4px;box-shadow:0 1px 4px rgba(0,0,0,.15);width:320px}
h1{font-size:17px;margin:0 0 4px;color:#243b53}
.sub{color:#829ab1;font-size:12px;margin:0 0 20px}
label{display:block;font-size:12px;color:#486581;margin:12px 0 4px}
input{width:100%;padding:8px 10px;border:1px solid #d9e2ec;border-radius:3px;box-sizing:border-box}
button{width:100%;margin-top:20px;padding:9px;background:#2c5282;color:#fff;border:0;border-radius:3px;cursor:pointer}
.err{color:#c53030;font-size:12px;margin:12px 0 0}
.foot{color:#9fb3c8;font-size:11px;text-align:center;margin-top:18px}
</style></head><body>
<form class="box" method="post" action="/login.cgi">
<h1>Administration</h1>
<p class="sub">Please sign in to continue.</p>
<label for="username">Username</label>
<input id="username" name="username" autocomplete="off">
<label for="password">Password</label>
<input id="password" name="password" type="password" autocomplete="off">
<button type="submit">Sign in</button>
{{ERROR}}
<p class="foot">Firmware 2.1.14</p>
</form></body></html>
`
