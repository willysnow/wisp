package console

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"

	"github.com/willysnow/wisp/internal/tlsutil"
)

// TLSMode selects how the console gets a certificate.
type TLSMode string

const (
	// TLSOff serves plain HTTP. Only correct behind a reverse proxy that
	// terminates TLS itself.
	TLSOff TLSMode = "off"
	// TLSFile uses a certificate and key you already have.
	TLSFile TLSMode = "file"
	// TLSACME obtains one from Let's Encrypt. Needs a public DNS name.
	TLSACME TLSMode = "acme"
	// TLSSelfSigned generates and persists its own. The right answer for a
	// console on an internal segment with no public name — which is most of
	// them.
	TLSSelfSigned TLSMode = "self-signed"
)

// defaultACMEDirectory is Let's Encrypt production. Overridable so the staging
// endpoint can be used while working out a deployment, instead of burning the
// production rate limit on a typo.
const defaultACMEDirectory = "https://acme-v02.api.letsencrypt.org/directory"

// TLSConfig is the console's TLS section.
type TLSConfig struct {
	// Mode is off, file, acme, or self-signed. Empty means off.
	Mode string `yaml:"mode"`

	// CertFile and KeyFile are the certificate in file mode, and where the
	// generated pair is kept in self-signed mode.
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`

	// Domains are the names to obtain (acme) or to put in the SANs
	// (self-signed). ACME issues for exactly this list and nothing else.
	Domains []string `yaml:"domains"`

	// Email is passed to the ACME account, so the CA can warn about expiry.
	Email string `yaml:"email"`

	// AcceptTOS records that you accept the CA's terms of service. ACME will
	// not run without it, because agreeing to a contract on an operator's
	// behalf is not the software's call.
	AcceptTOS bool `yaml:"accept_tos"`

	// CacheDir holds ACME account keys and issued certificates. Keep it: losing
	// it means re-issuing on every restart, which hits rate limits fast.
	CacheDir string `yaml:"cache_dir"`

	// Directory overrides the ACME endpoint. Empty means Let's Encrypt
	// production; point it at their staging URL while you are still testing.
	Directory string `yaml:"directory"`

	// HTTPAddr is a plain listener that redirects to HTTPS, and serves the
	// HTTP-01 challenge in acme mode. Empty means no plain listener at all.
	HTTPAddr string `yaml:"http_addr"`
}

// TLS is a resolved TLS setup, ready to hand to net/http.
type TLS struct {
	Mode TLSMode

	// Config is nil in off mode.
	Config *tls.Config

	// HTTPAddr and HTTPHandler describe the optional plain-HTTP listener.
	HTTPAddr    string
	HTTPHandler http.Handler

	// Fingerprint is the SHA-256 of the served certificate, in self-signed
	// mode. It is printed at startup so an operator can pin it on the sensors
	// rather than turning verification off.
	Fingerprint string
}

// Enabled reports whether the console terminates TLS itself.
func (t *TLS) Enabled() bool { return t != nil && t.Config != nil }

// TLSSetup resolves the TLS section into something servable.
func (c *Config) TLSSetup() (*TLS, error) {
	t := c.TLS

	switch TLSMode(t.Mode) {
	case "", TLSOff:
		if t.HTTPAddr != "" {
			return nil, fmt.Errorf("tls.http_addr: set but tls.mode is off — " +
				"the console already serves plain HTTP on -addr")
		}
		return &TLS{Mode: TLSOff}, nil

	case TLSFile:
		if t.CertFile == "" || t.KeyFile == "" {
			return nil, fmt.Errorf("tls.mode file: cert_file and key_file are both required")
		}
		cert, err := tls.LoadX509KeyPair(t.CertFile, t.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("tls: %w", err)
		}
		return &TLS{
			Mode:        TLSFile,
			Config:      baseTLSConfig(cert),
			HTTPAddr:    t.HTTPAddr,
			HTTPHandler: redirectToHTTPS(),
		}, nil

	case TLSSelfSigned:
		certFile, keyFile := t.CertFile, t.KeyFile
		if certFile == "" {
			certFile = "console-cert.pem"
		}
		if keyFile == "" {
			keyFile = "console-key.pem"
		}

		names := t.Domains
		if len(names) == 0 {
			// Whatever the machine calls itself, plus loopback, so a sensor on
			// the same host and an operator on the LAN both validate.
			host, _ := os.Hostname()
			names = []string{host, "localhost", "127.0.0.1", "::1"}
		}
		cert, err := tlsutil.LoadOrCreate(certFile, keyFile, names[0], names)
		if err != nil {
			return nil, fmt.Errorf("tls: %w", err)
		}
		return &TLS{
			Mode:        TLSSelfSigned,
			Config:      baseTLSConfig(cert),
			HTTPAddr:    t.HTTPAddr,
			HTTPHandler: redirectToHTTPS(),
			Fingerprint: fingerprint(cert),
		}, nil

	case TLSACME:
		switch {
		case len(t.Domains) == 0:
			return nil, fmt.Errorf("tls.mode acme: at least one domain is required")
		case !t.AcceptTOS:
			return nil, fmt.Errorf("tls.mode acme: set tls.accept_tos to confirm you " +
				"accept the certificate authority's terms of service")
		}

		m := &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(t.Domains...),
			Email:      t.Email,
			Cache:      autocert.DirCache(cacheDirOrDefault(t.CacheDir)),
		}
		if dir := t.Directory; dir != "" && dir != defaultACMEDirectory {
			m.Client = &acme.Client{DirectoryURL: dir}
		}

		cfg := m.TLSConfig()
		cfg.MinVersion = tls.VersionTLS12

		out := &TLS{Mode: TLSACME, Config: cfg, HTTPAddr: t.HTTPAddr}
		if out.HTTPAddr != "" {
			// With a plain listener the HTTP-01 challenge becomes available and
			// everything else is redirected. Without one, issuance relies on
			// TLS-ALPN-01 over 443 alone, which is fine and needs no port 80.
			out.HTTPHandler = m.HTTPHandler(redirectToHTTPS())
		}
		return out, nil
	}

	return nil, fmt.Errorf("tls.mode: want off, file, acme, or self-signed, got %q", t.Mode)
}

func baseTLSConfig(cert tls.Certificate) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		// 1.2 rather than 1.3: sensors are Go clients and would negotiate 1.3
		// anyway, but an operator's older browser on a locked-down workstation
		// should still be able to open the console.
		MinVersion: tls.VersionTLS12,
	}
}

func cacheDirOrDefault(dir string) string {
	if dir == "" {
		return "acme-cache"
	}
	return dir
}

// redirectToHTTPS answers every plain-HTTP request with a permanent redirect.
// The console is only ever reached by an operator's browser and by sensors
// carrying a bearer token; neither should be allowed to continue in the clear.
func redirectToHTTPS() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if h, _, err := net.SplitHostPort(r.Host); err == nil {
			host = h
		}
		http.Redirect(w, r, "https://"+host+r.URL.RequestURI(), http.StatusPermanentRedirect)
	})
}

// fingerprint is the SHA-256 of the leaf certificate, formatted the way openssl
// and browsers show it, so an operator can compare the two by eye.
func fingerprint(cert tls.Certificate) string {
	if len(cert.Certificate) == 0 {
		return ""
	}
	sum := sha256.Sum256(cert.Certificate[0])

	hexed := hex.EncodeToString(sum[:])
	pairs := make([]string, 0, len(sum))
	for i := 0; i < len(hexed); i += 2 {
		pairs = append(pairs, hexed[i:i+2])
	}
	return strings.ToUpper(strings.Join(pairs, ":"))
}
