package console

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestTLSOffByDefault: an empty config still starts, and says so by leaving the
// TLS setup disabled rather than half-configured.
func TestTLSOffByDefault(t *testing.T) {
	setup, err := (&Config{}).TLSSetup()
	if err != nil {
		t.Fatalf("TLSSetup: %v", err)
	}
	if setup.Enabled() {
		t.Error("TLS reported enabled with no configuration")
	}
	if setup.Mode != TLSOff {
		t.Errorf("Mode = %q, want %q", setup.Mode, TLSOff)
	}
}

// TestSelfSignedGeneratesAndPersists is the mode most consoles will use: an
// internal segment with no public DNS name.
func TestSelfSignedGeneratesAndPersists(t *testing.T) {
	dir := t.TempDir()
	cfg := &Config{TLS: TLSConfig{
		Mode:     string(TLSSelfSigned),
		CertFile: filepath.Join(dir, "cert.pem"),
		KeyFile:  filepath.Join(dir, "key.pem"),
		Domains:  []string{"console.internal"},
	}}

	setup, err := cfg.TLSSetup()
	if err != nil {
		t.Fatalf("TLSSetup: %v", err)
	}
	if !setup.Enabled() || len(setup.Config.Certificates) != 1 {
		t.Fatal("self-signed mode produced no certificate")
	}
	if setup.Fingerprint == "" {
		t.Error("no fingerprint to pin — the operator has nothing to give the sensors")
	}

	// A certificate that changes on restart is both a pinning nightmare and,
	// on the decoy side, a honeypot fingerprint. It must be reused.
	again, err := cfg.TLSSetup()
	if err != nil {
		t.Fatalf("second TLSSetup: %v", err)
	}
	if again.Fingerprint != setup.Fingerprint {
		t.Errorf("the certificate changed across restarts: %s then %s",
			setup.Fingerprint, again.Fingerprint)
	}
}

// TestACMERequiresExplicitConsent: accepting a certificate authority's terms is
// the operator's decision to record, not the software's to assume.
func TestACMERequiresExplicitConsent(t *testing.T) {
	cfg := &Config{TLS: TLSConfig{
		Mode:    string(TLSACME),
		Domains: []string{"console.example.com"},
	}}

	_, err := cfg.TLSSetup()
	if err == nil {
		t.Fatal("acme mode started without accept_tos")
	}
	if !strings.Contains(err.Error(), "accept_tos") {
		t.Errorf("unhelpful error: %v", err)
	}

	cfg.TLS.AcceptTOS = true
	setup, err := cfg.TLSSetup()
	if err != nil {
		t.Fatalf("TLSSetup with consent: %v", err)
	}
	if !setup.Enabled() || setup.Config.GetCertificate == nil {
		t.Error("acme mode did not install a certificate source")
	}
}

// TestTLSConfigErrors covers the mistakes that should stop startup rather than
// silently serve something other than what was asked for.
func TestTLSConfigErrors(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  TLSConfig
		want string
	}{
		{
			name: "acme without domains",
			cfg:  TLSConfig{Mode: string(TLSACME), AcceptTOS: true},
			want: "domain",
		},
		{
			name: "file without paths",
			cfg:  TLSConfig{Mode: string(TLSFile)},
			want: "cert_file",
		},
		{
			name: "file that does not exist",
			cfg:  TLSConfig{Mode: string(TLSFile), CertFile: "nope.pem", KeyFile: "nope-key.pem"},
			want: "tls:",
		},
		{
			name: "unknown mode",
			cfg:  TLSConfig{Mode: "sure-why-not"},
			want: "want off, file, acme, or self-signed",
		},
		{
			// A redirect listener with nothing to redirect to would send every
			// sensor into a loop.
			name: "http_addr with tls off",
			cfg:  TLSConfig{HTTPAddr: ":80"},
			want: "http_addr",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := (&Config{TLS: tc.cfg}).TLSSetup()
			if err == nil {
				t.Fatalf("accepted an invalid config")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

// TestFingerprintIsComparable checks the printed form is the one an operator
// sees elsewhere — colon-separated uppercase hex, as openssl and browsers show
// it. If it is not comparable by eye, nobody will compare it.
func TestFingerprintIsComparable(t *testing.T) {
	dir := t.TempDir()
	setup, err := (&Config{TLS: TLSConfig{
		Mode:     string(TLSSelfSigned),
		CertFile: filepath.Join(dir, "cert.pem"),
		KeyFile:  filepath.Join(dir, "key.pem"),
	}}).TLSSetup()
	if err != nil {
		t.Fatalf("TLSSetup: %v", err)
	}

	parts := strings.Split(setup.Fingerprint, ":")
	if len(parts) != 32 {
		t.Fatalf("fingerprint has %d parts, want 32", len(parts))
	}
	if setup.Fingerprint != strings.ToUpper(setup.Fingerprint) {
		t.Error("fingerprint is not uppercase")
	}
}
