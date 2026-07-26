package tlsutil

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"path/filepath"
	"strings"
	"testing"
)

// newCert generates a certificate and returns it with its files and
// fingerprint.
//
// The tests verify ClientConfig's decisions directly rather than over a real
// handshake: any TLS-inspecting agent on the machine running the tests would
// substitute its own certificate, and a pinning check is supposed to fail when
// that happens. Testing the callback keeps the property under test instead of
// the local network stack.
func newCert(t *testing.T) (cert tls.Certificate, certPath, fingerprint string) {
	t.Helper()

	dir := t.TempDir()
	certPath = filepath.Join(dir, "cert.pem")

	cert, err := LoadOrCreate(certPath, filepath.Join(dir, "key.pem"),
		"console.internal", []string{"console.internal", "127.0.0.1", "::1"})
	if err != nil {
		t.Fatalf("generate certificate: %v", err)
	}

	sum := sha256.Sum256(cert.Certificate[0])
	return cert, certPath, formatFingerprint(sum[:])
}

// TestPinnedFingerprintAccepted is the path that lets a sensor trust a
// self-signed console without turning verification off.
func TestPinnedFingerprintAccepted(t *testing.T) {
	cert, _, fp := newCert(t)

	cfg, err := ClientConfig("", fp, false)
	if err != nil {
		t.Fatalf("client config: %v", err)
	}
	if cfg.VerifyPeerCertificate == nil {
		t.Fatal("no verification callback was installed")
	}
	if err := cfg.VerifyPeerCertificate(cert.Certificate, nil); err != nil {
		t.Errorf("the pinned certificate was rejected: %v", err)
	}
}

// TestWrongFingerprintRejected is the property that makes pinning worth having.
// A different certificate is what an interception looks like, and it must fail.
func TestWrongFingerprintRejected(t *testing.T) {
	_, _, fp := newCert(t)
	impostor, _, _ := newCert(t)

	cfg, err := ClientConfig("", fp, false)
	if err != nil {
		t.Fatalf("client config: %v", err)
	}

	err = cfg.VerifyPeerCertificate(impostor.Certificate, nil)
	if err == nil {
		t.Fatal("a certificate with the wrong fingerprint was accepted")
	}
	if !strings.Contains(err.Error(), "fingerprint mismatch") {
		t.Errorf("rejected for the wrong reason: %v", err)
	}
}

// TestNoCertificateRejected: an empty chain must not read as "nothing to
// check, therefore fine".
func TestNoCertificateRejected(t *testing.T) {
	_, _, fp := newCert(t)

	cfg, err := ClientConfig("", fp, false)
	if err != nil {
		t.Fatalf("client config: %v", err)
	}
	if err := cfg.VerifyPeerCertificate(nil, nil); err == nil {
		t.Error("an empty certificate chain was accepted")
	}
}

// TestCAFileTrusted covers the other supported route: hand the sensor the
// console's certificate and let x509 do the verifying.
func TestCAFileTrusted(t *testing.T) {
	cert, certPath, _ := newCert(t)

	cfg, err := ClientConfig(certPath, "", false)
	if err != nil {
		t.Fatalf("client config: %v", err)
	}
	if cfg.RootCAs == nil {
		t.Fatal("ca_file did not produce a root pool")
	}
	if cfg.InsecureSkipVerify {
		t.Error("ca_file also turned verification off")
	}

	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:   cfg.RootCAs,
		DNSName: "console.internal",
	}); err != nil {
		t.Errorf("the console's own certificate did not verify against it: %v", err)
	}

	// And an unrelated certificate still does not.
	other, _, _ := newCert(t)
	otherLeaf, err := x509.ParseCertificate(other.Certificate[0])
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if _, err := otherLeaf.Verify(x509.VerifyOptions{
		Roots:   cfg.RootCAs,
		DNSName: "console.internal",
	}); err == nil {
		t.Error("a different certificate verified against the pinned CA")
	}
}

// TestMissingCAFileIsAnError: a typo in the path must stop the sensor, not
// silently fall back to trusting anything.
func TestMissingCAFileIsAnError(t *testing.T) {
	if _, err := ClientConfig(filepath.Join(t.TempDir(), "nope.pem"), "", false); err == nil {
		t.Error("a missing ca_file was accepted")
	}
	if _, err := ClientConfig("", "not-a-fingerprint", false); err == nil {
		t.Error("a malformed fingerprint was accepted")
	}
}

// TestUnverifiedByDefault documents the default: no TLS settings of our own,
// which means net/http's system roots.
func TestUnverifiedByDefault(t *testing.T) {
	cfg, err := ClientConfig("", "", false)
	if err != nil {
		t.Fatalf("client config: %v", err)
	}
	if cfg != nil {
		t.Errorf("expected nil config (system roots), got %+v", cfg)
	}
}

// TestInsecureSkipsVerification documents the escape hatch, and that nothing
// but asking for it turns it on.
func TestInsecureSkipsVerification(t *testing.T) {
	cfg, err := ClientConfig("", "", true)
	if err != nil {
		t.Fatalf("client config: %v", err)
	}
	if !cfg.InsecureSkipVerify {
		t.Error("insecure was requested but verification stayed on")
	}

	// Precedence: a fingerprint is still checked even when insecure is set, so
	// a leftover flag cannot quietly disable a pin.
	_, _, fp := newCert(t)
	pinned, err := ClientConfig("", fp, true)
	if err != nil {
		t.Fatalf("client config: %v", err)
	}
	if pinned.VerifyPeerCertificate == nil {
		t.Error("insecure_skip_verify overrode the pinned fingerprint")
	}
}

// TestFingerprintFormats accepts what people actually paste: the console's own
// colon-separated output, plus the bare hex another tool might print.
func TestFingerprintFormats(t *testing.T) {
	raw := make([]byte, sha256.Size)
	for i := range raw {
		raw[i] = byte(i)
	}
	colons := formatFingerprint(raw)
	bare := strings.ReplaceAll(colons, ":", "")

	for _, in := range []string{colons, bare, strings.ToLower(colons), " " + colons + " "} {
		got, err := parseFingerprint(in)
		if err != nil {
			t.Errorf("parseFingerprint(%q) failed: %v", in, err)
			continue
		}
		if string(got) != string(raw) {
			t.Errorf("parseFingerprint(%q) decoded to the wrong value", in)
		}
	}

	for _, in := range []string{"", "ab:cd", "zz" + strings.Repeat("00", 31)} {
		if _, err := parseFingerprint(in); err == nil {
			t.Errorf("parseFingerprint(%q) succeeded, want an error", in)
		}
	}
}
