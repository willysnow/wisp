// Package tlsutil provides the self-signed certificates that TLS-only decoys
// need.
//
// Certificates are persisted for the same reason SSH host keys are: one that
// changes on every restart is a honeypot fingerprint. An attacker who connects
// twice and sees a different certificate learns more about us than we learn
// about them.
package tlsutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"strings"
	"time"
)

// validity is how long a generated certificate lasts. Real cluster certificates
// are typically issued for a year; an obviously long-lived one stands out.
const validity = 365 * 24 * time.Hour

// LoadOrCreate returns the certificate at certPath/keyPath, generating a
// self-signed one if either file is missing.
//
// commonName and names shape the generated certificate's subject and SANs —
// pass what the service being impersonated would really present.
func LoadOrCreate(certPath, keyPath, commonName string, names []string) (tls.Certificate, error) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err == nil {
		return cert, nil
	}
	if !os.IsNotExist(err) && !isMissingFile(certPath, keyPath) {
		return tls.Certificate{}, fmt.Errorf("load certificate: %w", err)
	}

	certPEM, keyPEM, err := generate(commonName, names)
	if err != nil {
		return tls.Certificate{}, err
	}
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		return tls.Certificate{}, err
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return tls.Certificate{}, err
	}
	return tls.X509KeyPair(certPEM, keyPEM)
}

// ClientConfig builds the TLS settings a sensor uses to reach its console.
//
// A console on an internal segment usually has no publicly trusted
// certificate, and "just turn verification off" would hand every captured
// credential — and the sensor's own token — to anyone able to intercept the
// connection. So there are two ways to trust a private certificate properly,
// and the insecure option is last, named for what it is.
//
// Precedence is fingerprint, then CA file, then insecure, then system roots.
func ClientConfig(caFile, fingerprint string, insecure bool) (*tls.Config, error) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}

	switch {
	case fingerprint != "":
		want, err := parseFingerprint(fingerprint)
		if err != nil {
			return nil, err
		}
		// Pinning replaces chain verification rather than adding to it: a
		// self-signed console has no chain to check, and the leaf's hash is a
		// stronger statement than any CA's signature would be here.
		cfg.InsecureSkipVerify = true
		cfg.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return fmt.Errorf("console presented no certificate")
			}
			got := sha256.Sum256(rawCerts[0])
			if subtle.ConstantTimeCompare(got[:], want) != 1 {
				return fmt.Errorf("console certificate fingerprint mismatch: got %s",
					formatFingerprint(got[:]))
			}
			return nil
		}

	case caFile != "":
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("console ca_file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("console ca_file %s: no certificate found", caFile)
		}
		cfg.RootCAs = pool

	case insecure:
		cfg.InsecureSkipVerify = true

	default:
		return nil, nil // system roots; net/http's own default is fine
	}

	return cfg, nil
}

// parseFingerprint accepts the SHA-256 forms people actually paste: with
// colons, with spaces, upper or lower case.
func parseFingerprint(s string) ([]byte, error) {
	cleaned := strings.NewReplacer(":", "", " ", "", "-", "").Replace(strings.TrimSpace(s))

	raw, err := hex.DecodeString(strings.ToLower(cleaned))
	if err != nil {
		return nil, fmt.Errorf("fingerprint: not hexadecimal: %w", err)
	}
	if len(raw) != sha256.Size {
		return nil, fmt.Errorf("fingerprint: want a %d-byte SHA-256, got %d bytes",
			sha256.Size, len(raw))
	}
	return raw, nil
}

func formatFingerprint(sum []byte) string {
	hexed := hex.EncodeToString(sum)
	pairs := make([]string, 0, len(sum))
	for i := 0; i < len(hexed); i += 2 {
		pairs = append(pairs, hexed[i:i+2])
	}
	return strings.ToUpper(strings.Join(pairs, ":"))
}

func isMissingFile(paths ...string) bool {
	for _, p := range paths {
		if _, err := os.Stat(p); os.IsNotExist(err) {
			return true
		}
	}
	return false
}

func generate(commonName string, names []string) (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}

	// Split the requested SANs into DNS names and IP addresses; x509 keeps them
	// in separate fields and a hostname in the IP list is silently ignored.
	var dnsNames []string
	var ips []net.IP
	for _, n := range names {
		if ip := net.ParseIP(n); ip != nil {
			ips = append(ips, ip)
			continue
		}
		dnsNames = append(dnsNames, n)
	}

	now := time.Now()
	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             now.Add(-time.Hour), // tolerate mild clock skew
		NotAfter:              now.Add(validity),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              dnsNames,
		IPAddresses:           ips,
	}

	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM, nil
}
