package k8ssvc

import (
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/willysnow/wisp/internal/service"
	"github.com/willysnow/wisp/internal/service/servicetest"
)

func start(t *testing.T) (*servicetest.StreamHarness, *http.Client, string) {
	t.Helper()

	dir := t.TempDir()
	h := servicetest.StartStream(t, func(addr string) service.StreamService {
		svc, err := New(addr, "v1.29.4",
			filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem"))
		if err != nil {
			t.Fatalf("new: %v", err)
		}
		return svc
	})

	// The decoy presents a certificate that cannot chain to anything, which is
	// what a real apiserver looks like to a client without the cluster CA. The
	// test client skips verification for the same reason kubectl's
	// --insecure-skip-tls-verify exists, and because a TLS-inspecting agent on
	// the machine running the tests would otherwise break this.
	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // see above
		Proxy:           nil,
	}}
	return h, client, "https://" + h.Addr
}

func get(t *testing.T, client *http.Client, url, token string) (*http.Response, string) {
	t.Helper()

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("get %s: %v", url, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return resp, string(body)
}

// TestStolenTokenIsCaptured is what the decoy exists for. Knowing which service
// account was compromised is far more actionable than knowing someone knocked.
func TestStolenTokenIsCaptured(t *testing.T) {
	h, client, base := start(t)

	const token = "eyJhbGciOiJSUzI1NiIsImtpZCI6InN0b2xlbiJ9.eyJzdWIiOiJzeXN0ZW06c2Vy" +
		"dmljZWFjY291bnQ6a3ViZS1zeXN0ZW06ZGVwbG95ZXIifQ.signature"
	get(t, client, base+"/api/v1/namespaces/kube-system/secrets", token)

	ev := h.WaitFor(t, "auth_attempt")
	captured, _ := ev.Data["token"].(string)
	if !strings.HasPrefix(captured, "eyJhbGciOiJSUzI1NiIs") {
		t.Errorf("token = %q, want the presented credential", captured)
	}
	if path, _ := ev.Data["path"].(string); !strings.Contains(path, "secrets") {
		t.Errorf("path = %v, want the resource they were after", ev.Data["path"])
	}
}

// TestAnswers403Not401 is the design decision the module rests on.
//
// 401 reads as "wrong door" and ends the interaction. 403 reads as "right door,
// wrong credentials", so the attacker retries with a stolen token — and the
// token is the thing worth having.
func TestAnswers403Not401(t *testing.T) {
	_, client, base := start(t)

	for _, path := range []string{
		"/api/v1/pods",
		"/api/v1/namespaces/default/secrets",
		"/apis/apps/v1/deployments",
	} {
		resp, body := get(t, client, base+path, "")

		if resp.StatusCode == http.StatusUnauthorized {
			t.Fatalf("%s returned 401 — that ends the conversation", path)
		}
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("%s returned %d, want 403", path, resp.StatusCode)
		}

		var status map[string]any
		if err := json.Unmarshal([]byte(body), &status); err != nil {
			t.Fatalf("%s body is not a Status object: %v", path, err)
		}
		if status["kind"] != "Status" || status["reason"] != "Forbidden" {
			t.Errorf("%s body = %v, want an apiserver Status", path, status)
		}
	}
}

// TestDiscoveryLooksLikeACluster: /version and /api are what kubectl and every
// scanner call first, and an apiserver that cannot answer them is not one.
func TestDiscoveryLooksLikeACluster(t *testing.T) {
	h, client, base := start(t)

	resp, body := get(t, client, base+"/version", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/version returned %d, want 200", resp.StatusCode)
	}

	var version map[string]any
	if err := json.Unmarshal([]byte(body), &version); err != nil {
		t.Fatalf("/version is not JSON: %v", err)
	}
	if version["gitVersion"] != "v1.29.4" {
		t.Errorf("gitVersion = %v, want the configured version", version["gitVersion"])
	}
	if version["major"] == nil || version["platform"] == nil {
		t.Errorf("/version = %v, missing fields a real one has", version)
	}

	if resp, _ := get(t, client, base+"/api", ""); resp.StatusCode != http.StatusOK {
		t.Errorf("/api returned %d, want 200", resp.StatusCode)
	}

	h.WaitFor(t, "discovery")
}

// TestCertificateLooksLikeAnAPIServer: anything that inspects the certificate
// sees the names a real one presents, even though it chains to nothing.
func TestCertificateLooksLikeAnAPIServer(t *testing.T) {
	_, _, base := start(t)

	conn, err := tls.Dial("tcp", strings.TrimPrefix(base, "https://"),
		&tls.Config{InsecureSkipVerify: true}) //nolint:gosec // inspecting, not trusting
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	leaf := conn.ConnectionState().PeerCertificates[0]
	if leaf.Subject.CommonName != "kube-apiserver" {
		t.Errorf("CommonName = %q, want kube-apiserver", leaf.Subject.CommonName)
	}

	names := strings.Join(leaf.DNSNames, ",")
	for _, want := range []string{"kubernetes", "kubernetes.default.svc"} {
		if !strings.Contains(names, want) {
			t.Errorf("SANs %q missing %q", names, want)
		}
	}
}

// TestCertificateIsReused across restarts. One that changed every restart would
// identify the box as a honeypot to anyone who connected twice.
func TestCertificateIsReused(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")

	first, err := New("127.0.0.1:0", "v1.29.4", certPath, keyPath)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	second, err := New("127.0.0.1:0", "v1.29.4", certPath, keyPath)
	if err != nil {
		t.Fatalf("new again: %v", err)
	}

	if string(first.tlsCert.Certificate[0]) != string(second.tlsCert.Certificate[0]) {
		t.Error("the certificate changed between restarts — that is a honeypot fingerprint")
	}
}

// TestAnonymousRequestIsRecordedWithoutACredential.
//
// Someone enumerating the cluster without a token is still worth an event —
// but it must not read as an authentication attempt, or the alerts that
// actually carry a stolen credential get lost among the ones that do not.
func TestAnonymousRequestIsRecordedWithoutACredential(t *testing.T) {
	h, client, base := start(t)

	get(t, client, base+"/api/v1/nodes", "")

	ev := h.WaitFor(t, "resource_access")
	if _, hasToken := ev.Data["token"]; hasToken {
		t.Error("a token was recorded for a request that carried none")
	}
	if h.Count("auth_attempt") > 0 {
		t.Error("an anonymous request was recorded as an authentication attempt")
	}
	if res, _ := ev.Data["resource"].(string); res == "" {
		t.Errorf("no resource recorded: %v", ev.Data)
	}
}
