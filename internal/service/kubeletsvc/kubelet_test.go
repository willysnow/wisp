package kubeletsvc

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
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
		svc, err := New(addr, "node-1",
			filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem"))
		if err != nil {
			t.Fatalf("new: %v", err)
		}
		return svc
	})

	// A kubelet's serving certificate is issued by the cluster CA, which no
	// client outside the cluster has. Skipping verification is what every tool
	// that talks to one from outside does, and it keeps a TLS-inspecting agent
	// on the test machine from breaking the suite.
	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // see above
		Proxy:           nil,
	}}
	return h, client, "https://" + h.Addr
}

func do(t *testing.T, client *http.Client, req *http.Request) (*http.Response, string) {
	t.Helper()

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", req.Method, req.URL, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return resp, string(body)
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
	return do(t, client, req)
}

func run(t *testing.T, client *http.Client, base, pod, cmd string) (*http.Response, string) {
	t.Helper()

	form := url.Values{"cmd": {cmd}}
	req, err := http.NewRequest(http.MethodPost,
		base+"/run/default/"+pod+"/payments-api", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return do(t, client, req)
}

// TestSubmittedCommandIsCaptured is what the decoy exists for. An intruder who
// reaches a kubelet's /run endpoint types what they came for, and that sentence
// is worth more than the fact that port 10250 was touched.
func TestSubmittedCommandIsCaptured(t *testing.T) {
	h, client, base := start(t)

	const cmd = "cat /var/run/secrets/kubernetes.io/serviceaccount/token"
	run(t, client, base, appPod, cmd)

	ev := h.WaitFor(t, "command")
	if got, _ := ev.Data["cmd"].(string); got != cmd {
		t.Errorf("cmd = %q, want %q", got, cmd)
	}
	if got, _ := ev.Data["pod"].(string); got != appPod {
		t.Errorf("pod = %q, want %q", got, appPod)
	}
	if got, _ := ev.Data["namespace"].(string); got != "default" {
		t.Errorf("namespace = %q, want default", got)
	}
}

// TestNothingIsExecuted. The decoy answers commands from a table, and a
// regression that turned that into a real exec would hand an intruder the
// machine the sensor is running on. The property is worth a test that fails
// loudly rather than a comment saying it must not happen.
func TestNothingIsExecuted(t *testing.T) {
	_, client, base := start(t)

	proof := filepath.Join(t.TempDir(), "executed")
	run(t, client, base, appPod, "touch "+proof)
	run(t, client, base, appPod, "sh -c 'touch "+proof+"'")

	if _, err := os.Stat(proof); !os.IsNotExist(err) {
		t.Fatalf("the decoy executed a submitted command — %s exists", proof)
	}
}

// TestKnownCommandsAnswerPlausibly. An `id` that comes back empty reads as a
// broken endpoint and ends the interaction; `uid=0(root)` gets a second command,
// and the second command is usually the one that says what they came for.
func TestKnownCommandsAnswerPlausibly(t *testing.T) {
	_, client, base := start(t)

	resp, body := run(t, client, base, appPod, "id")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/run returned %d, want 200", resp.StatusCode)
	}
	if !strings.Contains(body, "uid=0(root)") {
		t.Errorf("id returned %q, want a root identity", body)
	}

	if _, body := run(t, client, base, appPod, "hostname"); !strings.Contains(body, appPod) {
		t.Errorf("hostname returned %q, want the pod it was run in", body)
	}
}

// TestStreamingExecCommandIsCapturedBeforeTheUpgradeFails.
//
// /exec needs a SPDY upgrade this decoy will not complete, but the command is
// in the query string and arrives before any of that. Losing it because the
// handshake failed would mean losing the capture for every tool that prefers
// the streaming endpoint.
func TestStreamingExecCommandIsCapturedBeforeTheUpgradeFails(t *testing.T) {
	h, client, base := start(t)

	get(t, client, base+"/exec/default/"+dbPod+"/postgres?command=psql&command=-c&command=SELECT+*+FROM+cards", "")

	ev := h.WaitFor(t, "command")
	cmd, _ := ev.Data["cmd"].(string)
	if !strings.Contains(cmd, "SELECT * FROM cards") {
		t.Errorf("cmd = %q, want the query they came for", cmd)
	}
}

// TestPodListNamesSomethingWorthBreakingInto. /pods is the reconnaissance call,
// and its answer is what turns the next request into a command rather than
// another scan. A node with nothing interesting on it is not worth a second
// packet.
func TestPodListNamesSomethingWorthBreakingInto(t *testing.T) {
	h, client, base := start(t)

	resp, body := get(t, client, base+"/pods", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/pods returned %d, want 200", resp.StatusCode)
	}

	var list struct {
		Kind  string `json:"kind"`
		Items []struct {
			Metadata struct{ Name, Namespace string } `json:"metadata"`
			Spec     struct {
				ServiceAccountName string `json:"serviceAccountName"`
				Containers         []struct{ Name, Image string }
			} `json:"spec"`
		} `json:"items"`
	}
	if err := json.Unmarshal([]byte(body), &list); err != nil {
		t.Fatalf("/pods is not a PodList: %v", err)
	}
	if list.Kind != "PodList" {
		t.Errorf("kind = %q, want PodList", list.Kind)
	}
	if len(list.Items) < 3 {
		t.Errorf("%d pods, want a node that looks in use", len(list.Items))
	}
	for _, item := range list.Items {
		if item.Spec.ServiceAccountName == "" || len(item.Spec.Containers) == 0 {
			t.Errorf("pod %s is missing the fields a real one has: %+v",
				item.Metadata.Name, item.Spec)
		}
	}

	h.WaitFor(t, "pod_list")
}

// TestStolenTokenIsCaptured. Tooling that meets a kubelet which refuses
// anonymous requests falls back to whatever service-account token it already
// has, and that token names the compromised account.
func TestStolenTokenIsCaptured(t *testing.T) {
	h, client, base := start(t)

	const token = "eyJhbGciOiJSUzI1NiIsImtpZCI6InN0b2xlbiJ9.eyJzdWIiOiJzeXN0ZW06c2Vy" +
		"dmljZWFjY291bnQ6ZGVmYXVsdDpwYXltZW50cy1hcGkifQ.signature"
	get(t, client, base+"/pods", token)

	ev := h.WaitFor(t, "auth_attempt")
	if captured, _ := ev.Data["token"].(string); !strings.HasPrefix(captured, "eyJhbGciOiJSUzI1NiIs") {
		t.Errorf("token = %q, want the presented credential", captured)
	}
}

// TestConfigzAdmitsTheDoorIsOpen. An intruder reads /configz to confirm that
// the endpoint they just used really is unauthenticated. A decoy that answered
// commands while reporting `anonymous: false` would be contradicting itself.
func TestConfigzAdmitsTheDoorIsOpen(t *testing.T) {
	_, client, base := start(t)

	_, body := get(t, client, base+"/configz", "")

	var cfg struct {
		KubeletConfig struct {
			Authentication struct {
				Anonymous struct{ Enabled bool } `json:"anonymous"`
			} `json:"authentication"`
		} `json:"kubeletconfig"`
	}
	if err := json.Unmarshal([]byte(body), &cfg); err != nil {
		t.Fatalf("/configz is not a KubeletConfiguration: %v", err)
	}
	if !cfg.KubeletConfig.Authentication.Anonymous.Enabled {
		t.Error("/configz reports anonymous auth off while the decoy answers anonymous commands")
	}
}

// TestCertificateLooksLikeANodeAndIsReused. A kubelet's certificate is issued
// to system:node:<name>, and one that changed on every restart would identify
// the box as a honeypot to anyone who connected twice.
func TestCertificateLooksLikeANodeAndIsReused(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")

	first, err := New("127.0.0.1:0", "node-1", certPath, keyPath)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	second, err := New("127.0.0.1:0", "node-1", certPath, keyPath)
	if err != nil {
		t.Fatalf("new again: %v", err)
	}

	if string(first.tlsCert.Certificate[0]) != string(second.tlsCert.Certificate[0]) {
		t.Error("the certificate changed between restarts — that is a honeypot fingerprint")
	}

	leaf, err := x509.ParseCertificate(first.tlsCert.Certificate[0])
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	if leaf.Subject.CommonName != "system:node:node-1" {
		t.Errorf("CommonName = %q, want system:node:node-1", leaf.Subject.CommonName)
	}
}
