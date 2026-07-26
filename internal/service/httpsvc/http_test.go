package httpsvc

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/willysnow/wisp/internal/event"
)

func startTLS(t *testing.T) (base string, client *http.Client, events func() []event.Event) {
	t.Helper()

	dir := t.TempDir()
	svc, err := NewTLS("127.0.0.1:0", "nginx/1.18.0 (Ubuntu)", "Administration", "Firmware 2.1.14",
		filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem"),
		[]string{"admin.internal", "127.0.0.1"})
	if err != nil {
		t.Fatalf("new: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	var mu sync.Mutex
	var seen []event.Event
	emit := event.EmitterFunc(func(e event.Event) {
		mu.Lock()
		defer mu.Unlock()
		seen = append(seen, e)
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = svc.Serve(ctx, ln, emit)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})

	transport := &http.Transport{
		// The decoy's certificate is self-signed by design; the client here is
		// standing in for a scanner, which does not check either. Proxy is
		// disabled so the request cannot be diverted by a local TLS-inspecting
		// agent, which would replace the certificate and the SNI under test.
		Proxy:           nil,
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: "admin.internal"},
	}

	return "https://" + ln.Addr().String(),
		&http.Client{Transport: transport, Timeout: 5 * time.Second},
		func() []event.Event {
			mu.Lock()
			defer mu.Unlock()
			return append([]event.Event(nil), seen...)
		}
}

// TestTLSDecoyIsItsOwnService: the same panel behind TLS has to report as
// "https", or an operator cannot tell which of the two doors was tried.
func TestTLSDecoyIsItsOwnService(t *testing.T) {
	base, client, events := startTLS(t)

	resp, err := client.Get(base + "/admin")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if !strings.Contains(string(body), "Administration") {
		t.Error("the login page was not served over TLS")
	}
	if got := resp.Header.Get("Server"); got != "nginx/1.18.0 (Ubuntu)" {
		t.Errorf("Server = %q, want the configured header", got)
	}

	ev := events()[0]
	if ev.Service != "https" {
		t.Errorf("Service = %q, want https", ev.Service)
	}
	if ev.Data["sni"] != "admin.internal" {
		t.Errorf("sni = %v, want admin.internal — the name they expected to find here",
			ev.Data["sni"])
	}
}

// TestTLSCredentialsAreCaptured — the reason the decoy exists is unchanged by
// the transport.
func TestTLSCredentialsAreCaptured(t *testing.T) {
	base, client, events := startTLS(t)

	resp, err := client.PostForm(base+"/login.cgi", url.Values{
		"username": {"admin"},
		"password": {"Summer2026!"},
	})
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	var login event.Event
	for _, e := range events() {
		if e.Kind == "login_form" {
			login = e
		}
	}
	if login.Kind == "" {
		t.Fatal("the posted credentials were not captured")
	}
	if login.Data["username"] != "admin" || login.Data["password"] != "Summer2026!" {
		t.Errorf("captured %v / %v, want admin / Summer2026!",
			login.Data["username"], login.Data["password"])
	}

	// Never granted, and never a hint about which half was wrong.
	if !strings.Contains(string(body), "Invalid username or password") {
		t.Error("the decoy did not answer with its usual refusal")
	}
	if strings.Contains(string(body), "no such user") {
		t.Error("the answer would let an attacker enumerate accounts")
	}
}

// TestCertificateIsReused: a certificate that changes on every restart
// identifies the box as a honeypot to anyone who connects twice.
func TestCertificateIsReused(t *testing.T) {
	dir := t.TempDir()
	cert, key := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")

	first, err := NewTLS("127.0.0.1:0", "", "", "", cert, key, []string{"admin.internal"})
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	second, err := NewTLS("127.0.0.1:0", "", "", "", cert, key, []string{"admin.internal"})
	if err != nil {
		t.Fatalf("second: %v", err)
	}

	a := first.tlsConfig.Certificates[0].Certificate[0]
	b := second.tlsConfig.Certificates[0].Certificate[0]
	if string(a) != string(b) {
		t.Error("the certificate changed between restarts")
	}
}

// TestPlainHTTPUnchanged guards the shared code path: adding TLS must not have
// renamed the original service.
func TestPlainHTTPUnchanged(t *testing.T) {
	if got := New("0.0.0.0:8080", "", "", "").Name(); got != "http" {
		t.Errorf("Name() = %q, want http", got)
	}
}

// TestRealmAndFooterReachThePage.
//
// They did not, for a while: `realm` was accepted from the config, stored on
// the service, and never read, so a panel on a box calling itself a DiskStation
// was still titled "Administration". A login page that contradicts every other
// port is the inconsistency the device persona exists to remove, and it is only
// removed if these two strings actually arrive.
func TestRealmAndFooterReachThePage(t *testing.T) {
	svc := New("127.0.0.1:0", "nginx", "DiskStation", "DSM 7.2-64570")
	page := svc.page("")

	for _, want := range []string{
		"<title>DiskStation</title>",
		"<h1>DiskStation</h1>",
		"DSM 7.2-64570",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("login page is missing %q", want)
		}
	}
	if strings.Contains(page, "Administration") || strings.Contains(page, "Firmware 2.1.14") {
		t.Error("the page still shows the built-in defaults")
	}
	if strings.Contains(page, "{{") {
		t.Errorf("a placeholder was left unsubstituted:\n%s", page)
	}
}

// TestRealmIsEscaped. It comes from the config file rather than from an
// attacker, but it is substituted into HTML, and "the input is trusted today"
// is how injection bugs are introduced.
func TestRealmIsEscaped(t *testing.T) {
	page := New("127.0.0.1:0", "", `NAS<script>alert(1)</script>`, "").page("")

	if strings.Contains(page, "<script>alert(1)</script>") {
		t.Error("the realm was substituted into the page unescaped")
	}
	if !strings.Contains(page, "&lt;script&gt;") {
		t.Errorf("the realm was not escaped at all:\n%s", page)
	}
}
