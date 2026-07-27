package proxysvc

import (
	"bufio"
	"encoding/base64"
	"net"
	"strings"
	"testing"

	"github.com/willysnow/wisp/internal/service"
	"github.com/willysnow/wisp/internal/service/servicetest"
)

func start(t *testing.T) *servicetest.StreamHarness {
	return servicetest.StartStream(t, func(addr string) service.StreamService {
		return New(addr, "", "")
	})
}

// sendRequest writes a raw HTTP request and returns the response's status line.
func sendRequest(t *testing.T, conn net.Conn, raw string) string {
	t.Helper()
	if _, err := conn.Write([]byte(raw)); err != nil {
		t.Fatalf("write request: %v", err)
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatalf("read status line: %v", err)
	}
	return strings.TrimSpace(line)
}

func TestBasicCredentialsCaptured(t *testing.T) {
	h := start(t)
	conn := h.Dial()

	creds := base64.StdEncoding.EncodeToString([]byte("admin:proxypass"))
	req := "GET http://example.com/ HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"Proxy-Authorization: Basic " + creds + "\r\n" +
		"User-Agent: proxychecker/1.0\r\n" +
		"\r\n"

	status := sendRequest(t, conn, req)
	if !strings.Contains(status, "407") {
		t.Fatalf("status = %q, want 407 Proxy Authentication Required", status)
	}

	ev := h.WaitFor(t, "login_password")
	if ev.Data["username"] != "admin" {
		t.Errorf("username = %v, want admin", ev.Data["username"])
	}
	if ev.Data["password"] != "proxypass" {
		t.Errorf("password = %v, want proxypass", ev.Data["password"])
	}
	if ev.Data["target"] != "http://example.com/" {
		t.Errorf("target = %v, want http://example.com/", ev.Data["target"])
	}
}

func TestConnectTargetLogged(t *testing.T) {
	h := start(t)
	conn := h.Dial()

	// A CONNECT to an internal address — the shape of an SSRF pivot using the
	// proxy as the hop.
	req := "CONNECT 169.254.169.254:80 HTTP/1.1\r\n" +
		"Host: 169.254.169.254:80\r\n" +
		"User-Agent: sslscan\r\n" +
		"\r\n"

	status := sendRequest(t, conn, req)
	if !strings.Contains(status, "407") {
		t.Fatalf("status = %q, want 407", status)
	}

	ev := h.WaitFor(t, "proxy_request")
	if ev.Data["method"] != "CONNECT" {
		t.Errorf("method = %v, want CONNECT", ev.Data["method"])
	}
	if ev.Data["target"] != "169.254.169.254:80" {
		t.Errorf("target = %v, want 169.254.169.254:80", ev.Data["target"])
	}
}

func TestAbsoluteFormNoAuth(t *testing.T) {
	h := start(t)
	conn := h.Dial()

	req := "GET http://checkip.example.net/ HTTP/1.1\r\n" +
		"Host: checkip.example.net\r\n" +
		"User-Agent: open-proxy-check\r\n" +
		"\r\n"

	if status := sendRequest(t, conn, req); !strings.Contains(status, "407") {
		t.Fatalf("status = %q, want 407", status)
	}

	ev := h.WaitFor(t, "proxy_request")
	if ev.Data["target"] != "http://checkip.example.net/" {
		t.Errorf("target = %v, want the requested URL", ev.Data["target"])
	}
	if ev.Data["target_host"] != "checkip.example.net" {
		t.Errorf("target_host = %v, want checkip.example.net", ev.Data["target_host"])
	}
	if _, ok := ev.Data["password"]; ok {
		t.Errorf("no-auth request must not log a password")
	}
}
