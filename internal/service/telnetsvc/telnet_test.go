package telnetsvc

import (
	"bufio"
	"io"
	"strings"
	"testing"

	"github.com/willysnow/wisp/internal/service"
	"github.com/willysnow/wisp/internal/service/servicetest"
)

func start(t *testing.T) *servicetest.StreamHarness {
	return servicetest.StartStream(t, func(addr string) service.StreamService {
		return New(addr, "Ubuntu 22.04.3 LTS")
	})
}

// readUntil consumes output up to and including a prompt.
func readUntil(t *testing.T, r *bufio.Reader, want string) string {
	t.Helper()

	var got strings.Builder
	for !strings.HasSuffix(got.String(), want) {
		b, err := r.ReadByte()
		if err != nil {
			t.Fatalf("waiting for %q, got %q: %v", want, got.String(), err)
		}
		got.WriteByte(b)
	}
	return got.String()
}

// TestCredentialsAreCaptured is what the module is for. Almost nothing
// legitimate speaks telnet on a modern network, so a login attempt here is
// close to conclusive.
func TestCredentialsAreCaptured(t *testing.T) {
	h := start(t)

	conn := h.Dial()
	r := bufio.NewReader(conn)

	banner := readUntil(t, r, "login: ")
	if !strings.Contains(banner, "Ubuntu 22.04.3 LTS") {
		t.Errorf("banner missing from %q", banner)
	}

	if _, err := io.WriteString(conn, "root\r\n"); err != nil {
		t.Fatalf("write user: %v", err)
	}
	readUntil(t, r, "Password: ")
	if _, err := io.WriteString(conn, "hunter2\r\n"); err != nil {
		t.Fatalf("write password: %v", err)
	}

	ev := h.WaitFor(t, "login_password")
	if ev.Data["username"] != "root" || ev.Data["password"] != "hunter2" {
		t.Errorf("captured %v, want root/hunter2", ev.Data)
	}
}

// TestNeverGrantsAccess, and never says which half was wrong. Anything that
// distinguishes a real account from an invented one lets an attacker enumerate
// users for free.
func TestNeverGrantsAccess(t *testing.T) {
	h := start(t)

	conn := h.Dial()
	r := bufio.NewReader(conn)
	readUntil(t, r, "login: ")

	for _, creds := range [][2]string{{"root", "root"}, {"admin", "admin"}} {
		if _, err := io.WriteString(conn, creds[0]+"\r\n"); err != nil {
			t.Fatalf("write: %v", err)
		}
		readUntil(t, r, "Password: ")
		if _, err := io.WriteString(conn, creds[1]+"\r\n"); err != nil {
			t.Fatalf("write: %v", err)
		}

		reply := readUntil(t, r, "login: ")
		if !strings.Contains(reply, "Login incorrect") {
			t.Fatalf("reply to %s = %q, want a refusal", creds[0], reply)
		}
		if strings.Contains(strings.ToLower(reply), "no such user") {
			t.Fatal("the refusal distinguishes a missing account from a wrong password")
		}
	}
}

// TestNegotiationIsStrippedFromCredentials is the subtle one.
//
// Clients negotiate telnet options in the middle of the login exchange. A naive
// read splices those control bytes into the username, and the captured
// credential becomes something that never gets matched against a password dump.
func TestNegotiationIsStrippedFromCredentials(t *testing.T) {
	h := start(t)

	conn := h.Dial()
	r := bufio.NewReader(conn)
	readUntil(t, r, "login: ")

	// "ad" IAC DO ECHO "min" — negotiation spliced into the middle of a name,
	// which is what a real client does.
	payload := append([]byte("ad"), iac, do, optEcho)
	payload = append(payload, "min\r\n"...)
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}

	readUntil(t, r, "Password: ")

	// A subnegotiation block in the password, terminated by IAC SE.
	pass := append([]byte("s3cr"), iac, sb, 24, 'x', 'y', iac, se)
	pass = append(pass, "et\r\n"...)
	if _, err := conn.Write(pass); err != nil {
		t.Fatalf("write: %v", err)
	}

	ev := h.WaitFor(t, "login_password")
	if ev.Data["username"] != "admin" {
		t.Errorf("username = %q, want admin — negotiation leaked into the credential",
			ev.Data["username"])
	}
	if ev.Data["password"] != "s3cret" {
		t.Errorf("password = %q, want s3cret", ev.Data["password"])
	}
}

// TestConnectionIsRecorded — telnet is high-signal enough that the connection
// alone is worth an event, before anyone types anything.
func TestConnectionIsRecorded(t *testing.T) {
	h := start(t)

	conn := h.Dial()
	conn.Close()

	h.WaitFor(t, "connect")
}

// TestOversizeCredentialIsBounded: a megabyte-long "username" is an attack on
// the sensor, not a login attempt.
func TestOversizeCredentialIsBounded(t *testing.T) {
	h := start(t)

	conn := h.Dial()
	r := bufio.NewReader(conn)
	readUntil(t, r, "login: ")

	go func() {
		_, _ = io.WriteString(conn, strings.Repeat("A", maxLine*8)+"\r\n")
		_, _ = io.WriteString(conn, "pw\r\n")
	}()

	ev := h.WaitFor(t, "login_password")
	if got := len(ev.Data["username"].(string)); got > maxLine {
		t.Errorf("captured a %d-byte username, want at most %d", got, maxLine)
	}
}

// TestEmptyCredentialsAreNotEvents: a client that sends bare newlines has
// offered nothing, and recording it as a login attempt would be noise in the
// one place noise costs the most.
func TestEmptyCredentialsAreNotEvents(t *testing.T) {
	h := start(t)

	conn := h.Dial()
	r := bufio.NewReader(conn)
	readUntil(t, r, "login: ")

	if _, err := io.WriteString(conn, "\r\n"); err != nil {
		t.Fatalf("write: %v", err)
	}
	readUntil(t, r, "Password: ")
	if _, err := io.WriteString(conn, "\r\n"); err != nil {
		t.Fatalf("write: %v", err)
	}
	readUntil(t, r, "login: ")

	h.Quiet(t, "login_password")
}
