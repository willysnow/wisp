package ftpsvc

import (
	"bufio"
	"fmt"
	"strings"
	"testing"

	"github.com/willysnow/wisp/internal/service"
	"github.com/willysnow/wisp/internal/service/servicetest"
)

func start(t *testing.T) *servicetest.StreamHarness {
	return servicetest.StartStream(t, func(addr string) service.StreamService {
		return New(addr, "(vsFTPd 3.0.5)")
	})
}

// session opens a connection and reads the greeting.
func session(t *testing.T, h *servicetest.StreamHarness) (*bufio.Reader, func(string) string) {
	t.Helper()

	conn := h.Dial()
	r := bufio.NewReader(conn)

	greeting, err := r.ReadString('\n')
	if err != nil {
		t.Fatalf("read greeting: %v", err)
	}
	if !strings.HasPrefix(greeting, "220 ") {
		t.Fatalf("greeting = %q, want a 220", greeting)
	}

	send := func(line string) string {
		t.Helper()
		if _, err := fmt.Fprintf(conn, "%s\r\n", line); err != nil {
			t.Fatalf("write %q: %v", line, err)
		}
		reply, err := r.ReadString('\n')
		if err != nil {
			t.Fatalf("read reply to %q: %v", line, err)
		}
		return strings.TrimRight(reply, "\r\n")
	}
	return r, send
}

// TestCredentialsAreCapturedAsAPair is the property FTP makes awkward: the
// username and the password arrive in two separate commands, and an event
// carrying only one of them is not a credential anyone can use.
func TestCredentialsAreCapturedAsAPair(t *testing.T) {
	h := start(t)
	_, send := session(t, h)

	if reply := send("USER admin"); !strings.HasPrefix(reply, "331") {
		t.Errorf("USER reply = %q, want 331", reply)
	}
	if reply := send("PASS s3cret"); !strings.HasPrefix(reply, "530") {
		t.Errorf("PASS reply = %q, want 530", reply)
	}

	ev := h.WaitFor(t, "login_password")
	if ev.Data["username"] != "admin" {
		t.Errorf("username = %v, want admin — the USER command was not remembered",
			ev.Data["username"])
	}
	if ev.Data["password"] != "s3cret" {
		t.Errorf("password = %v, want s3cret", ev.Data["password"])
	}
}

// TestNeverGrantsAccess: every password is wrong, and the refusal never says
// whether the account exists.
func TestNeverGrantsAccess(t *testing.T) {
	h := start(t)
	_, send := session(t, h)

	for _, user := range []string{"anonymous", "root", "definitely-not-a-user"} {
		send("USER " + user)
		reply := send("PASS anything")

		if !strings.HasPrefix(reply, "530") {
			t.Errorf("PASS for %s = %q, want 530", user, reply)
		}
		if strings.Contains(strings.ToLower(reply), "no such") ||
			strings.Contains(strings.ToLower(reply), "unknown user") {
			t.Errorf("reply %q lets an attacker tell real accounts from invented ones", reply)
		}
	}
}

// TestPostLoginCommandsRecordIntent: a client going straight for STOR or
// SITE EXEC has told you what it came for, even though it never logged in.
func TestPostLoginCommandsRecordIntent(t *testing.T) {
	h := start(t)
	_, send := session(t, h)

	send("STOR backdoor.php")

	ev := h.WaitFor(t, "command")
	if ev.Data["command"] != "STOR" {
		t.Errorf("command = %v, want STOR", ev.Data["command"])
	}
	if ev.Data["arg"] != "backdoor.php" {
		t.Errorf("arg = %v, want the filename they meant to plant", ev.Data["arg"])
	}
}

// TestTLSIsRefused is deliberate rather than a missing feature: an encrypted
// session would hide the credentials this service exists to capture.
func TestTLSIsRefused(t *testing.T) {
	h := start(t)
	_, send := session(t, h)

	reply := send("AUTH TLS")
	if !strings.HasPrefix(reply, "530") {
		t.Errorf("AUTH TLS reply = %q, want a refusal that keeps the session in the clear", reply)
	}
}

// TestLooksLikeVsftpd — the greeting and the stock replies are what a scanner
// fingerprints on.
func TestLooksLikeVsftpd(t *testing.T) {
	h := start(t)
	r, send := session(t, h)

	if reply := send("SYST"); reply != "215 UNIX Type: L8" {
		t.Errorf("SYST = %q, want the standard answer", reply)
	}

	// FEAT is a multi-line reply: the first line opens it, and the test has to
	// drain the rest or the next command reads the wrong line.
	if reply := send("FEAT"); !strings.HasPrefix(reply, "211-") {
		t.Errorf("FEAT = %q, want a multi-line 211", reply)
	}
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			t.Fatalf("draining FEAT: %v", err)
		}
		if strings.HasPrefix(line, "211 ") {
			break
		}
	}
}

// TestQuitEndsTheSession cleanly, the way a real server does.
func TestQuitEndsTheSession(t *testing.T) {
	h := start(t)
	r, send := session(t, h)

	if reply := send("QUIT"); !strings.HasPrefix(reply, "221") {
		t.Errorf("QUIT reply = %q, want 221", reply)
	}
	if _, err := r.ReadString('\n'); err == nil {
		t.Error("the connection stayed open after QUIT")
	}
}

// TestConnectionIsRecorded before anything is typed.
func TestConnectionIsRecorded(t *testing.T) {
	h := start(t)
	session(t, h)

	h.WaitFor(t, "connect")
}
