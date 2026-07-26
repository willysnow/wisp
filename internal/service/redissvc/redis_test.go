package redissvc

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
		return New(addr, "7.0.15")
	})
}

// respCommand encodes a command the way a real client does.
func respCommand(args ...string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "*%d\r\n", len(args))
	for _, a := range args {
		fmt.Fprintf(&b, "$%d\r\n%s\r\n", len(a), a)
	}
	return b.String()
}

func session(t *testing.T, h *servicetest.StreamHarness) func(...string) string {
	t.Helper()

	conn := h.Dial()
	r := bufio.NewReader(conn)

	return func(args ...string) string {
		t.Helper()
		if _, err := conn.Write([]byte(respCommand(args...))); err != nil {
			t.Fatalf("write %v: %v", args, err)
		}
		line, err := r.ReadString('\n')
		if err != nil {
			t.Fatalf("read reply to %v: %v", args, err)
		}
		return strings.TrimRight(line, "\r\n")
	}
}

// TestAuthIsCapturedAsACredential, not buried in the command stream — it
// belongs alongside the SSH and FTP logins where an operator looks for
// credentials.
func TestAuthIsCapturedAsACredential(t *testing.T) {
	h := start(t)
	send := session(t, h)

	if reply := send("AUTH", "hunter2"); reply != "+OK" {
		t.Errorf("AUTH reply = %q, want +OK", reply)
	}

	ev := h.WaitFor(t, "login_password")
	if ev.Data["password"] != "hunter2" {
		t.Errorf("password = %v, want hunter2", ev.Data["password"])
	}
}

// TestACLAuthCapturesBothParts — Redis 6 added a username, and capturing only
// the password would lose half the credential.
func TestACLAuthCapturesBothParts(t *testing.T) {
	h := start(t)
	send := session(t, h)

	send("AUTH", "default", "s3cret")

	ev := h.WaitFor(t, "login_password")
	if ev.Data["username"] != "default" || ev.Data["password"] != "s3cret" {
		t.Errorf("captured %v, want default/s3cret", ev.Data)
	}
}

// TestTakeoverPlaybookIsRecorded is the reason this decoy answers +OK instead
// of refusing.
//
// The standard Redis takeover writes an SSH key by pointing the database at
// ~/.ssh and saving. Refusing the first command would end the interaction;
// answering keeps the script running so all four steps land in the log, and
// the log then says exactly what the attacker intended.
func TestTakeoverPlaybookIsRecorded(t *testing.T) {
	h := start(t)
	send := session(t, h)

	steps := [][]string{
		{"CONFIG", "SET", "dir", "/root/.ssh"},
		{"CONFIG", "SET", "dbfilename", "authorized_keys"},
		{"SET", "x", "ssh-rsa AAAAB3NzaC1yc2E... attacker@host"},
		{"SAVE"},
	}
	for _, step := range steps {
		if reply := send(step...); strings.HasPrefix(reply, "-") {
			t.Fatalf("%v was refused with %q — the script would stop here", step, reply)
		}
	}

	var seen []string
	for _, e := range h.Events() {
		if e.Kind == "command" {
			seen = append(seen, fmt.Sprint(e.Data["command"]))
		}
	}
	joined := strings.Join(seen, ",")
	for _, want := range []string{"CONFIG", "SET", "SAVE"} {
		if !strings.Contains(joined, want) {
			t.Errorf("the playbook step %s was not recorded; got %s", want, joined)
		}
	}

	// The key itself is the evidence: without the argument, "SET x" says
	// nothing about what was planted.
	var planted bool
	for _, e := range h.Events() {
		if args, ok := e.Data["args"].(string); ok && strings.Contains(args, "ssh-rsa") {
			planted = true
		}
	}
	if !planted {
		t.Error("the key the attacker tried to plant was not recorded")
	}
}

// TestNothingIsActuallyStored: the decoy answers as if it worked, and does
// nothing. A SAVE that wrote a file would make this a real foothold.
func TestNothingIsActuallyStored(t *testing.T) {
	h := start(t)
	send := session(t, h)

	send("SET", "planted", "value")
	if reply := send("GET", "planted"); reply != "$-1" {
		t.Errorf("GET after SET returned %q, want a nil reply — nothing may persist", reply)
	}
}

// TestLooksLikeRedis — INFO is what a scanner fingerprints on, and a version
// that does not match the banner is a tell.
func TestLooksLikeRedis(t *testing.T) {
	h := start(t)
	send := session(t, h)

	if reply := send("PING"); reply != "+PONG" {
		t.Errorf("PING = %q, want +PONG", reply)
	}
	if reply := send("INFO"); !strings.HasPrefix(reply, "$") {
		t.Errorf("INFO = %q, want a bulk string", reply)
	}
}

// TestOversizeArgumentIsBounded — a client that sends a megabyte-long value
// must not put a megabyte in the event log.
func TestOversizeArgumentIsBounded(t *testing.T) {
	h := start(t)
	send := session(t, h)

	send("SET", "k", strings.Repeat("A", argLogLimit*4))

	ev := h.WaitFor(t, "command")
	if args, ok := ev.Data["args"].(string); ok && len(args) > argLogLimit+16 {
		t.Errorf("logged %d bytes of argument, want about %d", len(args), argLogLimit)
	}
}

// TestConnectionIsRecorded before any command arrives.
func TestConnectionIsRecorded(t *testing.T) {
	h := start(t)
	session(t, h)

	h.WaitFor(t, "connect")
}
