package gitsvc

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/willysnow/wisp/internal/event"
)

// start brings the service up on a loopback port and returns a dialer plus an
// accessor for the events it emitted.
func start(t *testing.T) (dial func() net.Conn, events func() []event.Event) {
	t.Helper()

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
		_ = New(ln.Addr().String()).Serve(ctx, ln, emit)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})

	return func() net.Conn {
			conn, err := net.Dial("tcp", ln.Addr().String())
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			t.Cleanup(func() { conn.Close() })
			_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
			return conn
		}, func() []event.Event {
			mu.Lock()
			defer mu.Unlock()
			return append([]event.Event(nil), seen...)
		}
}

func pktLine(payload string) string {
	return fmt.Sprintf("%04x%s", len(payload)+4, payload)
}

func waitFor(t *testing.T, events func() []event.Event, kinds ...string) event.Event {
	t.Helper()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		for _, e := range events() {
			for _, k := range kinds {
				if e.Kind == k {
					return e
				}
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("no event of kind %v was emitted", kinds)
	return event.Event{}
}

// TestCloneRequestCapturesRepository is what this module is for. The repository
// path arrives in the first packet, and a name the attacker did not have to
// guess is a lead about what else they know.
func TestCloneRequestCapturesRepository(t *testing.T) {
	dial, events := start(t)

	conn := dial()
	_, err := io.WriteString(conn,
		pktLine("git-upload-pack /srv/git/payments-api.git\x00host=git.internal\x00"))
	if err != nil {
		t.Fatalf("write: %v", err)
	}

	ev := waitFor(t, events, "repo_request")
	if got := ev.Data["repository"]; got != "/srv/git/payments-api.git" {
		t.Errorf("repository = %v, want /srv/git/payments-api.git", got)
	}
	if got := ev.Data["command"]; got != "git-upload-pack" {
		t.Errorf("command = %v, want git-upload-pack", got)
	}
	if got := ev.Data["host"]; got != "git.internal" {
		t.Errorf("host = %v, want git.internal — the name they were given for this box", got)
	}
}

// TestPushIsWriteRequest: a fetch is reconnaissance, a push is an attempt to
// put code into your infrastructure. They must not read the same in an alert.
func TestPushIsWriteRequest(t *testing.T) {
	dial, events := start(t)

	conn := dial()
	if _, err := io.WriteString(conn, pktLine("git-receive-pack /deploy.git\x00")); err != nil {
		t.Fatalf("write: %v", err)
	}

	ev := waitFor(t, events, "write_request")
	if got := ev.Data["repository"]; got != "/deploy.git" {
		t.Errorf("repository = %v, want /deploy.git", got)
	}
	if !event.IsHighValue(ev.Kind) {
		t.Error("a push attempt is not treated as high value, so a flood could bury it")
	}
}

// TestExtraParametersCaptured — protocol v2 clients send their version, which
// distinguishes a modern git client from a scanner imitating one.
func TestExtraParametersCaptured(t *testing.T) {
	dial, events := start(t)

	conn := dial()
	_, err := io.WriteString(conn,
		pktLine("git-upload-pack /repo.git\x00host=example.com\x00\x00version=2\x00"))
	if err != nil {
		t.Fatalf("write: %v", err)
	}

	ev := waitFor(t, events, "repo_request")
	if got := ev.Data["version"]; got != "2" {
		t.Errorf("version = %v, want 2", got)
	}
}

// TestAnswersLikeARealDaemon: the reply has to be an ordinary refusal, in the
// protocol's own framing. A client that gets something malformed learns it is
// not talking to git.
func TestAnswersLikeARealDaemon(t *testing.T) {
	dial, _ := start(t)

	conn := dial()
	if _, err := io.WriteString(conn, pktLine("git-upload-pack /nope.git\x00")); err != nil {
		t.Fatalf("write: %v", err)
	}

	reply, err := readPktLine(conn)
	if err != nil {
		t.Fatalf("read reply: %v", err)
	}
	if !strings.HasPrefix(reply, "ERR ") {
		t.Errorf("reply = %q, want an ERR pkt-line", reply)
	}
	if !strings.Contains(reply, "/nope.git") {
		t.Errorf("reply = %q, want it to name the repository the way git does", reply)
	}
}

// TestControlCharactersAreStripped: the repository name is attacker-controlled
// and gets echoed back. It must not be able to carry terminal escapes or extra
// protocol framing out with it.
func TestControlCharactersAreStripped(t *testing.T) {
	dial, _ := start(t)

	conn := dial()
	_, err := io.WriteString(conn,
		pktLine("git-upload-pack /evil\x1b[31m\r\n0000fake\x00"))
	if err != nil {
		t.Fatalf("write: %v", err)
	}

	reply, err := readPktLine(conn)
	if err != nil {
		t.Fatalf("read reply: %v", err)
	}
	for _, c := range reply {
		if c == 0x1b || c == '\r' {
			t.Fatalf("reply %q echoed a control character back", reply)
		}
	}
}

// TestSilentConnectionIsRecorded — a socket that opens and says nothing is what
// a port scan looks like from in here, and it is still worth an event.
func TestSilentConnectionIsRecorded(t *testing.T) {
	dial, events := start(t)

	conn := dial()
	conn.Close()

	waitFor(t, events, "connection")
}

// TestMalformedRequestsDoNotHang covers the parser's bounds: none of these may
// take a goroutine down or block.
func TestMalformedRequestsDoNotHang(t *testing.T) {
	for _, tc := range []struct{ name, payload string }{
		{"not hex", "zzzzgit-upload-pack /x\x00"},
		{"length beyond limit", "ffffgit-upload-pack /x\x00"},
		{"length below header", "0001"},
		{"flush only", "0000"},
		{"header only", "0004"},
		{"no command", pktLine("\x00\x00\x00")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dial, _ := start(t)

			conn := dial()
			if _, err := io.WriteString(conn, tc.payload); err != nil {
				t.Fatalf("write: %v", err)
			}
			// Whatever it decides, it has to decide it: reading to EOF must
			// return rather than block until the test's deadline.
			_ = conn.SetDeadline(time.Now().Add(time.Second))
			if _, err := io.ReadAll(conn); err != nil && !strings.Contains(err.Error(), "closed") {
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					t.Fatal("the connection hung instead of being answered or closed")
				}
			}
		})
	}
}
