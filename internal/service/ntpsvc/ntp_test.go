package ntpsvc

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/willysnow/wisp/internal/event"
)

// readTimeout is how long we wait before concluding no reply is coming.
const readTimeout = 500 * time.Millisecond

// start brings the service up on a loopback port and returns a connected client
// plus an accessor for the events it emitted.
func start(t *testing.T) (client net.Conn, events func() []event.Event) {
	t.Helper()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
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
		_ = New(pc.LocalAddr().String()).ServePacket(ctx, pc, emit)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})

	c, err := net.Dial("udp", pc.LocalAddr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })

	return c, func() []event.Event {
		mu.Lock()
		defer mu.Unlock()
		return append([]event.Event(nil), seen...)
	}
}

// request sends payload and returns the reply length, or -1 if nothing arrived
// before readTimeout.
func request(t *testing.T, c net.Conn, payload []byte) int {
	t.Helper()

	if _, err := c.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := c.SetReadDeadline(time.Now().Add(readTimeout)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}

	buf := make([]byte, 1024)
	n, err := c.Read(buf)
	if err != nil {
		return -1
	}
	return n
}

// monlistPacket is the classic mode 7 amplification request: version 2, mode 7,
// implementation 3, request code 42 (MON_GETLIST_1).
func monlistPacket() []byte {
	return append([]byte{0x17, 0x00, 0x03, 0x2a}, make([]byte, 44)...)
}

// clientPacket is an ordinary mode 3 client request.
func clientPacket() []byte {
	return append([]byte{0x1b}, make([]byte, 47)...)
}

// TestMonlistIsNeverAnswered guards the service's central safety property. A
// reply to mode 7 would make the sensor a working DDoS reflector aimed at
// whatever source address the attacker spoofed, so this must never regress into
// "answer with something harmless-looking".
func TestMonlistIsNeverAnswered(t *testing.T) {
	c, events := start(t)

	if n := request(t, c, monlistPacket()); n != -1 {
		t.Fatalf("monlist was answered with %d bytes; the sensor is an amplifier", n)
	}

	got := events()
	if len(got) != 1 {
		t.Fatalf("got %d events, want 1", len(got))
	}
	if got[0].Kind != "monlist_probe" {
		t.Errorf("Kind = %q, want %q", got[0].Kind, "monlist_probe")
	}
	if got[0].Data["request_code"] != byte(42) {
		t.Errorf("request_code = %v, want 42", got[0].Data["request_code"])
	}
}

// TestClientRequestIsAnswered checks the service still behaves like an NTP
// server for legitimate traffic — silence everywhere would be its own tell.
func TestClientRequestIsAnswered(t *testing.T) {
	c, events := start(t)

	n := request(t, c, clientPacket())
	if n != packetSize {
		t.Fatalf("reply was %d bytes, want %d", n, packetSize)
	}

	got := events()
	if len(got) != 1 {
		t.Fatalf("got %d events, want 1", len(got))
	}
	if got[0].Kind != "request" {
		t.Errorf("Kind = %q, want %q", got[0].Kind, "request")
	}
	if got[0].Data["mode"] != uint8(modeClient) {
		t.Errorf("mode = %v, want %d", got[0].Data["mode"], modeClient)
	}
}

// TestShortPacketDoesNotPanic covers the truncated-datagram path — a scanner
// sending a single byte must be recorded, not crash the sensor.
func TestShortPacketDoesNotPanic(t *testing.T) {
	c, events := start(t)

	if n := request(t, c, []byte{0x1b}); n != -1 {
		t.Errorf("short packet drew a %d-byte reply, want none", n)
	}

	got := events()
	if len(got) != 1 {
		t.Fatalf("got %d events, want 1", len(got))
	}
	if got[0].Kind != "request" {
		t.Errorf("Kind = %q, want %q", got[0].Kind, "request")
	}
}
