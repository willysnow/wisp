// Package servicetest is the harness the protocol emulators are tested with.
//
// Every one of them needs the same three things: a listener on a loopback
// port, somewhere to collect the events it emits, and a way to wait for one
// without sleeping a fixed amount. Writing that nine times over would mean
// nine slightly different versions of it, and the differences would be where
// the flakiness lived.
package servicetest

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/willysnow/wisp/internal/event"
	"github.com/willysnow/wisp/internal/service"
)

// waitTimeout bounds how long a test waits for an event before failing. Every
// emulator answers in microseconds on loopback; this is only here so a broken
// one fails rather than hanging a CI run.
const waitTimeout = 3 * time.Second

// Harness is a running service and the events it has produced.
type Harness struct {
	// Addr is where the service is listening.
	Addr string

	mu     sync.Mutex
	events []event.Event
}

// Events returns everything emitted so far.
func (h *Harness) Events() []event.Event {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]event.Event(nil), h.events...)
}

func (h *Harness) emit(e event.Event) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.events = append(h.events, e)
}

// WaitFor returns the first event of the given kind, failing the test if none
// arrives. Polling rather than sleeping keeps the suite fast and keeps a slow
// machine from turning a pass into a flake.
func (h *Harness) WaitFor(t *testing.T, kind string) event.Event {
	t.Helper()

	deadline := time.Now().Add(waitTimeout)
	for {
		for _, e := range h.Events() {
			if e.Kind == kind {
				return e
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("no %q event was emitted; got %s", kind, h.kinds())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// Quiet fails the test if an event of the given kind ever appears. Used for
// the properties an emulator must never violate.
func (h *Harness) Quiet(t *testing.T, kind string) {
	t.Helper()

	// Long enough for a wrong answer to have arrived, short enough not to slow
	// the suite: the emulator has already answered by the time this runs.
	time.Sleep(100 * time.Millisecond)
	for _, e := range h.Events() {
		if e.Kind == kind {
			t.Fatalf("an event of kind %q was emitted: %v", kind, e.Data)
		}
	}
}

// Count reports how many events of a kind were emitted.
func (h *Harness) Count(kind string) int {
	n := 0
	for _, e := range h.Events() {
		if e.Kind == kind {
			n++
		}
	}
	return n
}

func (h *Harness) kinds() string {
	seen := map[string]int{}
	for _, e := range h.Events() {
		seen[e.Kind]++
	}
	if len(seen) == 0 {
		return "no events at all"
	}

	out := ""
	for k, n := range seen {
		if out != "" {
			out += ", "
		}
		out += k
		if n > 1 {
			out += " x" + itoa(n)
		}
	}
	return out
}

func itoa(n int) string {
	if n < 10 {
		return string(rune('0' + n))
	}
	return itoa(n/10) + string(rune('0'+n%10))
}

// StreamHarness starts a TCP service on a loopback port.
type StreamHarness struct {
	*Harness
	t *testing.T
}

// StartStream brings up a TCP service. It is stopped when the test ends.
func StartStream(t *testing.T, build func(addr string) service.StreamService) *StreamHarness {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	h := &Harness{Addr: ln.Addr().String()}
	svc := build(h.Addr)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = svc.Serve(ctx, ln, event.EmitterFunc(h.emit))
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})

	return &StreamHarness{Harness: h, t: t}
}

// Dial opens a connection with a deadline, closed when the test ends.
func (s *StreamHarness) Dial() net.Conn {
	s.t.Helper()

	conn, err := net.Dial("tcp", s.Addr)
	if err != nil {
		s.t.Fatalf("dial: %v", err)
	}
	s.t.Cleanup(func() { conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(waitTimeout))
	return conn
}

// PacketHarness starts a UDP service on a loopback port.
type PacketHarness struct {
	*Harness
	t      *testing.T
	client net.PacketConn
	server net.Addr
}

// StartPacket brings up a UDP service. It is stopped when the test ends.
func StartPacket(t *testing.T, build func(addr string) service.PacketService) *PacketHarness {
	t.Helper()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	h := &Harness{Addr: pc.LocalAddr().String()}
	svc := build(h.Addr)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = svc.ServePacket(ctx, pc, event.EmitterFunc(h.emit))
	}()

	client, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("client listen: %v", err)
	}

	t.Cleanup(func() {
		client.Close()
		cancel()
		<-done
	})

	return &PacketHarness{Harness: h, t: t, client: client, server: pc.LocalAddr()}
}

// Send delivers one datagram to the service.
func (p *PacketHarness) Send(payload []byte) {
	p.t.Helper()

	if _, err := p.client.WriteTo(payload, p.server); err != nil {
		p.t.Fatalf("send: %v", err)
	}
}

// Reply reads one datagram back, or reports that none came.
func (p *PacketHarness) Reply() ([]byte, bool) {
	p.t.Helper()

	_ = p.client.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 4096)
	n, _, err := p.client.ReadFrom(buf)
	if err != nil {
		return nil, false
	}
	return buf[:n], true
}
