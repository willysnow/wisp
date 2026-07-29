package portscan

import (
	"sync"
	"testing"
	"time"

	"github.com/willysnow/wisp/internal/event"
)

// collector is an Emitter that records what it receives.
type collector struct {
	mu     sync.Mutex
	events []event.Event
}

func (c *collector) Emit(e event.Event) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, e)
}

func (c *collector) count(kind string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, e := range c.events {
		if e.Kind == kind {
			n++
		}
	}
	return n
}

func (c *collector) last(kind string) (event.Event, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i := len(c.events) - 1; i >= 0; i-- {
		if c.events[i].Kind == kind {
			return c.events[i], true
		}
	}
	return event.Event{}, false
}

// harness is a detector with a controllable clock.
type harness struct {
	d     *Detector
	c     *collector
	clock time.Time
}

func newHarness(t *testing.T, cfg Config) *harness {
	t.Helper()
	c := &collector{}
	d := New(c, cfg)
	h := &harness{d: d, c: c, clock: time.Unix(1700000000, 0)}
	d.now = func() time.Time { return h.clock }
	return h
}

func (h *harness) advance(d time.Duration) { h.clock = h.clock.Add(d) }

// touch feeds one connection event from src to a service on a port.
func (h *harness) touch(src string, port int, service string) {
	h.d.Emit(event.NewRaw(service, "connection", src, 40000, port))
}

func TestScanDetectedAtThreshold(t *testing.T) {
	h := newHarness(t, Config{Threshold: 5, Window: time.Minute, Cooldown: 5 * time.Minute})

	services := []struct {
		port int
		name string
	}{{22, "ssh"}, {21, "ftp"}, {6379, "redis"}, {27017, "mongodb"}}
	for _, s := range services {
		h.touch("10.0.0.9", s.port, s.name)
	}
	// Four distinct ports is below the threshold of five.
	if got := h.c.count(kind); got != 0 {
		t.Fatalf("portscan fired at 4 ports, want 0 (got %d)", got)
	}

	h.touch("10.0.0.9", 3306, "mysql") // the fifth
	if got := h.c.count(kind); got != 1 {
		t.Fatalf("portscan events = %d, want 1 at the threshold", got)
	}

	ev, _ := h.c.last(kind)
	if ev.SrcIP != "10.0.0.9" {
		t.Errorf("src_ip = %v, want 10.0.0.9", ev.SrcIP)
	}
	if ev.Data["ports"] != 5 {
		t.Errorf("ports = %v, want 5", ev.Data["ports"])
	}
	if ev.Data["method"] != "connect" {
		t.Errorf("method = %v, want connect", ev.Data["method"])
	}
	if ev.Data["services"] != "ftp,mongodb,mysql,redis,ssh" {
		t.Errorf("services = %v, want the sorted set", ev.Data["services"])
	}
}

func TestForwardsEveryEvent(t *testing.T) {
	h := newHarness(t, Config{Threshold: 100, Window: time.Minute})
	h.touch("10.0.0.9", 22, "ssh")
	h.touch("10.0.0.9", 21, "ftp")
	// The detector is transparent: both connection events reach the sink even
	// when nothing trips the threshold.
	if got := h.c.count("connection"); got != 2 {
		t.Fatalf("forwarded connection events = %d, want 2", got)
	}
	if got := h.c.count(kind); got != 0 {
		t.Fatalf("portscan events = %d, want 0", got)
	}
}

func TestCooldownCollapsesASweep(t *testing.T) {
	h := newHarness(t, Config{Threshold: 3, Window: time.Minute, Cooldown: 5 * time.Minute})

	for p := 1; p <= 20; p++ {
		h.touch("10.0.0.9", p, "banner")
	}
	// Twenty ports past the threshold, but within one cooldown, is one event.
	if got := h.c.count(kind); got != 1 {
		t.Fatalf("portscan events = %d during one sweep, want 1", got)
	}

	// After the cooldown, a source still scanning produces a second event.
	h.advance(6 * time.Minute)
	for p := 100; p <= 110; p++ {
		h.touch("10.0.0.9", p, "banner")
	}
	if got := h.c.count(kind); got != 2 {
		t.Fatalf("portscan events = %d after cooldown, want 2", got)
	}
}

func TestPortsAgeOutOfWindow(t *testing.T) {
	h := newHarness(t, Config{Threshold: 5, Window: 30 * time.Second, Cooldown: time.Minute})

	h.touch("10.0.0.9", 22, "ssh")
	h.touch("10.0.0.9", 21, "ftp")
	h.touch("10.0.0.9", 23, "telnet")
	h.touch("10.0.0.9", 25, "smtp")

	// A slow prober: the next touch is well after the window, so the first four
	// have aged out and only one port is current.
	h.advance(45 * time.Second)
	h.touch("10.0.0.9", 80, "http")
	h.touch("10.0.0.9", 443, "https")

	if got := h.c.count(kind); got != 0 {
		t.Fatalf("portscan fired on aged-out ports, want 0 (got %d)", got)
	}
}

func TestIgnoredSourceNeverScans(t *testing.T) {
	h := newHarness(t, Config{Threshold: 3, Window: time.Minute, Ignore: []string{"127.0.0.1"}})
	for p := 1; p <= 10; p++ {
		h.touch("127.0.0.1", p, "banner")
	}
	if got := h.c.count(kind); got != 0 {
		t.Fatalf("an ignored source scanned, want 0 (got %d)", got)
	}
	// A different source still trips.
	for p := 1; p <= 3; p++ {
		h.touch("10.0.0.9", p, "banner")
	}
	if got := h.c.count(kind); got != 1 {
		t.Fatalf("portscan events = %d for a non-ignored source, want 1", got)
	}
}

func TestDistinctSourcesTrackedSeparately(t *testing.T) {
	h := newHarness(t, Config{Threshold: 5, Window: time.Minute})
	// Two sources, four ports each — neither alone reaches the threshold.
	for _, src := range []string{"10.0.0.1", "10.0.0.2"} {
		for p := 1; p <= 4; p++ {
			h.touch(src, p, "banner")
		}
	}
	if got := h.c.count(kind); got != 0 {
		t.Fatalf("portscan fired across two under-threshold sources, want 0 (got %d)", got)
	}
}
