package sink

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/willysnow/wisp/internal/event"
)

// capture is a sink that remembers everything it was given.
type capture struct {
	mu     sync.Mutex
	events []event.Event
}

func (c *capture) Emit(e event.Event) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, e)
}

func (c *capture) all() []event.Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]event.Event(nil), c.events...)
}

func (c *capture) countKind(kind string) int {
	n := 0
	for _, e := range c.all() {
		if e.Kind == kind {
			n++
		}
	}
	return n
}

func testEvent(ip, kind string) event.Event {
	return event.Event{
		Time:    time.Now(),
		Node:    "sensor-1",
		Service: "ssh",
		Kind:    kind,
		SrcIP:   ip,
		SrcPort: 4444,
		DstPort: 2222,
	}
}

// TestFirstEventsAlwaysPass is the property that keeps the limiter from
// defeating the point of the sensor: the opening events from a new source are
// the alert.
func TestFirstEventsAlwaysPass(t *testing.T) {
	out := &capture{}
	l := NewLimiter(out, LimitConfig{})
	defer l.Close()

	for i := 0; i < DefaultPerSourceBurst; i++ {
		l.Emit(testEvent("10.0.0.5", "connection"))
	}

	if n := out.countKind("connection"); n != DefaultPerSourceBurst {
		t.Errorf("%d of the first %d events got through, want all of them",
			n, DefaultPerSourceBurst)
	}
}

// TestFloodIsCapped is the reason the limiter exists: an attacker who finds the
// honeypot must not be able to choose how much this sensor writes.
func TestFloodIsCapped(t *testing.T) {
	out := &capture{}
	l := NewLimiter(out, LimitConfig{})
	defer l.Close()

	const flood = 20000
	for i := 0; i < flood; i++ {
		l.Emit(testEvent("10.0.0.5", "connection"))
	}

	passed := out.countKind("connection")
	if passed > DefaultPerSourceBurst+10 { // +10 for refill during the loop
		t.Errorf("%d of %d flood events were written, want about %d",
			passed, flood, DefaultPerSourceBurst)
	}
	if passed == 0 {
		t.Error("the flood was silenced completely — the first events must still land")
	}
}

// TestHighValueSurvivesNoiseFlood is the property the two-tier budget exists
// for. An attacker who floods with bare connections must not be able to hide
// the password they try next.
func TestHighValueSurvivesNoiseFlood(t *testing.T) {
	out := &capture{}
	l := NewLimiter(out, LimitConfig{})
	defer l.Close()

	for i := 0; i < 5000; i++ {
		l.Emit(testEvent("10.0.0.5", "connection"))
	}
	l.Emit(testEvent("10.0.0.5", "login_password"))

	if n := out.countKind("login_password"); n != 1 {
		t.Errorf("the credential event was dropped after a noise flood (got %d, want 1)", n)
	}
}

// TestOneSourceCannotStarveAnother: the per-source limit is what protects the
// sensor-wide budget, so a single flood must not silence the rest of the
// network.
func TestOneSourceCannotStarveAnother(t *testing.T) {
	out := &capture{}
	l := NewLimiter(out, LimitConfig{})
	defer l.Close()

	for i := 0; i < 10000; i++ {
		l.Emit(testEvent("10.0.0.5", "connection"))
	}

	before := len(out.all())
	l.Emit(testEvent("192.168.1.9", "login_password"))

	if len(out.all()) == before {
		t.Error("an event from a second source was dropped while the first was flooding")
	}
}

// TestSuppressionIsReported — a silently truncated log looks like a quiet
// network, which is the opposite of what a flood should look like.
func TestSuppressionIsReported(t *testing.T) {
	out := &capture{}
	l := NewLimiter(out, LimitConfig{})

	const flood = 500
	for i := 0; i < flood; i++ {
		l.Emit(testEvent("10.0.0.5", "connection"))
	}
	l.Close() // flushes whatever is still pending

	var summary *event.Event
	for _, e := range out.all() {
		if e.Kind == "rate_limited" {
			summary = &e
			break
		}
	}
	if summary == nil {
		t.Fatal("no rate_limited event was emitted — the drops went unreported")
	}

	dropped, ok := summary.Data["dropped"].(int64)
	if !ok || dropped == 0 {
		t.Fatalf("summary dropped = %v, want a non-zero count", summary.Data["dropped"])
	}
	if passed := int64(out.countKind("connection")); dropped+passed != flood {
		t.Errorf("summary accounts for %d + %d passed = %d events, want %d",
			dropped, passed, dropped+passed, flood)
	}
	if summary.SrcIP != "10.0.0.5" || summary.Node != "sensor-1" {
		t.Errorf("summary lost the source context: src=%s node=%s",
			summary.SrcIP, summary.Node)
	}
}

// TestSourceTableIsBounded closes the other denial of service: an attacker
// rotating source addresses must not be able to make the sensor allocate
// without limit.
func TestSourceTableIsBounded(t *testing.T) {
	out := &capture{}
	l := NewLimiter(out, LimitConfig{})
	defer l.Close()

	for i := 0; i < maxTrackedSources*2; i++ {
		l.Emit(testEvent(fmt.Sprintf("10.%d.%d.%d", i/65536, (i/256)%256, i%256), "connection"))
	}

	l.mu.Lock()
	tracked := len(l.sources)
	l.mu.Unlock()

	if tracked > maxTrackedSources {
		t.Errorf("tracking %d sources, want at most %d", tracked, maxTrackedSources)
	}
}

// TestDisabledConfigUsesDefaults: a zero value in the config means "unset", not
// "block everything". A typo must never silence a sensor.
func TestZeroConfigUsesDefaults(t *testing.T) {
	got := LimitConfig{}.withDefaults()
	if got != DefaultLimit() {
		t.Errorf("zero config resolved to %+v, want the defaults %+v", got, DefaultLimit())
	}

	partial := LimitConfig{PerSourceRate: 5}.withDefaults()
	if partial.PerSourceRate != 5 {
		t.Errorf("PerSourceRate = %d, want the configured 5", partial.PerSourceRate)
	}
	if partial.GlobalRate != DefaultGlobalRate {
		t.Errorf("GlobalRate = %d, want the default %d", partial.GlobalRate, DefaultGlobalRate)
	}
}

// TestBucketRefills checks the limiter recovers: a source that backs off is
// heard from again.
func TestBucketRefills(t *testing.T) {
	b := newBucket(60, 2) // one per second, two in hand
	start := time.Now()

	if !b.allow(start) || !b.allow(start) {
		t.Fatal("the burst was not available")
	}
	if b.allow(start) {
		t.Fatal("a third event was allowed with an empty bucket")
	}
	if !b.allow(start.Add(2 * time.Second)) {
		t.Error("the bucket did not refill after two seconds")
	}
}
