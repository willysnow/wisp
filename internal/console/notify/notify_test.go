package notify

import (
	"context"
	"io"
	"log"
	"sync"
	"testing"
	"time"

	"github.com/willysnow/wisp/internal/event"
)

// recorder captures what a notifier was asked to send.
type recorder struct {
	mu     sync.Mutex
	alerts []Alert
}

func (r *recorder) Name() string { return "recorder" }

func (r *recorder) Send(_ context.Context, a Alert) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.alerts = append(r.alerts, a)
	return nil
}

func (r *recorder) get() []Alert {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]Alert(nil), r.alerts...)
}

func ev(service, kind, srcIP string) event.Event {
	return event.Event{
		Time:    time.Now(),
		Node:    "sensor-1",
		Service: service,
		Kind:    kind,
		SrcIP:   srcIP,
		Data:    map[string]any{},
	}
}

// TestSuppressorCollapsesRepeats is the property that decides whether anyone
// keeps notifications switched on. A scanner hitting one service repeatedly is
// one story, not thirty messages.
func TestSuppressorCollapsesRepeats(t *testing.T) {
	s := NewSuppressor(15 * time.Minute)
	now := time.Now()

	allow, repeated := s.Admit("k", now)
	if !allow || repeated != 0 {
		t.Fatalf("first admit = (%v, %d), want (true, 0)", allow, repeated)
	}

	for i := 0; i < 30; i++ {
		if allow, _ := s.Admit("k", now.Add(time.Duration(i)*time.Second)); allow {
			t.Fatalf("repeat %d was admitted inside the window", i)
		}
	}

	// After the window, the next one fires and reports what it swallowed.
	allow, repeated = s.Admit("k", now.Add(16*time.Minute))
	if !allow {
		t.Fatal("admit after window expiry = false, want true")
	}
	if repeated != 30 {
		t.Errorf("repeated = %d, want 30", repeated)
	}
}

// TestSuppressorSeparatesKeys guards the other half: suppression must not hide
// a genuinely new attacker. A second source IP is a new story even when
// everything else matches.
func TestSuppressorSeparatesKeys(t *testing.T) {
	s := NewSuppressor(15 * time.Minute)
	now := time.Now()

	a := Key(ev("ssh", "login_password", "10.0.0.1"))
	b := Key(ev("ssh", "login_password", "10.0.0.2"))
	c := Key(ev("redis", "login_password", "10.0.0.1"))

	for _, k := range []string{a, b, c} {
		if allow, _ := s.Admit(k, now); !allow {
			t.Errorf("key %q was suppressed on first sight", k)
		}
	}
}

// TestSweepDoesNotDiscardPendingCounts checks that housekeeping cannot lose a
// suppressed count that has not been reported yet.
func TestSweepDoesNotDiscardPendingCounts(t *testing.T) {
	s := NewSuppressor(time.Minute)
	now := time.Now()

	s.Admit("k", now)
	s.Admit("k", now) // suppressed; repeated = 1

	// Long after the window, but the pending count must survive the sweep.
	s.sweep(now.Add(10 * time.Minute))

	allow, repeated := s.Admit("k", now.Add(11*time.Minute))
	if !allow {
		t.Fatal("admit after sweep = false, want true")
	}
	if repeated != 1 {
		t.Errorf("repeated = %d, want 1 (the sweep dropped a pending count)", repeated)
	}
}

// TestDispatcherFiltersByKind confirms low-value events never reach a notifier.
// Bare connections and version probes are context for an investigation, not a
// reason to wake someone.
func TestDispatcherFiltersByKind(t *testing.T) {
	rec := &recorder{}
	d := NewDispatcher([]Notifier{rec}, time.Minute, nil, log.New(io.Discard, "", 0))

	d.Handle([]event.Event{
		ev("ssh", "connect", "10.0.0.1"),     // noise
		ev("k8s", "probe", "10.0.0.1"),       // noise
		ev("http", "login_form", "10.0.0.1"), // credential
		ev("ollama", "prompt", "10.0.0.2"),   // stated intent
	})
	d.Close()

	got := rec.get()
	if len(got) != 2 {
		t.Fatalf("sent %d alerts, want 2", len(got))
	}
	for _, a := range got {
		switch a.Event.Kind {
		case "login_form", "prompt":
		default:
			t.Errorf("unexpected alert for kind %q", a.Event.Kind)
		}
	}
}

// TestDispatcherWildcard covers the escape hatch for operators who want
// everything.
func TestDispatcherWildcard(t *testing.T) {
	rec := &recorder{}
	d := NewDispatcher([]Notifier{rec}, time.Minute, []string{"*"}, log.New(io.Discard, "", 0))

	d.Handle([]event.Event{
		ev("ssh", "connect", "10.0.0.1"),
		ev("k8s", "probe", "10.0.0.2"),
	})
	d.Close()

	if got := rec.get(); len(got) != 2 {
		t.Fatalf("sent %d alerts, want 2", len(got))
	}
}

// TestDispatcherWithNoNotifiersIsInert makes sure the default configuration
// (console only, nothing configured) does no work and does not panic.
func TestDispatcherWithNoNotifiersIsInert(t *testing.T) {
	d := NewDispatcher(nil, time.Minute, nil, log.New(io.Discard, "", 0))
	if d.Enabled() {
		t.Error("Enabled() = true with no notifiers")
	}
	d.Handle([]event.Event{ev("ssh", "login_password", "10.0.0.1")})
	d.Close()
}

// TestSummaryReportsSuppressedCount checks the operator can tell a single probe
// from a sustained one.
func TestSummaryReportsSuppressedCount(t *testing.T) {
	a := Alert{Event: ev("ssh", "login_password", "10.0.0.9"), Repeated: 47}

	got := a.Summary()
	want := "ssh login_password from 10.0.0.9 on sensor-1 (+47 similar suppressed)"
	if got != want {
		t.Errorf("Summary() = %q, want %q", got, want)
	}

	plain := Alert{Event: ev("ssh", "login_password", "10.0.0.9")}.Summary()
	if plain != "ssh login_password from 10.0.0.9 on sensor-1" {
		t.Errorf("Summary() with no repeats = %q", plain)
	}
}
