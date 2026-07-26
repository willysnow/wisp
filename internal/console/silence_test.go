package console

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/willysnow/wisp/internal/console/store"
	"github.com/willysnow/wisp/internal/event"
)

// deliver writes one event as the named sensor, which is what makes the
// console consider it alive.
func deliver(t *testing.T, st *store.Store, node string) {
	t.Helper()

	if err := st.Insert(context.Background(), []event.Event{{
		Time: time.Now(), Node: node, Service: "ssh", Kind: "connection",
		SrcIP: "10.0.0.1",
	}}); err != nil {
		t.Fatalf("insert: %v", err)
	}
}

// backdate moves a sensor's last delivery into the past, standing in for the
// sensor having gone quiet.
func backdate(t *testing.T, st *store.Store, node string, ago time.Duration) {
	t.Helper()

	if err := st.SetSensorLastSeen(context.Background(), node, time.Now().Add(-ago)); err != nil {
		t.Fatalf("backdate: %v", err)
	}
}

// TestSilentSensorIsReported is the property this feature exists for.
//
// A sensor that has been found and stopped produces exactly the same thing as
// a network where nothing is happening: nothing. The console is the only place
// that can tell those apart, and if it does not, an intrusion that begins by
// killing the sensor is invisible.
func TestSilentSensorIsReported(t *testing.T) {
	_, st := newTestServer(t, "")
	ctx := context.Background()

	deliver(t, st, "sensor-1")
	backdate(t, st, "sensor-1", time.Hour)

	watcher := NewSilenceWatcher(st, SilencePolicy{After: 30 * time.Minute}, nil, nil)

	events, err := watcher.Check(ctx)
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if len(events) != 1 || events[0].Kind != KindSensorSilent {
		t.Fatalf("got %d events %v, want one sensor_silent", len(events), events)
	}
	if events[0].Node != "sensor-1" {
		t.Errorf("Node = %q, want the sensor that went quiet", events[0].Node)
	}
	if note, _ := events[0].Data["note"].(string); !strings.Contains(note, "found and stopped") {
		t.Errorf("note = %q, want it to say what silence may mean", note)
	}

	// The alert has to reach the timeline too, or an operator who was not
	// notified has no record of the gap.
	stored, err := st.List(ctx, store.Filter{Kind: KindSensorSilent})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(stored) != 1 {
		t.Errorf("stored %d silence events, want 1", len(stored))
	}
}

// TestSilenceIsReportedOnce: a sensor that stays down must not page someone
// every minute until they turn the console off.
func TestSilenceIsReportedOnce(t *testing.T) {
	_, st := newTestServer(t, "")
	ctx := context.Background()

	deliver(t, st, "sensor-1")
	backdate(t, st, "sensor-1", time.Hour)

	watcher := NewSilenceWatcher(st, SilencePolicy{After: 30 * time.Minute}, nil, nil)

	if events, _ := watcher.Check(ctx); len(events) != 1 {
		t.Fatalf("first check raised %d events, want 1", len(events))
	}
	for i := 0; i < 3; i++ {
		events, err := watcher.Check(ctx)
		if err != nil {
			t.Fatalf("check: %v", err)
		}
		if len(events) != 0 {
			t.Fatalf("repeat check %d raised %v, want nothing", i+1, events)
		}
	}
}

// TestReturningSensorIsReported — whoever was woken at 3am should not have to
// guess whether it is still down.
func TestReturningSensorIsReported(t *testing.T) {
	_, st := newTestServer(t, "")
	ctx := context.Background()

	deliver(t, st, "sensor-1")
	backdate(t, st, "sensor-1", time.Hour)

	watcher := NewSilenceWatcher(st, SilencePolicy{After: 30 * time.Minute}, nil, nil)
	if _, err := watcher.Check(ctx); err != nil {
		t.Fatalf("check: %v", err)
	}

	// It reports again.
	deliver(t, st, "sensor-1")

	events, err := watcher.Check(ctx)
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if len(events) != 1 || events[0].Kind != KindSensorReturned {
		t.Fatalf("got %v, want one sensor_returned", events)
	}

	// And it can go quiet again later — the flag must have been cleared, not
	// just skipped.
	backdate(t, st, "sensor-1", time.Hour)
	again, err := watcher.Check(ctx)
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if len(again) != 1 || again[0].Kind != KindSensorSilent {
		t.Fatalf("got %v, want the sensor to be reportable as silent again", again)
	}
}

// TestSilenceAlertDoesNotRevivePatient is the subtle one.
//
// The alert is attributed to the sensor that went quiet, because that is what
// an operator filters on. If storing it went through the normal ingest path it
// would update that sensor's last_seen — and the console would immediately
// decide the sensor was healthy again, on the strength of its own alert.
func TestSilenceAlertDoesNotReviveSensor(t *testing.T) {
	_, st := newTestServer(t, "")
	ctx := context.Background()

	deliver(t, st, "sensor-1")
	backdate(t, st, "sensor-1", time.Hour)

	watcher := NewSilenceWatcher(st, SilencePolicy{After: 30 * time.Minute}, nil, nil)
	if _, err := watcher.Check(ctx); err != nil {
		t.Fatalf("check: %v", err)
	}

	sensors, err := st.Sensors(ctx)
	if err != nil {
		t.Fatalf("sensors: %v", err)
	}
	if len(sensors) != 1 {
		t.Fatalf("got %d sensors, want 1", len(sensors))
	}
	if time.Since(sensors[0].LastSeen) < 30*time.Minute {
		t.Error("the silence alert updated the sensor's last_seen — it now looks alive")
	}

	// And the very next check must not report it as returned.
	events, err := watcher.Check(ctx)
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if len(events) != 0 {
		t.Errorf("got %v, want nothing — the sensor is still quiet", events)
	}
}

// TestDisabledPolicyReportsNothing: a console that was not asked to watch for
// silence must not invent alerts.
func TestDisabledPolicyReportsNothing(t *testing.T) {
	_, st := newTestServer(t, "")

	deliver(t, st, "sensor-1")
	backdate(t, st, "sensor-1", 30*24*time.Hour)

	watcher := NewSilenceWatcher(st, SilencePolicy{}, nil, nil)
	events, err := watcher.Check(context.Background())
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if len(events) != 0 {
		t.Errorf("got %v with no policy configured, want nothing", events)
	}
}

// TestSilenceKindsNotify — an alert nobody is told about is a log line. These
// kinds have to be on the list the dispatcher sends.
func TestSilenceKindsNotify(t *testing.T) {
	for _, kind := range []string{KindSensorSilent, KindSensorReturned} {
		if !event.IsHighValue(kind) {
			t.Errorf("%s is not a notifying kind, so nobody would hear about it", kind)
		}
	}
}

// TestSilentSensorIsMarkedInTheUI closes the loop: the operator who opens the
// page has to see it, not only the one who read the notification.
func TestSilentSensorIsMarkedInTheUI(t *testing.T) {
	srv, st := newUIServer(t)
	srv.silenceAfter = 30 * time.Minute

	deliver(t, st, "quiet-one")
	backdate(t, st, "quiet-one", time.Hour)
	deliver(t, st, "healthy-one")

	session := cookieNamed(login(t, srv, testUser, testPassword), sessionCookieName)
	body := get(t, srv, "/", session).Body.String()

	if !strings.Contains(body, "silent") {
		t.Error("the quiet sensor is not marked on the page")
	}
}
