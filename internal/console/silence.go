package console

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/willysnow/wisp/internal/console/notify"
	"github.com/willysnow/wisp/internal/console/store"
	"github.com/willysnow/wisp/internal/event"
)

// A sensor that goes quiet looks exactly like a network with nothing happening
// on it, and only the console can tell those apart. The sensor cannot report
// its own death: if someone found it and killed the process, pulled the cable,
// or filled its disk, the last thing it would do is stay silent.
//
// So silence is treated as an event in its own right. Nothing else in wisp
// alerts on the absence of something.

// SilenceService is the name these events carry. It is not a sensor's service,
// so it is named for the console itself — filtering the UI by service=wisp
// shows what the console noticed on its own.
const SilenceService = "wisp"

const (
	// KindSensorSilent is raised once when a sensor crosses the threshold.
	KindSensorSilent = "sensor_silent"
	// KindSensorReturned is raised once when it starts reporting again. Worth
	// its own event: an operator who was paged at 3am should not have to guess
	// whether it is still down.
	KindSensorReturned = "sensor_returned"
)

// DefaultSilenceCheck is how often the watcher looks. A minute is fine
// resolution for a threshold measured in tens of minutes, and the query is two
// indexed reads.
const DefaultSilenceCheck = time.Minute

// SilencePolicy configures the watcher. A zero After disables it.
type SilencePolicy struct {
	// After is how long a sensor may be quiet before it is reported.
	After time.Duration
	// CheckInterval is how often the check runs. Zero means DefaultSilenceCheck.
	CheckInterval time.Duration
}

func (p SilencePolicy) Enabled() bool { return p.After > 0 }

// SilenceWatcher reports sensors that stop and start reporting.
type SilenceWatcher struct {
	store    *store.Store
	policy   SilencePolicy
	dispatch *notify.Dispatcher
	logger   *log.Logger
}

func NewSilenceWatcher(st *store.Store, policy SilencePolicy, dispatch *notify.Dispatcher, logger *log.Logger) *SilenceWatcher {
	if policy.CheckInterval <= 0 {
		policy.CheckInterval = DefaultSilenceCheck
	}
	return &SilenceWatcher{store: st, policy: policy, dispatch: dispatch, logger: logger}
}

// Check runs one pass and returns the events it raised.
func (w *SilenceWatcher) Check(ctx context.Context) ([]event.Event, error) {
	if !w.policy.Enabled() {
		return nil, nil
	}

	cutoff := time.Now().Add(-w.policy.After)
	silent, returned, err := w.store.SilenceTransitions(ctx, cutoff)
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	var events []event.Event

	for _, s := range silent {
		quiet := now.Sub(s.LastSeen).Round(time.Second)
		events = append(events, event.Event{
			Time:    now,
			Node:    s.Node,
			Service: SilenceService,
			Kind:    KindSensorSilent,
			Data: map[string]any{
				"last_seen":  s.LastSeen.UTC().Format(time.RFC3339),
				"silent_for": quiet.String(),
				"threshold":  w.policy.After.String(),
				// Said plainly, because the alert has to carry its own meaning
				// to whoever reads it on a phone at 3am.
				"note": fmt.Sprintf(
					"%s has not reported for %s. A sensor that goes quiet may have been found and stopped.",
					s.Node, quiet),
			},
		})
	}

	for _, s := range returned {
		events = append(events, event.Event{
			Time:    now,
			Node:    s.Node,
			Service: SilenceService,
			Kind:    KindSensorReturned,
			Data: map[string]any{
				"last_seen": s.LastSeen.UTC().Format(time.RFC3339),
				"note":      fmt.Sprintf("%s is reporting again.", s.Node),
			},
		})
	}

	if len(events) == 0 {
		return nil, nil
	}

	// Stored first, so the timeline shows the gap even if every notifier is
	// down — which is a real possibility when the network is having the kind
	// of day that makes a sensor go quiet.
	if err := w.store.InsertSystem(ctx, events); err != nil {
		return events, err
	}
	if w.dispatch != nil {
		w.dispatch.Handle(events)
	}
	return events, nil
}

// Run checks on every interval until ctx is cancelled.
func (w *SilenceWatcher) Run(ctx context.Context) {
	if !w.policy.Enabled() {
		return
	}

	ticker := time.NewTicker(w.policy.CheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		events, err := w.Check(ctx)
		switch {
		case ctx.Err() != nil:
			return
		case err != nil:
			w.logf("sensor silence check failed: %v", err)
		default:
			for _, e := range events {
				w.logf("%s: %s", e.Kind, e.Data["note"])
			}
		}
	}
}

func (w *SilenceWatcher) logf(format string, args ...any) {
	if w.logger != nil {
		w.logger.Printf(format, args...)
	}
}
