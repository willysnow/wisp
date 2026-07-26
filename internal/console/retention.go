package console

import (
	"context"
	"log"
	"time"

	"github.com/willysnow/wisp/internal/console/store"
)

// DefaultRetentionInterval is how often housekeeping runs. Hourly is often
// enough that the database never drifts far past the limit, and rare enough
// that the work is invisible.
const DefaultRetentionInterval = time.Hour

// vacuumThreshold is how many deleted rows must accumulate before the janitor
// rebuilds the database file. VACUUM takes a write lock over the whole
// database, so it is worth doing after a real purge and not after trimming
// nine rows.
const vacuumThreshold = 5000

// Retention is the console's storage policy. Zero values mean "no limit",
// which is the default: silently discarding an operator's evidence because
// they did not configure anything would be the wrong way round.
type Retention struct {
	// MaxAge drops events older than this.
	MaxAge time.Duration
	// MaxEvents keeps only the newest N events, whatever their age.
	MaxEvents int64
	// Interval is how often the policy is applied.
	Interval time.Duration
}

// Enabled reports whether any limit is set.
func (r Retention) Enabled() bool { return r.MaxAge > 0 || r.MaxEvents > 0 }

// Janitor applies the retention policy on a timer.
//
// Without it the console is a service whose disk usage is chosen by whoever is
// scanning the sensors. Filling the disk stops ingest, and an attacker who
// notices that has found a way to blind the fleet with a port scan.
type Janitor struct {
	store  *store.Store
	policy Retention
	logger *log.Logger

	// sinceVacuum counts rows deleted since the file was last rebuilt.
	sinceVacuum int64
}

func NewJanitor(st *store.Store, policy Retention, logger *log.Logger) *Janitor {
	if policy.Interval <= 0 {
		policy.Interval = DefaultRetentionInterval
	}
	return &Janitor{store: st, policy: policy, logger: logger}
}

// Sweep applies the policy once and reports what it removed.
func (j *Janitor) Sweep(ctx context.Context) (Sweep, error) {
	var out Sweep

	// Expired sessions are cleared regardless of the event policy: they are
	// the console's own litter, not the operator's data.
	n, err := j.store.PurgeExpiredSessions(ctx)
	if err != nil {
		return out, err
	}
	out.Sessions = n

	if j.policy.MaxAge > 0 {
		n, err := j.store.DeleteEventsBefore(ctx, time.Now().Add(-j.policy.MaxAge))
		if err != nil {
			return out, err
		}
		out.ByAge = n
	}

	if j.policy.MaxEvents > 0 {
		n, err := j.store.TrimEvents(ctx, j.policy.MaxEvents)
		if err != nil {
			return out, err
		}
		out.ByCount = n
	}

	j.sinceVacuum += out.ByAge + out.ByCount
	if j.sinceVacuum >= vacuumThreshold {
		if err := j.store.Vacuum(ctx); err != nil {
			return out, err
		}
		j.sinceVacuum = 0
		out.Vacuumed = true
	}

	return out, nil
}

// Sweep is the result of one housekeeping pass.
type Sweep struct {
	ByAge    int64
	ByCount  int64
	Sessions int64
	Vacuumed bool
}

// Events is the total number of events removed.
func (s Sweep) Events() int64 { return s.ByAge + s.ByCount }

// Run applies the policy immediately and then on every interval, until ctx is
// cancelled. It is meant to be called in its own goroutine.
func (j *Janitor) Run(ctx context.Context) {
	ticker := time.NewTicker(j.policy.Interval)
	defer ticker.Stop()

	for {
		sweep, err := j.Sweep(ctx)
		switch {
		case ctx.Err() != nil:
			return
		case err != nil:
			j.logf("retention sweep failed: %v", err)
		case sweep.Events() > 0:
			j.logf("retention: removed %d events (%d aged out, %d over the limit)",
				sweep.Events(), sweep.ByAge, sweep.ByCount)
		}

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (j *Janitor) logf(format string, args ...any) {
	if j.logger != nil {
		j.logger.Printf(format, args...)
	}
}
