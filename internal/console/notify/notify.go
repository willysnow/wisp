// Package notify turns stored events into alerts someone actually sees.
//
// Two problems have to be solved together, and solving only one makes the
// console useless in opposite ways:
//
//   - Notify on everything and a single port scan sends thirty messages. The
//     operator mutes the channel, and the next real intrusion is missed.
//   - Notify on nothing and the console is a dashboard nobody opens.
//
// So notification is filtered by event kind (only things that mean something
// happened) and then suppressed by key over a time window (the same attacker
// hitting the same service repeatedly is one alert, with a count).
package notify

import (
	"context"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/willysnow/wisp/internal/event"
)

// DefaultWindow is how long a given alert key stays suppressed after firing.
const DefaultWindow = 15 * time.Minute

// sendTimeout bounds one delivery attempt.
const sendTimeout = 20 * time.Second

// DefaultKinds are the event kinds worth waking someone for: a credential was
// offered, or the intruder stated their intent. Everything else (bare
// connections, version probes, discovery calls) is recorded but not pushed —
// it is context for the investigation, not the trigger for one.
//
// It is the same list the sensor's rate limiter protects, and deliberately so:
// the events a flood must not drown out are the events worth a notification.
var DefaultKinds = event.HighValueKinds

// Alert is one notification-worthy event, plus how many similar events were
// folded into it since the last time this key fired.
type Alert struct {
	Event    event.Event
	Repeated int
}

// Notifier delivers alerts somewhere. Implementations must be safe for
// concurrent use.
type Notifier interface {
	Name() string
	Send(ctx context.Context, a Alert) error
}

// Suppressor collapses repeats of the same alert key within a window.
type Suppressor struct {
	window time.Duration

	mu   sync.Mutex
	seen map[string]*entry
}

type entry struct {
	until    time.Time
	repeated int
}

func NewSuppressor(window time.Duration) *Suppressor {
	if window <= 0 {
		window = DefaultWindow
	}
	return &Suppressor{window: window, seen: map[string]*entry{}}
}

// Admit reports whether an alert for key should fire now. When it should, it
// also returns how many events were suppressed since the previous firing, so
// the alert can say "and 47 more".
func (s *Suppressor) Admit(key string, now time.Time) (allow bool, repeated int) {
	s.mu.Lock()
	defer s.mu.Unlock()

	e, ok := s.seen[key]
	if !ok {
		s.seen[key] = &entry{until: now.Add(s.window)}
		return true, 0
	}
	if now.After(e.until) {
		repeated = e.repeated
		e.until = now.Add(s.window)
		e.repeated = 0
		return true, repeated
	}

	e.repeated++
	return false, 0
}

// sweep drops keys whose window expired long enough ago that they carry no
// pending count. Without it, a wide scan would leave one map entry per source
// address forever.
func (s *Suppressor) sweep(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for k, e := range s.seen {
		if e.repeated == 0 && now.After(e.until.Add(s.window)) {
			delete(s.seen, k)
		}
	}
}

// Key identifies "the same alert happening again". Source IP and kind are the
// load-bearing parts: the same attacker retrying the same thing is one story,
// while a second source address doing the same thing is a new one.
func Key(e event.Event) string {
	return strings.Join([]string{e.Node, e.Service, e.Kind, e.SrcIP}, "|")
}

// Dispatcher filters, suppresses, and fans alerts out to every notifier.
type Dispatcher struct {
	notifiers []Notifier
	sup       *Suppressor
	kinds     map[string]bool
	logger    *log.Logger

	wg   sync.WaitGroup
	done chan struct{}
}

// NewDispatcher returns a dispatcher. An empty kinds slice means DefaultKinds;
// to notify on everything, pass []string{"*"}.
func NewDispatcher(notifiers []Notifier, window time.Duration, kinds []string, logger *log.Logger) *Dispatcher {
	if len(kinds) == 0 {
		kinds = DefaultKinds
	}
	set := make(map[string]bool, len(kinds))
	for _, k := range kinds {
		set[k] = true
	}

	d := &Dispatcher{
		notifiers: notifiers,
		sup:       NewSuppressor(window),
		kinds:     set,
		logger:    logger,
		done:      make(chan struct{}),
	}

	d.wg.Add(1)
	go d.sweepLoop()
	return d
}

func (d *Dispatcher) Enabled() bool { return len(d.notifiers) > 0 }

// Handle processes a batch of freshly ingested events.
//
// It returns immediately: ingest must not wait on an SMTP server or a Slack
// webhook, because a sensor whose delivery times out will retry and eventually
// drop events it has already successfully reported.
func (d *Dispatcher) Handle(events []event.Event) {
	if !d.Enabled() {
		return
	}

	now := time.Now()
	var alerts []Alert
	for _, e := range events {
		if !d.kinds[e.Kind] && !d.kinds["*"] {
			continue
		}
		allow, repeated := d.sup.Admit(Key(e), now)
		if !allow {
			continue
		}
		alerts = append(alerts, Alert{Event: e, Repeated: repeated})
	}
	if len(alerts) == 0 {
		return
	}

	d.wg.Add(1)
	go func() {
		defer d.wg.Done()
		d.deliver(alerts)
	}()
}

func (d *Dispatcher) deliver(alerts []Alert) {
	for _, a := range alerts {
		for _, n := range d.notifiers {
			ctx, cancel := context.WithTimeout(context.Background(), sendTimeout)
			err := n.Send(ctx, a)
			cancel()
			if err != nil {
				// A failed notification is logged, not retried. The event is
				// already durably stored; the console is the source of truth
				// and a retry storm against a broken webhook helps nobody.
				d.logger.Printf("notify: %s failed: %v", n.Name(), err)
			}
		}
	}
}

func (d *Dispatcher) sweepLoop() {
	defer d.wg.Done()

	ticker := time.NewTicker(DefaultWindow)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			d.sup.sweep(time.Now())
		case <-d.done:
			return
		}
	}
}

// Close waits for in-flight notifications to finish.
func (d *Dispatcher) Close() {
	close(d.done)
	d.wg.Wait()
}

// Summary renders an alert as a single human-readable line, shared by every
// notifier so an email and a Slack message say the same thing.
func (a Alert) Summary() string {
	var b strings.Builder
	b.WriteString(a.Event.Service)
	b.WriteString(" ")
	b.WriteString(a.Event.Kind)
	b.WriteString(" from ")
	b.WriteString(a.Event.SrcIP)
	b.WriteString(" on ")
	b.WriteString(a.Event.Node)
	if a.Repeated > 0 {
		b.WriteString(" (+")
		b.WriteString(itoa(a.Repeated))
		b.WriteString(" similar suppressed)")
	}
	return b.String()
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
