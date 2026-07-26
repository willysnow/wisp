package sink

import (
	"sort"
	"sync"
	"time"

	"github.com/willysnow/wisp/internal/event"
)

// Rate limiting exists because a honeypot is, by construction, a machine that
// writes a record every time a stranger touches it. An attacker who works out
// what it is can turn that into a weapon: hold the port open and the sensor
// fills its own disk, or delivers hard enough to bury the console. The sensor
// must not be the tool that takes down the fleet's monitoring.
//
// The limiter is deliberately not a plain cap. Three properties matter more
// than the numbers:
//
//  1. The first events from a new source always get through. That is the alert;
//     dropping it to save disk would be exactly backwards.
//  2. Credentials and prompts have their own budget, so a flood of bare
//     connections cannot crowd out the one password that matters.
//  3. Suppression is itself reported. A silently truncated log looks like a
//     quiet network, and going quiet is precisely what being flooded should not
//     look like.
const (
	// DefaultPerSourceRate is events per minute from one source IP, for
	// ordinary traffic.
	DefaultPerSourceRate = 60
	// DefaultPerSourceBurst is how many may arrive at once — a port scan
	// touching every service should land in full.
	DefaultPerSourceBurst = 30

	// High-value kinds get their own, separate allowance. A brute force is a
	// genuine flood of login_password events, and after a hundred of them the
	// hundred-and-first adds nothing the summary does not.
	DefaultHighValueRate  = 30
	DefaultHighValueBurst = 60

	// DefaultGlobalRate bounds the sensor as a whole, across every source. The
	// backstop for a distributed scan, where no single address trips its own
	// limit.
	DefaultGlobalRate  = 600
	DefaultGlobalBurst = 300

	// summaryInterval is how often a throttled source reports what it dropped.
	summaryInterval = time.Minute

	// summaryCheckInterval is how often pending summaries are checked. Without
	// it, a flood that stops would never report its final count — a summary
	// otherwise only falls due when the next event from that source arrives.
	summaryCheckInterval = 15 * time.Second

	// maxTrackedSources bounds the limiter's own memory. An attacker rotating
	// source addresses must not be able to make the sensor allocate forever —
	// that is the same denial of service by another route.
	maxTrackedSources = 4096

	// idleEviction is how long a quiet source is kept. Forgetting one costs
	// nothing: with a full bucket it would be admitted on its next event anyway.
	idleEviction = 5 * time.Minute
)

// LimitConfig is the sensor's rate limit, in events per minute.
type LimitConfig struct {
	PerSourceRate  int
	PerSourceBurst int
	HighValueRate  int
	HighValueBurst int
	GlobalRate     int
	GlobalBurst    int
}

// DefaultLimit returns the built-in limits.
func DefaultLimit() LimitConfig {
	return LimitConfig{
		PerSourceRate:  DefaultPerSourceRate,
		PerSourceBurst: DefaultPerSourceBurst,
		HighValueRate:  DefaultHighValueRate,
		HighValueBurst: DefaultHighValueBurst,
		GlobalRate:     DefaultGlobalRate,
		GlobalBurst:    DefaultGlobalBurst,
	}
}

// withDefaults fills in unset fields. A zero means "unset", not "block
// everything" — a config typo must never silence the sensor.
func (c LimitConfig) withDefaults() LimitConfig {
	d := DefaultLimit()
	if c.PerSourceRate <= 0 {
		c.PerSourceRate = d.PerSourceRate
	}
	if c.PerSourceBurst <= 0 {
		c.PerSourceBurst = d.PerSourceBurst
	}
	if c.HighValueRate <= 0 {
		c.HighValueRate = d.HighValueRate
	}
	if c.HighValueBurst <= 0 {
		c.HighValueBurst = d.HighValueBurst
	}
	if c.GlobalRate <= 0 {
		c.GlobalRate = d.GlobalRate
	}
	if c.GlobalBurst <= 0 {
		c.GlobalBurst = d.GlobalBurst
	}
	return c
}

// bucket is a token bucket that refills continuously.
type bucket struct {
	tokens   float64
	capacity float64
	perSec   float64
	last     time.Time
}

func newBucket(ratePerMinute, burst int) *bucket {
	return &bucket{
		tokens:   float64(burst),
		capacity: float64(burst),
		perSec:   float64(ratePerMinute) / 60,
	}
}

// allow spends a token if one is available.
func (b *bucket) allow(now time.Time) bool {
	if !b.last.IsZero() {
		b.tokens += now.Sub(b.last).Seconds() * b.perSec
		if b.tokens > b.capacity {
			b.tokens = b.capacity
		}
	}
	b.last = now

	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// source is one address's state.
type source struct {
	ip        string
	normal    *bucket
	highValue *bucket

	dropped      map[string]int64 // by kind, for the summary
	droppedTotal int64
	firstDrop    time.Time
	lastSummary  time.Time
	lastSeen     time.Time

	// Context of the most recent dropped event, so a summary can be emitted
	// later without an event in hand.
	node    string
	service string
	srcPort int
	dstPort int
}

// Limiter caps how many events reach the sinks behind it.
//
// Emit is safe for concurrent use and never blocks: a service goroutine held up
// by bookkeeping is a worse failure than a dropped event.
type Limiter struct {
	next event.Emitter
	cfg  LimitConfig

	mu      sync.Mutex
	sources map[string]*source
	global  *bucket

	// globalDropped counts events lost to the sensor-wide cap, which belong to
	// no single source.
	globalDropped int64

	done chan struct{}
	wg   sync.WaitGroup
}

// NewLimiter wraps next. A zero LimitConfig means the defaults. Call Close to
// flush any pending suppression summary.
func NewLimiter(next event.Emitter, cfg LimitConfig) *Limiter {
	cfg = cfg.withDefaults()
	l := &Limiter{
		next:    next,
		cfg:     cfg,
		sources: make(map[string]*source),
		global:  newBucket(cfg.GlobalRate, cfg.GlobalBurst),
		done:    make(chan struct{}),
	}

	l.wg.Add(1)
	go l.run()
	return l
}

func (l *Limiter) Emit(e event.Event) {
	now := time.Now()

	pass, summary := l.admit(e, now)
	if summary != nil {
		// Emitted before the event it describes, so the log reads in the order
		// things happened: "4,812 of these were dropped", then the next
		// survivor.
		l.next.Emit(*summary)
	}
	if pass {
		l.next.Emit(e)
	}
}

// Close stops the background flusher after reporting whatever is still pending.
func (l *Limiter) Close() {
	close(l.done)
	l.wg.Wait()

	for _, s := range l.dueSummaries(time.Now(), true) {
		l.next.Emit(s)
	}
}

// run reports summaries for sources that have stopped sending. Without it, the
// last few thousand drops of a flood are only reported if the attacker comes
// back.
func (l *Limiter) run() {
	defer l.wg.Done()

	ticker := time.NewTicker(summaryCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-l.done:
			return
		case now := <-ticker.C:
			for _, s := range l.dueSummaries(now, false) {
				l.next.Emit(s)
			}
		}
	}
}

// dueSummaries collects and clears the summaries that have fallen due. Events
// are emitted by the caller, outside the lock.
func (l *Limiter) dueSummaries(now time.Time, force bool) []event.Event {
	l.mu.Lock()
	defer l.mu.Unlock()

	var out []event.Event
	for _, s := range l.sources {
		if s.droppedTotal == 0 {
			continue
		}
		if !force && now.Sub(s.lastSummary) < summaryInterval {
			continue
		}
		out = append(out, l.summaryEvent(s, now))
	}
	return out
}

// admit decides one event's fate and returns any summary that fell due.
func (l *Limiter) admit(e event.Event, now time.Time) (pass bool, summary *event.Event) {
	l.mu.Lock()
	defer l.mu.Unlock()

	src := l.sourceFor(e.SrcIP, now)
	src.lastSeen = now

	b := src.normal
	if event.IsHighValue(e.Kind) {
		b = src.highValue
	}

	switch {
	case !b.allow(now):
		l.record(src, e, now)
	case !l.global.allow(now):
		// The per-source budget was available but the sensor as a whole is over
		// its cap — a distributed scan. Charged to the source that happened to
		// arrive, which is the only one we can name.
		l.globalDropped++
		l.record(src, e, now)
	default:
		pass = true
	}

	if src.droppedTotal > 0 && now.Sub(src.lastSummary) >= summaryInterval {
		s := l.summaryEvent(src, now)
		summary = &s
	}
	return pass, summary
}

func (l *Limiter) record(src *source, e event.Event, now time.Time) {
	if src.droppedTotal == 0 {
		src.firstDrop = now
		if src.lastSummary.IsZero() {
			// The first summary falls due a full interval after the first drop,
			// not at the drop itself.
			src.lastSummary = now
		}
	}
	src.dropped[e.Kind]++
	src.droppedTotal++

	src.node, src.service = e.Node, e.Service
	src.srcPort, src.dstPort = e.SrcPort, e.DstPort
}

// summaryEvent reports what was suppressed, as an ordinary event so it travels
// through every sink and reaches the console with no special handling. The
// caller must hold the lock.
func (l *Limiter) summaryEvent(src *source, now time.Time) event.Event {
	kinds := make(map[string]any, len(src.dropped))
	for k, n := range src.dropped {
		kinds[k] = n
	}

	summary := event.Event{
		Time:    now.UTC(),
		Node:    src.node,
		Service: src.service,
		Kind:    "rate_limited",
		SrcIP:   src.ip,
		SrcPort: src.srcPort,
		DstPort: src.dstPort,
		Data: map[string]any{
			"dropped":  src.droppedTotal,
			"kinds":    kinds,
			"since":    src.firstDrop.UTC().Format(time.RFC3339),
			"duration": now.Sub(src.firstDrop).Round(time.Second).String(),
		},
	}

	src.dropped = map[string]int64{}
	src.droppedTotal = 0
	src.lastSummary = now
	return summary
}

// sourceFor returns the state for an address, evicting idle entries when the
// table has grown too large. The caller must hold the lock.
func (l *Limiter) sourceFor(ip string, now time.Time) *source {
	if s, ok := l.sources[ip]; ok {
		return s
	}

	if len(l.sources) >= maxTrackedSources {
		l.evictIdle(now)
	}

	s := &source{
		ip:        ip,
		normal:    newBucket(l.cfg.PerSourceRate, l.cfg.PerSourceBurst),
		highValue: newBucket(l.cfg.HighValueRate, l.cfg.HighValueBurst),
		dropped:   map[string]int64{},
	}
	l.sources[ip] = s
	return s
}

// evictIdle drops sources that have been quiet long enough to have a full
// bucket again. Sources with unreported drops are kept: their summary is still
// owed.
//
// Eviction is done in bulk rather than one entry at a time. A scan rotating
// source addresses hits this path on every single event, and reclaiming one
// slot per call would make each of those events cost a full pass over the
// table — an O(n) operation per packet is its own denial of service.
func (l *Limiter) evictIdle(now time.Time) {
	for ip, s := range l.sources {
		if s.droppedTotal == 0 && now.Sub(s.lastSeen) > idleEviction {
			delete(l.sources, ip)
		}
	}
	if len(l.sources) < maxTrackedSources {
		return
	}

	// Still full: the table is all live traffic. Drop the least recently seen
	// quarter, so the limiter degrades rather than growing without bound.
	type entry struct {
		ip   string
		seen time.Time
	}
	entries := make([]entry, 0, len(l.sources))
	for ip, s := range l.sources {
		entries = append(entries, entry{ip, s.lastSeen})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].seen.Before(entries[j].seen) })

	for _, e := range entries[:len(entries)/4] {
		delete(l.sources, e.ip)
	}
}

// Dropped reports how many events the sensor-wide cap discarded. Non-zero means
// the sensor is under load from more sources than any single limit can see.
func (l *Limiter) Dropped() int64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.globalDropped
}
