package sink

import (
	"encoding/json"
	"sync"
	"time"

	"github.com/willysnow/wisp/internal/event"
	"github.com/willysnow/wisp/internal/syslog"
)

// syslogQueue is how many events may be waiting for the collector. Beyond it,
// events are dropped and counted — the same bargain the console sink makes,
// and for the same reason: a service goroutine must never be held up by a
// logging destination. A hung sensor is a detectable tell; lost telemetry is
// merely bad.
const syslogQueue = 2048

// drainTimeout bounds how long shutdown waits for the collector to take what
// is queued.
const drainTimeout = 5 * time.Second

// Syslog delivers every event to a syslog collector.
//
// This is the integration point for anything that already reads syslog — a
// SIEM, a log shipper, a box that pages someone. The message body is the same
// JSON the sensor writes to events.jsonl, so whatever already parses that file
// parses this too.
type Syslog struct {
	writer *syslog.Writer

	queue chan event.Event
	done  chan struct{}
	wg    sync.WaitGroup

	mu      sync.Mutex
	dropped int64
}

// NewSyslog starts the delivery loop. Call Close to stop it.
func NewSyslog(cfg syslog.Config) (*Syslog, error) {
	w, err := syslog.New(cfg)
	if err != nil {
		return nil, err
	}

	s := &Syslog{
		writer: w,
		queue:  make(chan event.Event, syslogQueue),
		done:   make(chan struct{}),
	}
	s.wg.Add(1)
	go s.run()
	return s, nil
}

func (s *Syslog) Emit(e event.Event) {
	select {
	case s.queue <- e:
	default:
		s.mu.Lock()
		s.dropped++
		s.mu.Unlock()
	}
}

// Dropped reports how many events were discarded because the queue was full.
// Non-zero means the collector has been unreachable or too slow.
func (s *Syslog) Dropped() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.dropped
}

// Close drains what is queued and releases the connection.
func (s *Syslog) Close() error {
	close(s.done)
	s.wg.Wait()
	return s.writer.Close()
}

func (s *Syslog) run() {
	defer s.wg.Done()

	for {
		select {
		case e := <-s.queue:
			s.write(e)

		case <-s.done:
			s.drain()
			return
		}
	}
}

// drain flushes what is queued on shutdown, but not at any price.
//
// Each write to an unreachable collector costs a connection timeout, and a
// full queue would take hours to work through — so a stalled collector must
// not be able to hold shutdown open. The first failure ends the drain, since
// the next event is going to the same place.
func (s *Syslog) drain() {
	deadline := time.Now().Add(drainTimeout)

	for {
		select {
		case e := <-s.queue:
			if !s.write(e) || time.Now().After(deadline) {
				s.dropRemaining()
				return
			}
		default:
			return
		}
	}
}

func (s *Syslog) dropRemaining() {
	for {
		select {
		case <-s.queue:
			s.mu.Lock()
			s.dropped++
			s.mu.Unlock()
		default:
			return
		}
	}
}

// write reports whether the event reached the collector.
//
// A failure is counted, not retried here: the writer already reconnects once
// per message, and a collector that is down should cost telemetry rather than
// back-pressure.
func (s *Syslog) write(e event.Event) bool {
	if err := s.writer.Write(severityFor(e), e.Time, e.Node, e.Kind, message(e)); err != nil {
		s.mu.Lock()
		s.dropped++
		s.mu.Unlock()
		return false
	}
	return true
}

// severityFor maps an event to a syslog level, so a collector's existing rules
// can act on wisp without knowing anything about it.
//
// The high-value kinds — a credential offered, intent stated — are warnings;
// everything else is informational. Nothing is sent above warning: an
// intrusion attempt on a honeypot is expected by design, and a sensor that
// cried "critical" at every port scan would be filtered out within a week.
func severityFor(e event.Event) syslog.Severity {
	if event.IsHighValue(e.Kind) {
		return syslog.SeverityWarning
	}
	return syslog.SeverityInfo
}

// message renders the event as the same JSON line the file sink writes.
//
// If it does not fit, the data map is trimmed rather than the line being cut:
// a collector receiving half a JSON object gets nothing it can parse, while a
// short one still names the sensor, the service, and the source.
func message(e event.Event) string {
	full, err := json.Marshal(e)
	if err != nil {
		return ""
	}
	if len(full) <= syslogSoftLimit {
		return string(full)
	}

	// Drop the detail, keep the fact. The full event is still in events.jsonl
	// and at the console; this line's job is to reach the collector intact.
	trimmed := e
	trimmed.Data = map[string]any{
		"truncated": true,
		"note":      "event too large for syslog; see events.jsonl or the console",
	}
	short, err := json.Marshal(trimmed)
	if err != nil {
		return ""
	}
	return string(short)
}

// syslogSoftLimit is the body size beyond which the data map is dropped. It
// leaves room under the default 8192-byte line for the header.
const syslogSoftLimit = 7000
