package notify

import (
	"context"
	"encoding/json"

	"github.com/willysnow/wisp/internal/event"
	"github.com/willysnow/wisp/internal/syslog"
)

// Syslog forwards alerts to a syslog collector.
//
// The sensor can write syslog itself, and for a single sensor that is the
// simpler path. This exists for the fleet: what arrives here has already been
// deduplicated and filtered to the kinds worth acting on, so a SIEM receives
// the alerts an operator would have been paged for rather than every packet
// anyone sent at a honeypot.
type Syslog struct {
	name   string
	writer *syslog.Writer
}

func NewSyslog(name string, cfg syslog.Config) (*Syslog, error) {
	w, err := syslog.New(cfg)
	if err != nil {
		return nil, err
	}
	if name == "" {
		name = "syslog"
	}
	return &Syslog{name: name, writer: w}, nil
}

func (s *Syslog) Name() string { return s.name }

func (s *Syslog) Send(_ context.Context, a Alert) error {
	body := map[string]any{
		"time":    a.Event.Time,
		"node":    a.Event.Node,
		"service": a.Event.Service,
		"kind":    a.Event.Kind,
		"src_ip":  a.Event.SrcIP,
		"data":    a.Event.Data,
	}
	if a.Event.SrcPort != 0 {
		body["src_port"] = a.Event.SrcPort
	}
	if a.Event.DstPort != 0 {
		body["dst_port"] = a.Event.DstPort
	}
	// How many identical alerts were folded into this one. Without it a
	// suppressed brute force looks like a single login attempt.
	if a.Repeated > 0 {
		body["repeated"] = a.Repeated
	}

	line, err := json.Marshal(body)
	if err != nil {
		return err
	}

	return s.writer.Write(severityFor(a.Event), a.Event.Time,
		a.Event.Node, a.Event.Kind, string(line))
}

// Close releases the connection.
func (s *Syslog) Close() error { return s.writer.Close() }

// severityFor mirrors the sensor's mapping, so the same event does not arrive
// at a collector with two different levels depending on which path it took.
func severityFor(e event.Event) syslog.Severity {
	if event.IsHighValue(e.Kind) {
		return syslog.SeverityWarning
	}
	return syslog.SeverityInfo
}
