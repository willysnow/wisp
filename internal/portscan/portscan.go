// Package portscan detects a host scan by correlation rather than packet
// capture: it watches the events every other decoy already emits and flags a
// source that touches many of the sensor's ports in a short window.
//
// This is the cross-platform, zero-dependency, zero-privilege half of portscan
// detection. It is not a listener — it binds nothing — but an event.Emitter
// that sits in the pipeline every decoy already reports through, learning which
// ports and services a source touched from the events themselves.
//
// What it sees is bounded by that: only the ports wisp actually binds, and only
// scans that complete a connection. A stealth SYN/NULL/FIN/XMAS scan to an
// unbound port never reaches a listener, so it is invisible here; catching those
// needs packet capture, which is a Linux-only, privileged addition layered on
// top. This module is what works everywhere and needs nothing, which is why it
// is the baseline. Its events say `method=connect` to stay honest about it.
package portscan

import (
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/willysnow/wisp/internal/event"
)

const (
	name = "portscan"
	kind = "portscan"
)

// maxSources bounds how many distinct source IPs are tracked at once, so a
// spoofed-source flood cannot grow the map without limit. The least-recently
// active source is evicted when the cap is reached.
const maxSources = 8192

// maxServices caps how many service names one portscan event lists.
const maxServices = 32

// Config tunes what counts as a scan.
type Config struct {
	// Threshold is how many distinct ports one source must touch, within Window,
	// to be a scan.
	Threshold int
	Window    time.Duration
	// Cooldown is the minimum gap between portscan events for one source, so a
	// sweep of a thousand ports is one event, not nine hundred.
	Cooldown time.Duration
	// Ignore lists source IPs never treated as scanners — monitoring, health
	// checks, loopback.
	Ignore []string
}

// Detector observes every event on its way to the sinks, then forwards it
// unchanged. It is meant to sit outside the rate limiter, so a flood of
// connections still feeds detection even when the sinks are shedding them.
type Detector struct {
	next   event.Emitter
	cfg    Config
	ignore map[string]bool
	now    func() time.Time

	mu      sync.Mutex
	sources map[string]*tracker
}

type tracker struct {
	ports    map[int]portHit
	first    time.Time // when the source was first seen this window
	last     time.Time // last activity, for eviction
	lastEmit time.Time
}

type portHit struct {
	seen time.Time
	// service is set when the port was reached by a completed connection (the
	// event feeder, D); scanType is set when a raw probe hit this — necessarily
	// closed — port (the packet feeder, A1, on Linux). A port may have both.
	service  string
	scanType string
}

// New wraps next with a detector. Zero or negative config values fall back to
// sensible defaults so a half-filled config still behaves.
func New(next event.Emitter, cfg Config) *Detector {
	if cfg.Threshold <= 0 {
		cfg.Threshold = 5
	}
	if cfg.Window <= 0 {
		cfg.Window = time.Minute
	}
	if cfg.Cooldown <= 0 {
		cfg.Cooldown = 5 * time.Minute
	}
	ignore := make(map[string]bool, len(cfg.Ignore))
	for _, s := range cfg.Ignore {
		ignore[s] = true
	}
	return &Detector{
		next:    next,
		cfg:     cfg,
		ignore:  ignore,
		now:     time.Now,
		sources: map[string]*tracker{},
	}
}

// Emit observes the event, then forwards it. A portscan event the detector
// itself produces goes straight to next, so it is never re-observed.
func (d *Detector) Emit(e event.Event) {
	d.observe(e)
	d.next.Emit(e)
}

func (d *Detector) observe(e event.Event) {
	// Skip the detector's own output, and anything without the source and port
	// the correlation is keyed on.
	if e.Kind == kind || e.SrcIP == "" || e.DstPort == 0 || d.ignore[e.SrcIP] {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.record(e.SrcIP, e.SrcPort, e.DstPort, e.Service, "", d.now())
}

// record folds one observation — a completed connection from the event feeder,
// or a raw probe from the packet feeder — into a source's window, and emits a
// portscan once the source crosses the threshold. The caller holds d.mu.
func (d *Detector) record(srcIP string, srcPort, port int, service, scanType string, now time.Time) {
	t := d.sources[srcIP]
	if t == nil {
		if len(d.sources) >= maxSources {
			d.evictOldest()
		}
		t = &tracker{ports: map[int]portHit{}, first: now}
		d.sources[srcIP] = t
	}
	h := t.ports[port]
	h.seen = now
	if service != "" {
		h.service = service
	}
	if scanType != "" {
		h.scanType = scanType
	}
	t.ports[port] = h
	t.last = now

	// Age out ports that have fallen outside the window.
	for p, ph := range t.ports {
		if now.Sub(ph.seen) > d.cfg.Window {
			delete(t.ports, p)
		}
	}
	if len(t.ports) == 0 {
		delete(d.sources, srcIP)
		return
	}

	if len(t.ports) >= d.cfg.Threshold &&
		(t.lastEmit.IsZero() || now.Sub(t.lastEmit) >= d.cfg.Cooldown) {
		t.lastEmit = now
		d.emitScan(srcIP, srcPort, port, t, now)
	}
}

func (d *Detector) emitScan(srcIP string, srcPort, lastPort int, t *tracker, now time.Time) {
	ev := event.NewRaw(name, kind, srcIP, srcPort, lastPort)
	ev.Data["ports"] = len(t.ports)
	ev.Data["window_seconds"] = int(d.cfg.Window.Seconds())
	ev.Data["duration_seconds"] = int(now.Sub(t.first).Seconds())

	services, scanTypes := summarize(t)
	if len(scanTypes) > 0 {
		// A raw probe reached a closed port — packet-level evidence the fan-out
		// feeder alone could never have produced.
		ev.Data["method"] = "packet"
		ev.Data["scan_types"] = strings.Join(scanTypes, ",")
	} else {
		// Only completed connections: the cross-platform baseline, and honest
		// about seeing no stealth scans.
		ev.Data["method"] = "connect"
	}
	if len(services) > 0 {
		ev.Data["services"] = strings.Join(services, ",")
	}
	d.next.Emit(ev)
}

// summarize returns the distinct, sorted service names and scan types across a
// source's in-window ports — the most legible summary of a sweep
// ("services=ssh,ftp,redis  scan_types=syn,xmas").
func summarize(t *tracker) (services, scanTypes []string) {
	svcSeen := map[string]bool{}
	scanSeen := map[string]bool{}
	for _, h := range t.ports {
		if h.service != "" && !svcSeen[h.service] {
			svcSeen[h.service] = true
			services = append(services, h.service)
		}
		if h.scanType != "" && !scanSeen[h.scanType] {
			scanSeen[h.scanType] = true
			scanTypes = append(scanTypes, h.scanType)
		}
	}
	sort.Strings(services)
	sort.Strings(scanTypes)
	if len(services) > maxServices {
		services = services[:maxServices]
	}
	if len(scanTypes) > maxServices {
		scanTypes = scanTypes[:maxServices]
	}
	return services, scanTypes
}

// evictOldest drops the least-recently-active source. Called only at the cap,
// which a normal deployment never reaches.
func (d *Detector) evictOldest() {
	var oldestKey string
	var oldest time.Time
	for k, t := range d.sources {
		if oldestKey == "" || t.last.Before(oldest) {
			oldestKey, oldest = k, t.last
		}
	}
	if oldestKey != "" {
		delete(d.sources, oldestKey)
	}
}
