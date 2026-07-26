// Package event defines the structured record every honeypot service emits.
//
// One event = one observed interaction. Services never decide whether something
// is "interesting" — on a honeypot every interaction is interesting by
// construction, so the filtering/dedup decision belongs upstream in the console.
package event

import (
	"net"
	"strconv"
	"time"
)

// Event is the single wire format for everything wisp observes.
type Event struct {
	Time    time.Time      `json:"time"`
	Node    string         `json:"node"`
	Service string         `json:"service"`
	Kind    string         `json:"kind"`
	SrcIP   string         `json:"src_ip"`
	SrcPort int            `json:"src_port"`
	DstPort int            `json:"dst_port"`
	Data    map[string]any `json:"data,omitempty"`
}

// HighValueKinds are the events worth protecting when something has to give: a
// credential was offered, or the intruder stated their intent in their own
// words. Everything else — bare connections, version probes, discovery calls —
// is context for the investigation rather than the trigger for one.
//
// The sensor's rate limiter gives these their own budget so a flood of
// connections cannot crowd out the one password that matters, and the console's
// notifier uses the same list to decide what is worth waking someone for.
var HighValueKinds = []string{
	// Credentials offered.
	"login_password",
	"login_pubkey",
	"login_form",
	"login_basic",
	"auth_attempt",

	// Intent stated in the attacker's own words.
	"prompt",
	"tool_call",
	"resource_read",
	"command",
	// The Elasticsearch query is this list's `prompt`: not "someone touched
	// the database" but "someone asked it for credit card numbers".
	"search_query",

	// Actions that are never accidental.
	"write_request",
	"delete_request",
	"monlist_probe",
	"model_write",
	"model_delete",
	// A container spec is a written-down plan. The interesting ones bind-mount
	// the host filesystem or ask for `Privileged`, and neither happens by
	// accident.
	"container_create",

	// Reaching for the instance metadata service is the cloud equivalent of
	// reading /etc/shadow: there is no benign reason for an unfamiliar process
	// to ask 169.254.169.254 for the role credentials, and the answer is
	// usually the last thing that happens before lateral movement.
	"credential_request",

	// An attacker already at work on the segment. Nothing legitimate answers a
	// name that does not exist, so an LLMNR reply is not a sign of an intrusion
	// to come — it is one in progress.
	"llmnr_poisoned",

	// Raised by the console, not a sensor: a sensor that has stopped reporting
	// looks the same as a quiet network, and one of those two is an emergency.
	"sensor_silent",
	"sensor_returned",
}

var highValueSet = func() map[string]bool {
	m := make(map[string]bool, len(HighValueKinds))
	for _, k := range HighValueKinds {
		m[k] = true
	}
	return m
}()

// IsHighValue reports whether a kind is one of HighValueKinds.
func IsHighValue(kind string) bool { return highValueSet[kind] }

// Emitter receives events. Implementations must be safe for concurrent use —
// every service handles connections in its own goroutine.
type Emitter interface {
	Emit(Event)
}

// EmitterFunc adapts a plain function to Emitter.
type EmitterFunc func(Event)

func (f EmitterFunc) Emit(e Event) { f(e) }

// New builds an event from a connection's remote and local addresses.
func New(service, kind string, remote, local net.Addr) Event {
	srcIP, srcPort := SplitAddr(remote)
	_, dstPort := SplitAddr(local)
	return NewRaw(service, kind, srcIP, srcPort, dstPort)
}

// NewRaw builds an event from already-split address parts. Used by the HTTP
// services, which see r.RemoteAddr rather than a net.Addr.
func NewRaw(service, kind, srcIP string, srcPort, dstPort int) Event {
	return Event{
		Time:    time.Now().UTC(),
		Service: service,
		Kind:    kind,
		SrcIP:   srcIP,
		SrcPort: srcPort,
		DstPort: dstPort,
		Data:    map[string]any{},
	}
}

// SplitAddr breaks a net.Addr into host and port. A malformed address yields
// the whole string as host and port 0 rather than an error — an event with a
// slightly odd source beats a dropped event.
func SplitAddr(a net.Addr) (string, int) {
	if a == nil {
		return "", 0
	}
	host, portStr, err := net.SplitHostPort(a.String())
	if err != nil {
		return a.String(), 0
	}
	port, _ := strconv.Atoi(portStr)
	return host, port
}

// SplitHostPortString is SplitAddr for a raw "host:port" string.
func SplitHostPortString(s string) (string, int) {
	host, portStr, err := net.SplitHostPort(s)
	if err != nil {
		return s, 0
	}
	port, _ := strconv.Atoi(portStr)
	return host, port
}
