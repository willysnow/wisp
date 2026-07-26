// Package syslog writes messages to a syslog collector.
//
// The standard library's log/syslog is not usable here: it is Unix-only, and
// wisp builds for every platform Go targets. It is also frozen, so the RFC5424
// format every modern collector prefers is not available from it at all.
//
// This is deliberately a transport, not a policy. It knows how to frame and
// deliver a line; what goes in the line is decided by the sensor's sink and the
// console's notifier, which have different opinions about what is worth saying.
package syslog

import (
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/willysnow/wisp/internal/tlsutil"
)

// Severity is the syslog level of one message (RFC5424 §6.2.1).
type Severity int

const (
	SeverityAlert   Severity = 1
	SeverityCrit    Severity = 2
	SeverityErr     Severity = 3
	SeverityWarning Severity = 4
	SeverityNotice  Severity = 5
	SeverityInfo    Severity = 6
)

// Facilities that make sense for an application. local0-7 are the ones a
// collector's rules are usually written against.
var facilities = map[string]int{
	"kern": 0, "user": 1, "mail": 2, "daemon": 3, "auth": 4, "syslog": 5,
	"lpr": 6, "news": 7, "uucp": 8, "cron": 9, "authpriv": 10, "ftp": 11,
	"local0": 16, "local1": 17, "local2": 18, "local3": 19,
	"local4": 20, "local5": 21, "local6": 22, "local7": 23,
}

// Defaults. 514 is syslog's assigned port; local0 is the conventional place
// for an application that is not one of the named facilities.
const (
	DefaultNetwork   = "udp"
	DefaultFacility  = "local0"
	DefaultTag       = "wisp"
	DefaultFormat    = FormatRFC5424
	DefaultMaxLength = 8192
)

// Message formats.
const (
	// FormatRFC5424 is the modern format, with a full timestamp and a
	// structured header. Prefer it: RFC3164 has no year and second-level
	// precision, which makes correlating an intrusion harder than it needs to
	// be.
	FormatRFC5424 = "rfc5424"
	// FormatRFC3164 is the old BSD format, for collectors and appliances that
	// only accept that.
	FormatRFC3164 = "rfc3164"
)

// Stream framing (RFC6587). Datagram transports need none.
const (
	// FramingAuto uses octet counting over TLS, where RFC5425 requires it, and
	// newlines elsewhere, which every collector accepts.
	FramingAuto = "auto"
	// FramingNewline terminates each message with a newline.
	FramingNewline = "newline"
	// FramingOctet prefixes each message with its length.
	FramingOctet = "octet"
)

// Config is one syslog destination. It carries YAML tags because both the
// sensor and the console configure a destination the same way, and two
// divergent spellings of the same settings would be a support problem.
type Config struct {
	Enabled bool `yaml:"enabled"`

	// Address is host:port, or a path for the unix networks.
	Address string `yaml:"address"`

	// Network is udp, tcp, tcp+tls, unix, or unixgram. UDP is the default
	// because it is what a syslog collector always accepts and it cannot block
	// the sender; use tcp+tls when the events cross a network you do not own,
	// since they contain captured credentials.
	Network string `yaml:"network"`

	Facility string `yaml:"facility"`

	// Tag is the APP-NAME. It is what a collector's rules match on.
	Tag string `yaml:"tag"`

	Format  string `yaml:"format"`
	Framing string `yaml:"framing"`

	// MaxLength truncates a message before sending. Collectors silently cut
	// long lines, and a half a JSON object is worse than a short one.
	MaxLength int `yaml:"max_length"`

	// TLS trust for tcp+tls, with the same meaning as the console connection's.
	CAFile             string `yaml:"ca_file"`
	Fingerprint        string `yaml:"fingerprint"`
	InsecureSkipVerify bool   `yaml:"insecure_skip_verify"`
}

// withDefaults fills in what was not set. A blank field means "unset", never
// "off": a config typo must not silently stop the sensor from reporting.
func (c Config) withDefaults() Config {
	if c.Network == "" {
		c.Network = DefaultNetwork
	}
	if c.Facility == "" {
		c.Facility = DefaultFacility
	}
	if c.Tag == "" {
		c.Tag = DefaultTag
	}
	if c.Format == "" {
		c.Format = DefaultFormat
	}
	if c.Framing == "" {
		c.Framing = FramingAuto
	}
	if c.MaxLength <= 0 {
		c.MaxLength = DefaultMaxLength
	}
	return c
}

// Validate checks a destination before anything tries to use it.
func (c Config) Validate() error {
	c = c.withDefaults()

	if c.Address == "" {
		return fmt.Errorf("syslog: address is required")
	}
	switch c.Network {
	case "udp", "udp4", "udp6", "tcp", "tcp4", "tcp6", "tcp+tls", "unix", "unixgram":
	default:
		return fmt.Errorf("syslog: unknown network %q", c.Network)
	}
	if _, ok := facilities[c.Facility]; !ok {
		return fmt.Errorf("syslog: unknown facility %q", c.Facility)
	}
	switch c.Format {
	case FormatRFC5424, FormatRFC3164:
	default:
		return fmt.Errorf("syslog: unknown format %q", c.Format)
	}
	switch c.Framing {
	case FramingAuto, FramingNewline, FramingOctet:
	default:
		return fmt.Errorf("syslog: unknown framing %q", c.Framing)
	}
	if c.MaxLength < 480 {
		// RFC5424's floor for what a receiver must accept. Below it, messages
		// are being cut for no reason.
		return fmt.Errorf("syslog: max_length %d is below the 480-byte minimum", c.MaxLength)
	}
	return nil
}

// Timeouts for reaching a collector. Both are generous for a local network and
// short enough that a dead collector costs telemetry rather than a wedged
// goroutine.
const (
	dialTimeout  = 10 * time.Second
	writeTimeout = 5 * time.Second
)

// Writer delivers messages to one collector.
//
// It reconnects on demand rather than holding a connection open and hoping:
// a syslog collector restarting is ordinary, and a sensor that stops reporting
// because its log destination bounced would be worse than useless.
type Writer struct {
	cfg      Config
	facility int
	hostname string

	mu   sync.Mutex
	conn net.Conn
}

// New builds a Writer. It does not connect — the first message does, so a
// collector that is not up yet does not stop the sensor from starting.
func New(cfg Config) (*Writer, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	cfg = cfg.withDefaults()

	host, _ := os.Hostname()
	if host == "" {
		host = "-"
	}

	return &Writer{
		cfg:      cfg,
		facility: facilities[cfg.Facility],
		hostname: sanitiseField(host),
	}, nil
}

// Write sends one message. hostname may be empty, in which case this machine's
// name is used; msgID names the kind of thing being reported.
func (w *Writer) Write(sev Severity, at time.Time, hostname, msgID, msg string) error {
	line := w.format(sev, at, hostname, msgID, msg)

	w.mu.Lock()
	defer w.mu.Unlock()

	if err := w.send(line); err == nil {
		return nil
	}

	// One retry on a fresh connection. A collector that was restarted between
	// two events is the common case, and it should cost one event at most —
	// not every event until someone notices.
	w.closeLocked()
	return w.send(line)
}

func (w *Writer) send(line string) error {
	conn, err := w.connect()
	if err != nil {
		return err
	}

	framed := line
	if w.streaming() {
		if w.framing() == FramingOctet {
			framed = fmt.Sprintf("%d %s", len(line), line)
		} else {
			framed += "\n"
		}
	}

	// A deadline on every write, because a collector that accepts connections
	// and then stops reading — a stalled rsyslog, a full disk at the other end
	// — would otherwise block this goroutine forever once the socket buffer
	// filled. The sensor would go on running with its syslog output wedged,
	// and shutdown would never complete.
	_ = conn.SetWriteDeadline(time.Now().Add(writeTimeout))

	if _, err := conn.Write([]byte(framed)); err != nil {
		w.closeLocked()
		return err
	}
	return nil
}

func (w *Writer) connect() (net.Conn, error) {
	if w.conn != nil {
		return w.conn, nil
	}

	var (
		conn net.Conn
		err  error
	)

	if w.cfg.Network == "tcp+tls" {
		tlsCfg, cfgErr := tlsutil.ClientConfig(w.cfg.CAFile, w.cfg.Fingerprint, w.cfg.InsecureSkipVerify)
		if cfgErr != nil {
			return nil, cfgErr
		}
		conn, err = tls.DialWithDialer(&net.Dialer{Timeout: dialTimeout}, "tcp", w.cfg.Address, tlsCfg)
	} else {
		conn, err = net.DialTimeout(w.cfg.Network, w.cfg.Address, dialTimeout)
	}
	if err != nil {
		return nil, err
	}

	w.conn = conn
	return conn, nil
}

// Close releases the connection.
func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.closeLocked()
}

func (w *Writer) closeLocked() error {
	if w.conn == nil {
		return nil
	}
	err := w.conn.Close()
	w.conn = nil
	return err
}

func (w *Writer) streaming() bool {
	return strings.HasPrefix(w.cfg.Network, "tcp") || w.cfg.Network == "unix"
}

func (w *Writer) framing() string {
	if w.cfg.Framing != FramingAuto {
		return w.cfg.Framing
	}
	// RFC5425 requires octet counting over TLS; everywhere else a newline is
	// what collectors expect by default.
	if w.cfg.Network == "tcp+tls" {
		return FramingOctet
	}
	return FramingNewline
}

// format assembles the wire line, truncated to the configured length.
func (w *Writer) format(sev Severity, at time.Time, hostname, msgID, msg string) string {
	priority := w.facility*8 + int(sev)

	host := sanitiseField(hostname)
	if host == "" {
		host = w.hostname
	}

	var head string
	if w.cfg.Format == FormatRFC3164 {
		// BSD format: no year, no structured data, and the tag carries the
		// application name.
		head = fmt.Sprintf("<%d>%s %s %s: ",
			priority, at.Format("Jan _2 15:04:05"), host, sanitiseField(w.cfg.Tag))
	} else {
		id := sanitiseField(msgID)
		if id == "" {
			id = "-"
		}
		// Structured data is the nilvalue: without a registered enterprise
		// number any SD-ID we invented would be non-conformant, and the
		// message body is JSON, which every collector can parse anyway.
		head = fmt.Sprintf("<%d>1 %s %s %s %d %s - ",
			priority, at.UTC().Format(time.RFC3339), host,
			sanitiseField(w.cfg.Tag), os.Getpid(), id)
	}

	line := head + strings.Map(stripControl, msg)
	if len(line) > w.cfg.MaxLength {
		line = line[:w.cfg.MaxLength]
	}
	return line
}

// sanitiseField keeps a header field to the printable ASCII the format allows.
// These values come from event data, which comes from attackers: a space or a
// newline in a header would let one forge a second message inside the first.
func sanitiseField(s string) string {
	out := strings.Map(func(r rune) rune {
		if r <= 0x20 || r >= 0x7f {
			return -1
		}
		return r
	}, s)

	const maxField = 48 // RFC5424's limit for APP-NAME and MSGID
	if len(out) > maxField {
		out = out[:maxField]
	}
	return out
}

// stripControl removes the characters that would end a message early or start
// a forged one.
func stripControl(r rune) rune {
	if r == '\n' || r == '\r' || r == 0 {
		return -1
	}
	return r
}
