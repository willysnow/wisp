package syslog

import (
	"bufio"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// collector stands in for rsyslog: it listens and remembers what arrived.
type collector struct {
	addr string

	mu    sync.Mutex
	lines []string
}

func newUDPCollector(t *testing.T) *collector {
	t.Helper()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { pc.Close() })

	c := &collector{addr: pc.LocalAddr().String()}
	go func() {
		buf := make([]byte, 65536)
		for {
			n, _, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			c.record(string(buf[:n]))
		}
	}()
	return c
}

func newTCPCollector(t *testing.T, octetFramed bool) *collector {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	c := &collector{addr: ln.Addr().String()}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				r := bufio.NewReader(conn)
				for {
					if octetFramed {
						line, err := readOctetFramed(r)
						if err != nil {
							return
						}
						c.record(line)
						continue
					}
					line, err := r.ReadString('\n')
					if err != nil {
						return
					}
					c.record(strings.TrimRight(line, "\n"))
				}
			}()
		}
	}()
	return c
}

// readOctetFramed reads RFC6587 "<length> <message>".
func readOctetFramed(r *bufio.Reader) (string, error) {
	prefix, err := r.ReadString(' ')
	if err != nil {
		return "", err
	}
	n, err := strconv.Atoi(strings.TrimSpace(prefix))
	if err != nil {
		return "", err
	}
	buf := make([]byte, n)
	if _, err := readFull(r, buf); err != nil {
		return "", err
	}
	return string(buf), nil
}

func readFull(r *bufio.Reader, buf []byte) (int, error) {
	read := 0
	for read < len(buf) {
		n, err := r.Read(buf[read:])
		read += n
		if err != nil {
			return read, err
		}
	}
	return read, nil
}

func (c *collector) record(line string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lines = append(c.lines, line)
}

func (c *collector) wait(t *testing.T, n int) []string {
	t.Helper()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		c.mu.Lock()
		got := len(c.lines)
		c.mu.Unlock()
		if got >= n {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.lines) < n {
		t.Fatalf("collector received %d messages, want %d", len(c.lines), n)
	}
	return append([]string(nil), c.lines...)
}

// TestRFC5424OverUDP is the default path, and the shape a collector's rules are
// written against.
func TestRFC5424OverUDP(t *testing.T) {
	c := newUDPCollector(t)

	w, err := New(Config{Address: c.addr, Facility: "local3", Tag: "wisp"})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	defer w.Close()

	at := time.Date(2026, 7, 25, 14, 22, 7, 0, time.UTC)
	if err := w.Write(SeverityWarning, at, "sensor-01", "login_password",
		`{"kind":"login_password","username":"root"}`); err != nil {
		t.Fatalf("write: %v", err)
	}

	line := c.wait(t, 1)[0]

	// local3 is facility 19, warning is severity 4: 19*8+4 = 156.
	if !strings.HasPrefix(line, "<156>1 ") {
		t.Errorf("line = %q, want priority 156 and version 1", line)
	}
	for _, want := range []string{
		"2026-07-25T14:22:07Z", // the timestamp, in a format that sorts
		"sensor-01",            // the sensor, not the machine running the console
		"wisp",                 // APP-NAME, which is what rules match on
		"login_password",       // MSGID
		`"username":"root"`,    // the event itself
	} {
		if !strings.Contains(line, want) {
			t.Errorf("line = %q, missing %q", line, want)
		}
	}
}

// TestSeverityIsInThePriority: a collector should be able to route on level
// without parsing the body.
func TestSeverityIsInThePriority(t *testing.T) {
	c := newUDPCollector(t)

	w, err := New(Config{Address: c.addr, Facility: "local0"})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	defer w.Close()

	now := time.Now()
	_ = w.Write(SeverityInfo, now, "n", "connection", "{}")
	_ = w.Write(SeverityWarning, now, "n", "login_password", "{}")

	lines := c.wait(t, 2)
	if !strings.HasPrefix(lines[0], "<134>") { // 16*8+6
		t.Errorf("informational line = %q, want <134>", lines[0])
	}
	if !strings.HasPrefix(lines[1], "<132>") { // 16*8+4
		t.Errorf("warning line = %q, want <132>", lines[1])
	}
}

// TestTCPNewlineFraming and its octet-counting sibling cover the two ways a
// stream collector expects messages to be delimited. Getting this wrong means
// every message after the first is glued to the one before it.
func TestTCPNewlineFraming(t *testing.T) {
	c := newTCPCollector(t, false)

	w, err := New(Config{Address: c.addr, Network: "tcp", Framing: FramingNewline})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	defer w.Close()

	for i := 0; i < 3; i++ {
		if err := w.Write(SeverityInfo, time.Now(), "n", "probe",
			fmt.Sprintf(`{"seq":%d}`, i)); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}

	lines := c.wait(t, 3)
	for i, line := range lines[:3] {
		if !strings.Contains(line, fmt.Sprintf(`{"seq":%d}`, i)) {
			t.Errorf("message %d = %q, want seq %d", i, line, i)
		}
	}
}

func TestTCPOctetFraming(t *testing.T) {
	c := newTCPCollector(t, true)

	w, err := New(Config{Address: c.addr, Network: "tcp", Framing: FramingOctet})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	defer w.Close()

	for i := 0; i < 3; i++ {
		if err := w.Write(SeverityInfo, time.Now(), "n", "probe",
			fmt.Sprintf(`{"seq":%d}`, i)); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}

	lines := c.wait(t, 3)
	for i, line := range lines[:3] {
		if strings.HasPrefix(line, " ") || !strings.HasPrefix(line, "<") {
			t.Errorf("message %d = %q, want the length prefix consumed", i, line)
		}
	}
}

// TestReconnects is the property that keeps a sensor reporting: a collector
// restarting is ordinary, and it must cost one message rather than every
// message from then on.
func TestReconnects(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()

	received := make(chan string, 10)
	serve := func(ln net.Listener) {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				r := bufio.NewReader(conn)
				for {
					line, err := r.ReadString('\n')
					if err != nil {
						return
					}
					received <- line
				}
			}()
		}
	}
	go serve(ln)

	w, err := New(Config{Address: addr, Network: "tcp"})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	defer w.Close()

	if err := w.Write(SeverityInfo, time.Now(), "n", "probe", `{"seq":1}`); err != nil {
		t.Fatalf("first write: %v", err)
	}
	<-received

	// The collector goes away and comes back on the same address.
	ln.Close()
	time.Sleep(50 * time.Millisecond)

	again, err := net.Listen("tcp", addr)
	if err != nil {
		t.Skipf("could not rebind %s: %v", addr, err)
	}
	defer again.Close()
	go serve(again)

	// The first write after the restart may land in the dead connection's
	// buffer; the retry is what has to work.
	_ = w.Write(SeverityInfo, time.Now(), "n", "probe", `{"seq":2}`)
	if err := w.Write(SeverityInfo, time.Now(), "n", "probe", `{"seq":3}`); err != nil {
		t.Fatalf("write after the collector restarted: %v", err)
	}

	select {
	case line := <-received:
		if !strings.Contains(line, `"seq":`) {
			t.Errorf("received %q after reconnect", line)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("nothing arrived after the collector restarted")
	}
}

// TestHeaderInjection is the one that matters for a honeypot.
//
// Every field here can be attacker-chosen: the node name comes from config, but
// the message ID is the event kind and the body carries a captured username.
// A newline in any of them would let whoever sent it forge a second syslog
// record — inventing an "authentication succeeded" line, or hiding their own.
func TestHeaderInjection(t *testing.T) {
	c := newUDPCollector(t)

	w, err := New(Config{Address: c.addr})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	defer w.Close()

	err = w.Write(SeverityInfo, time.Now(),
		"host\nname",
		"kind with spaces\r\n<134>1 forged",
		"body\nwith\nnewlines\r\n<134>1 also forged")
	if err != nil {
		t.Fatalf("write: %v", err)
	}

	line := c.wait(t, 1)[0]

	// The newline is the whole attack. Records are separated by a datagram
	// boundary, a newline, or an octet count — never by the text "<134>" — so a
	// priority marker surviving inside the body is inert, and stripping it
	// would corrupt evidence for nothing. A captured HTTP path or an XML
	// injection attempt is exactly the sort of thing that legitimately
	// contains angle brackets.
	if strings.ContainsAny(line, "\n\r\x00") {
		t.Errorf("line %q carries a newline — a second record can be forged", line)
	}
	if !strings.HasPrefix(line, "<134>1 ") {
		t.Errorf("line %q does not start with exactly one header", line)
	}

	// Header fields are space-delimited, so a space in one ends it early and
	// shifts everything after it into the wrong field.
	fields := strings.SplitN(line, " ", 7)
	if len(fields) < 7 {
		t.Fatalf("line %q has too few header fields", line)
	}
	if fields[2] != "hostname" {
		t.Errorf("HOSTNAME = %q, want the newline removed rather than the field split",
			fields[2])
	}
	if strings.Contains(fields[5], " ") {
		t.Errorf("MSGID = %q still contains a space", fields[5])
	}
}

// TestTruncation: collectors cut long lines themselves, and where they cut is
// not somewhere we chose.
func TestTruncation(t *testing.T) {
	c := newUDPCollector(t)

	w, err := New(Config{Address: c.addr, MaxLength: 512})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	defer w.Close()

	if err := w.Write(SeverityInfo, time.Now(), "n", "prompt",
		strings.Repeat("A", 4000)); err != nil {
		t.Fatalf("write: %v", err)
	}

	line := c.wait(t, 1)[0]
	if len(line) != 512 {
		t.Errorf("line is %d bytes, want it cut to 512", len(line))
	}
}

// TestRFC3164 covers the old format, for the appliances that only accept it.
func TestRFC3164(t *testing.T) {
	c := newUDPCollector(t)

	w, err := New(Config{Address: c.addr, Format: FormatRFC3164, Tag: "wisp"})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	defer w.Close()

	at := time.Date(2026, 7, 25, 14, 22, 7, 0, time.UTC)
	if err := w.Write(SeverityNotice, at, "sensor-01", "probe", "hello"); err != nil {
		t.Fatalf("write: %v", err)
	}

	line := c.wait(t, 1)[0]
	if !strings.HasPrefix(line, "<133>Jul 25 14:22:07 sensor-01 wisp: hello") {
		t.Errorf("line = %q, want the BSD shape", line)
	}
	if strings.Contains(line, "2026") {
		t.Error("RFC3164 has no year; something is writing an RFC5424 timestamp")
	}
}

// TestValidation stops a misconfigured destination at startup rather than
// discovering it during an intrusion.
func TestValidation(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  Config
		want string
	}{
		{"no address", Config{}, "address"},
		{"bad network", Config{Address: "x:514", Network: "carrier-pigeon"}, "network"},
		{"bad facility", Config{Address: "x:514", Facility: "nonsense"}, "facility"},
		{"bad format", Config{Address: "x:514", Format: "xml"}, "format"},
		{"bad framing", Config{Address: "x:514", Framing: "vibes"}, "framing"},
		{"tiny max length", Config{Address: "x:514", MaxLength: 10}, "480"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.Validate()
			if err == nil {
				t.Fatal("accepted an invalid destination")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not mention %q", err, tc.want)
			}
		})
	}

	if err := (Config{Address: "collector:514"}).Validate(); err != nil {
		t.Errorf("a minimal destination was rejected: %v", err)
	}
}
