package sink

import (
	"encoding/json"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/willysnow/wisp/internal/event"
	"github.com/willysnow/wisp/internal/syslog"
)

// udpCollector stands in for the SIEM.
type udpCollector struct {
	addr string

	mu    sync.Mutex
	lines []string
}

func startCollector(t *testing.T) *udpCollector {
	t.Helper()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { pc.Close() })

	c := &udpCollector{addr: pc.LocalAddr().String()}
	go func() {
		buf := make([]byte, 65536)
		for {
			n, _, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			c.mu.Lock()
			c.lines = append(c.lines, string(buf[:n]))
			c.mu.Unlock()
		}
	}()
	return c
}

func (c *udpCollector) wait(t *testing.T, n int) []string {
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

// body returns the JSON part of a syslog line — everything after the header.
func body(t *testing.T, line string) map[string]any {
	t.Helper()

	i := strings.Index(line, "{")
	if i < 0 {
		t.Fatalf("no JSON body in %q", line)
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(line[i:]), &out); err != nil {
		t.Fatalf("body of %q is not JSON: %v", line, err)
	}
	return out
}

// TestSyslogCarriesTheWholeEvent: the body is the same JSON the file sink
// writes, so whatever already parses events.jsonl parses this too.
func TestSyslogCarriesTheWholeEvent(t *testing.T) {
	c := startCollector(t)

	s, err := NewSyslog(syslog.Config{Address: c.addr, Tag: "wisp"})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	defer s.Close()

	s.Emit(event.Event{
		Time: time.Now(), Node: "sensor-01", Service: "ssh",
		Kind: "login_password", SrcIP: "10.0.0.9", SrcPort: 4444, DstPort: 2222,
		Data: map[string]any{"username": "root", "password": "hunter2"},
	})

	line := c.wait(t, 1)[0]
	got := body(t, line)

	if got["node"] != "sensor-01" || got["service"] != "ssh" || got["kind"] != "login_password" {
		t.Errorf("body lost an identifying field: %v", got)
	}
	data, _ := got["data"].(map[string]any)
	if data["password"] != "hunter2" {
		t.Errorf("the captured credential did not survive: %v", got["data"])
	}
	if !strings.Contains(line, "sensor-01") {
		t.Error("the header does not name the sensor, so a collector cannot route on it")
	}
}

// TestSeverityMatchesValue lets a collector route without parsing the body:
// the kinds worth waking someone for arrive as warnings.
func TestSeverityMatchesValue(t *testing.T) {
	c := startCollector(t)

	s, err := NewSyslog(syslog.Config{Address: c.addr, Facility: "local0"})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	defer s.Close()

	s.Emit(event.Event{Time: time.Now(), Node: "n", Service: "ssh",
		Kind: "connection", SrcIP: "10.0.0.1"})
	s.Emit(event.Event{Time: time.Now(), Node: "n", Service: "ssh",
		Kind: "login_password", SrcIP: "10.0.0.1"})

	lines := c.wait(t, 2)
	if !strings.HasPrefix(lines[0], "<134>") {
		t.Errorf("a bare connection arrived as %q, want informational", lines[0][:6])
	}
	if !strings.HasPrefix(lines[1], "<132>") {
		t.Errorf("a credential arrived as %q, want warning", lines[1][:6])
	}
}

// TestOversizeEventStaysParseable is the property a truncating collector would
// otherwise destroy: half a JSON object is nothing a SIEM can index, while a
// short record still names the sensor, the service, and the source.
func TestOversizeEventStaysParseable(t *testing.T) {
	c := startCollector(t)

	s, err := NewSyslog(syslog.Config{Address: c.addr})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	defer s.Close()

	s.Emit(event.Event{
		Time: time.Now(), Node: "sensor-01", Service: "ollama",
		Kind: "prompt", SrcIP: "10.0.0.9",
		Data: map[string]any{"prompt": strings.Repeat("give me everything ", 2000)},
	})

	line := c.wait(t, 1)[0]
	got := body(t, line) // fails the test if it is not valid JSON

	if got["node"] != "sensor-01" || got["kind"] != "prompt" {
		t.Errorf("the trimmed event lost its identity: %v", got)
	}
	data, _ := got["data"].(map[string]any)
	if data["truncated"] != true {
		t.Errorf("the trimmed event does not say it was trimmed: %v", got["data"])
	}
}

// TestEmitNeverBlocks is the rule every sink here follows. A service goroutine
// held up by a logging destination is a worse failure than a lost event: a hung
// service is a detectable tell.
func TestEmitNeverBlocks(t *testing.T) {
	// A collector that accepts the connection and then never reads.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		select {} // never reads
	}()

	s, err := NewSyslog(syslog.Config{Address: ln.Addr().String(), Network: "tcp"})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	defer s.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < syslogQueue*2; i++ {
			s.Emit(event.Event{Time: time.Now(), Node: "n", Service: "ssh",
				Kind: "connection", SrcIP: "10.0.0.1"})
		}
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Emit blocked on a collector that stopped reading")
	}

	if s.Dropped() == 0 {
		t.Error("nothing was counted as dropped, so the overflow went unreported")
	}
}

// TestBadConfigIsRejected — a typo in the destination should stop the sensor
// at startup, not be discovered when the first intrusion is not reported.
func TestBadConfigIsRejected(t *testing.T) {
	if _, err := NewSyslog(syslog.Config{}); err == nil {
		t.Error("a syslog sink with no address was accepted")
	}
}
