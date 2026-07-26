package bannersvc

import (
	"io"
	"strings"
	"testing"

	"github.com/willysnow/wisp/internal/service"
	"github.com/willysnow/wisp/internal/service/servicetest"
)

func start(t *testing.T, banner string) *servicetest.StreamHarness {
	return servicetest.StartStream(t, func(addr string) service.StreamService {
		return New("vnc", addr, banner)
	})
}

// TestBannerIsSentFirst: the catcher's only way to draw a client out is to
// speak first, the way the real service on that port would.
func TestBannerIsSentFirst(t *testing.T) {
	h := start(t, "RFB 003.008\n")

	conn := h.Dial()
	buf := make([]byte, 32)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read banner: %v", err)
	}
	if got := string(buf[:n]); got != "RFB 003.008\n" {
		t.Errorf("banner = %q, want the configured one", got)
	}
}

// TestProbeIsCaptured is the point of the module: what the client said first is
// often enough to identify the scanner even though no credential is taken.
func TestProbeIsCaptured(t *testing.T) {
	h := start(t, "")

	conn := h.Dial()
	if _, err := io.WriteString(conn, "RFB 003.003\n"); err != nil {
		t.Fatalf("write: %v", err)
	}

	ev := h.WaitFor(t, "probe")
	if ev.Service != "vnc" {
		t.Errorf("Service = %q, want the name the port is pretending to be", ev.Service)
	}
	if got := ev.Data["payload"]; got != "RFB 003.003." {
		t.Errorf("payload = %v, want the client's first bytes", got)
	}
	if ev.Data["bytes"] != 12 {
		t.Errorf("bytes = %v, want 12", ev.Data["bytes"])
	}
}

// TestSilentConnectionIsRecorded — a scan that opens a socket and says nothing
// is still the thing this port exists to notice.
func TestSilentConnectionIsRecorded(t *testing.T) {
	h := start(t, "")

	conn := h.Dial()
	conn.Close()

	ev := h.WaitFor(t, "connect")
	if ev.Data["emulation"] != "banner" {
		t.Errorf("emulation = %v, want the event to say this is only a catcher",
			ev.Data["emulation"])
	}
	if _, captured := ev.Data["payload"]; captured {
		t.Error("a payload was recorded for a client that sent nothing")
	}
}

// TestBinaryPayloadIsRendered: these ports carry binary protocols, and raw
// bytes in the JSONL output would corrupt the file every downstream tool reads.
func TestBinaryPayloadIsRendered(t *testing.T) {
	h := start(t, "")

	conn := h.Dial()
	if _, err := conn.Write([]byte{0x00, 0x1b, 0xff, 'A', 0x0a, 0x7f}); err != nil {
		t.Fatalf("write: %v", err)
	}

	ev := h.WaitFor(t, "probe")
	payload, _ := ev.Data["payload"].(string)

	if payload != "...A.." {
		t.Errorf("payload = %q, want control and high bytes shown as dots", payload)
	}
	for _, r := range payload {
		if r > 126 || (r < 32 && r != ' ') {
			t.Fatalf("payload %q still contains a raw control byte", payload)
		}
	}
}

// TestOversizePayloadIsBounded: the read is capped, so a client that sends a
// gigabyte cannot make the sensor hold it.
func TestOversizePayloadIsBounded(t *testing.T) {
	h := start(t, "")

	conn := h.Dial()
	if _, err := io.WriteString(conn, strings.Repeat("A", maxCapture*4)); err != nil {
		// A short write is fine here: the service stops reading after
		// maxCapture and closes, which is exactly the behaviour under test.
		t.Logf("write ended early, as expected: %v", err)
	}

	ev := h.WaitFor(t, "probe")
	payload, _ := ev.Data["payload"].(string)
	if len(payload) > maxCapture {
		t.Errorf("captured %d bytes, want at most %d", len(payload), maxCapture)
	}
}
