package tftpsvc

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/willysnow/wisp/internal/event"
	"github.com/willysnow/wisp/internal/service"
	"github.com/willysnow/wisp/internal/service/servicetest"
)

func start(t *testing.T) *servicetest.PacketHarness {
	return servicetest.StartPacket(t, func(addr string) service.PacketService {
		return New(addr)
	})
}

// request builds an RRQ or WRQ packet the way a real client does.
func request(opcode uint16, filename, mode string) []byte {
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, opcode)
	buf = append(buf, filename...)
	buf = append(buf, 0)
	buf = append(buf, mode...)
	buf = append(buf, 0)
	return buf
}

// TestReadRequestCapturesFilename is the whole signal TFTP offers. There is no
// authentication to capture, so what they asked for is the intelligence: a
// client asking for a router config has told you what it thinks this box is.
func TestReadRequestCapturesFilename(t *testing.T) {
	h := start(t)
	h.Send(request(opRRQ, "/etc/passwd", "octet"))

	ev := h.WaitFor(t, "request")
	if ev.Data["filename"] != "/etc/passwd" {
		t.Errorf("filename = %v, want /etc/passwd", ev.Data["filename"])
	}
	if ev.Data["operation"] != "read" {
		t.Errorf("operation = %v, want read", ev.Data["operation"])
	}
	if ev.Data["mode"] != "octet" {
		t.Errorf("mode = %v, want octet", ev.Data["mode"])
	}
}

// TestWriteRequestIsHigherValue: a write is strictly worse than a read.
// Something is trying to plant a file, not just take one, and the alert has to
// say so — write_request is on the list that wakes someone.
func TestWriteRequestIsHigherValue(t *testing.T) {
	h := start(t)
	h.Send(request(opWRQ, "startup-config", "octet"))

	ev := h.WaitFor(t, "write_request")
	if ev.Data["operation"] != "write" {
		t.Errorf("operation = %v, want write", ev.Data["operation"])
	}
	if !event.IsHighValue(ev.Kind) {
		t.Error("a write attempt is not treated as high value, so a flood could bury it")
	}
}

// TestNothingIsEverServed is the rule.
//
// Serving a file would make this an open file server on someone's network;
// accepting a write would make it a malware drop. Both answers are errors, and
// they are the errors a real tftpd gives.
func TestNothingIsEverServed(t *testing.T) {
	h := start(t)

	for _, tc := range []struct {
		name   string
		packet []byte
		code   uint16
	}{
		{"read is refused", request(opRRQ, "boot.img", "octet"), errFileNotFound},
		{"write is refused", request(opWRQ, "evil.bin", "octet"), errAccessViolation},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h.Send(tc.packet)

			reply, ok := h.Reply()
			if !ok {
				t.Fatal("no reply; a real tftpd always answers")
			}
			if len(reply) < 4 {
				t.Fatalf("reply is %d bytes, too short to be an ERROR packet", len(reply))
			}
			if op := binary.BigEndian.Uint16(reply[:2]); op != opError {
				t.Fatalf("opcode = %d, want ERROR (%d) — something was served", op, opError)
			}
			if code := binary.BigEndian.Uint16(reply[2:4]); code != tc.code {
				t.Errorf("error code = %d, want %d", code, tc.code)
			}
		})
	}
}

// TestMalformedRequestsAreRecordedNotDropped: a packet the parser cannot make
// sense of is still a recorded interaction, and must not take the listener down.
func TestMalformedRequestsAreRecordedNotDropped(t *testing.T) {
	for _, tc := range []struct {
		name   string
		packet []byte
	}{
		{"empty", nil},
		{"too short", []byte{0, 1}},
		{"unknown opcode", request(99, "x", "octet")},
		{"no terminators", []byte{0, 1, 'f', 'o', 'o'}},
		{"nul only", []byte{0, 1, 0}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := start(t)
			h.Send(tc.packet)

			// Which kind it lands as depends on how far the parser got, and
			// that is the service's business rather than the test's. What
			// matters is that something was recorded — silence would mean an
			// attacker could probe this port without leaving a trace by
			// sending a packet the parser dislikes.
			waitForAny(t, h)

			// And the listener is still up. One bad datagram must not end it.
			before := len(h.Events())
			h.Send(request(opRRQ, "after.txt", "octet"))
			waitForMore(t, h, before)
		})
	}
}

func waitForAny(t *testing.T, h *servicetest.PacketHarness) {
	t.Helper()
	waitForMore(t, h, 0)
}

func waitForMore(t *testing.T, h *servicetest.PacketHarness, than int) {
	t.Helper()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if len(h.Events()) > than {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("no event beyond the %d already seen — the datagram vanished", than)
}

// TestFilenameIsRendered: filenames come from whoever sent the packet, and raw
// bytes would corrupt the JSONL line every downstream tool reads.
func TestFilenameIsRendered(t *testing.T) {
	h := start(t)

	packet := []byte{0, opRRQ}
	packet = append(packet, "bad"...)
	packet = append(packet, 0x00) // terminator
	packet = append(packet, "octet"...)
	packet = append(packet, 0)
	// Re-splice a control byte into the filename.
	packet = append([]byte{0, opRRQ, 'e', 0x1b, '[', '3', '1', 'm', 0}, "octet\x00"...)

	h.Send(packet)

	ev := h.WaitFor(t, "request")
	filename, _ := ev.Data["filename"].(string)
	for _, r := range filename {
		if r < 0x20 || r > 0x7e {
			t.Fatalf("filename %q still contains a raw control byte", filename)
		}
	}
}
