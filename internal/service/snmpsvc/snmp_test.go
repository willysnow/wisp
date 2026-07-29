package snmpsvc

import (
	"strconv"
	"strings"
	"testing"

	"github.com/willysnow/wisp/internal/service"
	"github.com/willysnow/wisp/internal/service/servicetest"
)

func start(t *testing.T) *servicetest.PacketHarness {
	return servicetest.StartPacket(t, func(addr string) service.PacketService {
		return New(addr)
	})
}

// --- a tiny BER encoder, the mirror of ber.go, so the tests speak real SNMP ---

func enc(tag byte, content []byte) []byte {
	out := append([]byte{tag}, encodeLen(len(content))...)
	return append(out, content...)
}

func encodeLen(n int) []byte {
	if n < 0x80 {
		return []byte{byte(n)}
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte(n)}, b...)
		n >>= 8
	}
	return append([]byte{0x80 | byte(len(b))}, b...)
}

func intTLV(v int) []byte {
	if v == 0 {
		return enc(0x02, []byte{0})
	}
	var b []byte
	for v > 0 {
		b = append([]byte{byte(v)}, b...)
		v >>= 8
	}
	if b[0]&0x80 != 0 {
		b = append([]byte{0}, b...) // keep it positive
	}
	return enc(0x02, b)
}

func octetTLV(b []byte) []byte { return enc(0x04, b) }
func strTLV(s string) []byte   { return octetTLV([]byte(s)) }
func nullTLV() []byte          { return enc(0x05, nil) }
func seq(parts ...[]byte) []byte {
	return enc(0x30, concat(parts...))
}
func concat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func oidTLV(oid string) []byte {
	parts := strings.Split(oid, ".")
	nums := make([]int, len(parts))
	for i, p := range parts {
		nums[i], _ = strconv.Atoi(p)
	}
	out := []byte{byte(nums[0]*40 + nums[1])}
	for _, n := range nums[2:] {
		out = append(out, base128(n)...)
	}
	return enc(0x06, out)
}

func base128(n int) []byte {
	if n == 0 {
		return []byte{0}
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte(n & 0x7f)}, b...)
		n >>= 7
	}
	for i := 0; i < len(b)-1; i++ {
		b[i] |= 0x80
	}
	return b
}

// request builds a v1/v2c request: version, community, and a PDU with one OID.
func request(version int, community, oid string, pduTag byte) []byte {
	varbinds := seq(seq(oidTLV(oid), nullTLV()))
	pdu := enc(pduTag, concat(intTLV(0x2a), intTLV(0), intTLV(0), varbinds))
	return seq(intTLV(version), strTLV(community), pdu)
}

const (
	pduGet = 0xA0
	pduSet = 0xA3
)

func TestV2cCommunityCaptured(t *testing.T) {
	h := start(t)
	h.Send(request(versionV2c, "public", "1.3.6.1.2.1.1.1.0", pduGet))

	ev := h.WaitFor(t, "auth_attempt")
	if ev.Data["community"] != "public" {
		t.Errorf("community = %v, want public", ev.Data["community"])
	}
	if ev.Data["version"] != "v2c" {
		t.Errorf("version = %v, want v2c", ev.Data["version"])
	}
	if ev.Data["operation"] != "GetRequest" {
		t.Errorf("operation = %v, want GetRequest", ev.Data["operation"])
	}
	if oids, _ := ev.Data["oids"].(string); !strings.Contains(oids, "1.3.6.1.2.1.1.1.0") {
		t.Errorf("oids = %v, want the requested OID", ev.Data["oids"])
	}

	// The decoy must never answer SNMP — it would be an amplifier.
	if _, ok := h.Reply(); ok {
		t.Fatal("decoy answered an SNMP request; it must stay silent")
	}
}

func TestV1SetRequestCaptured(t *testing.T) {
	h := start(t)
	// A SET is an attempt to reconfigure the device — the OID is the intent.
	h.Send(request(versionV1, "private", "1.3.6.1.2.1.1.5.0", pduSet))

	ev := h.WaitFor(t, "auth_attempt")
	if ev.Data["community"] != "private" {
		t.Errorf("community = %v, want private", ev.Data["community"])
	}
	if ev.Data["version"] != "v1" {
		t.Errorf("version = %v, want v1", ev.Data["version"])
	}
	if ev.Data["operation"] != "SetRequest" {
		t.Errorf("operation = %v, want SetRequest", ev.Data["operation"])
	}
}

func TestV3UsernameCaptured(t *testing.T) {
	h := start(t)

	// msgFlags: auth (0x01) + reportable (0x04); no privacy.
	globalData := seq(intTLV(1), intTLV(65507), octetTLV([]byte{0x05}), intTLV(3))
	engineID := []byte{0x80, 0x00, 0x1f, 0x88, 0x80, 0xde, 0xad, 0xbe, 0xef}
	secInner := seq(
		octetTLV(engineID),
		intTLV(1),  // engineBoots
		intTLV(42), // engineTime
		strTLV("admin"),
		octetTLV(make([]byte, 12)), // auth parameters
		octetTLV(nil),              // privacy parameters
	)
	secParams := octetTLV(secInner)
	scopedPDU := octetTLV(nil) // opaque to the decoy
	msg := seq(intTLV(versionV3), globalData, secParams, scopedPDU)

	h.Send(msg)

	ev := h.WaitFor(t, "auth_attempt")
	if ev.Data["version"] != "v3" {
		t.Errorf("version = %v, want v3", ev.Data["version"])
	}
	if ev.Data["username"] != "admin" {
		t.Errorf("username = %v, want admin", ev.Data["username"])
	}
	if ev.Data["auth"] != true {
		t.Errorf("auth = %v, want true", ev.Data["auth"])
	}
	if ev.Data["priv"] != false {
		t.Errorf("priv = %v, want false", ev.Data["priv"])
	}
	if ev.Data["engine_id"] != "80001f8880deadbeef" {
		t.Errorf("engine_id = %v, want 80001f8880deadbeef", ev.Data["engine_id"])
	}
}

func TestNonSNMPIgnored(t *testing.T) {
	h := start(t)
	h.Send([]byte("not snmp at all"))
	if _, ok := h.Reply(); ok {
		t.Fatal("decoy answered a non-SNMP datagram")
	}
	h.Quiet(t, "auth_attempt")
}
