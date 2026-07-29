package portscan

import (
	"encoding/binary"
	"net"
	"testing"
	"time"
)

// ipv4TCP builds a raw IPv4+TCP packet as the capture loop would hand it to
// handlePacket (link layer already stripped).
func ipv4TCP(src string, dstPort int, flags byte) []byte {
	ip := make([]byte, 20)
	ip[0] = 0x45 // version 4, IHL 5
	ip[9] = protoTCP
	copy(ip[12:16], net.ParseIP(src).To4())

	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[2:4], uint16(dstPort))
	tcp[12] = 5 << 4 // data offset 5 words
	tcp[13] = flags
	return append(ip, tcp...)
}

func ipv4UDP(src string, dstPort int) []byte {
	ip := make([]byte, 20)
	ip[0] = 0x45
	ip[9] = protoUDP
	copy(ip[12:16], net.ParseIP(src).To4())

	udp := make([]byte, 8)
	binary.BigEndian.PutUint16(udp[2:4], uint16(dstPort))
	return append(ip, udp...)
}

func TestClassifyTCP(t *testing.T) {
	cases := map[byte]string{
		flagSYN:                     "syn",
		0:                           "null",
		flagFIN:                     "fin",
		flagFIN | flagPSH | flagURG: "xmas",
		flagFIN | flagACK:           "maimon",
		flagACK:                     "ack",
		flagSYN | flagACK:           "synack",
		flagPSH:                     "flags",
		flagRST:                     "", // stray reset — noise
		flagRST | flagACK:           "", // any reset is dropped
		flagSYN | flagRST:           "", // reset wins
	}
	for flags, want := range cases {
		if got := classifyTCP(flags); got != want {
			t.Errorf("classifyTCP(%#02x) = %q, want %q", flags, got, want)
		}
	}
}

func TestSynScanToClosedPorts(t *testing.T) {
	h := newHarness(t, Config{Threshold: 5, Window: time.Minute, Cooldown: 5 * time.Minute})
	served := servedPorts{tcp: map[int]bool{}, udp: map[int]bool{}}

	for _, port := range []int{1521, 3389, 8443, 9000, 50000} {
		h.d.handlePacket(ipv4TCP("10.0.0.9", port, flagSYN), served)
	}

	if got := h.c.count(kind); got != 1 {
		t.Fatalf("portscan events = %d, want 1", got)
	}
	ev, _ := h.c.last(kind)
	if ev.Data["method"] != "packet" {
		t.Errorf("method = %v, want packet", ev.Data["method"])
	}
	if ev.Data["scan_types"] != "syn" {
		t.Errorf("scan_types = %v, want syn", ev.Data["scan_types"])
	}
	if ev.Data["ports"] != 5 {
		t.Errorf("ports = %v, want 5", ev.Data["ports"])
	}
	// No completed connections were involved, so there is no services list.
	if _, ok := ev.Data["services"]; ok {
		t.Errorf("services present on a pure packet scan: %v", ev.Data["services"])
	}
}

func TestServedPortsAreLeftToTheListener(t *testing.T) {
	h := newHarness(t, Config{Threshold: 5, Window: time.Minute})
	served := servedPorts{tcp: map[int]bool{22: true, 80: true, 443: true}, udp: map[int]bool{}}

	// Six SYNs, all to ports a listener serves: the packet feeder ignores every
	// one, because the event feeder already sees those connections.
	for i := 0; i < 6; i++ {
		port := []int{22, 80, 443}[i%3]
		h.d.handlePacket(ipv4TCP("10.0.0.9", port, flagSYN), served)
	}
	if got := h.c.count(kind); got != 0 {
		t.Fatalf("portscan fired on served ports, want 0 (got %d)", got)
	}
}

func TestUDPScan(t *testing.T) {
	h := newHarness(t, Config{Threshold: 3, Window: time.Minute})
	served := servedPorts{tcp: map[int]bool{}, udp: map[int]bool{}}
	for _, port := range []int{53, 123, 500} {
		h.d.handlePacket(ipv4UDP("10.0.0.9", port), served)
	}
	ev, ok := h.c.last(kind)
	if !ok {
		t.Fatal("no portscan event for a UDP sweep")
	}
	if ev.Data["scan_types"] != "udp" {
		t.Errorf("scan_types = %v, want udp", ev.Data["scan_types"])
	}
}

func TestMixedConnectAndPacket(t *testing.T) {
	h := newHarness(t, Config{Threshold: 5, Window: time.Minute})
	served := servedPorts{tcp: map[int]bool{}, udp: map[int]bool{}}

	// Three completed connections (event feeder) and two stealth probes to
	// closed ports (packet feeder) from the same source.
	h.touch("10.0.0.9", 22, "ssh")
	h.touch("10.0.0.9", 21, "ftp")
	h.touch("10.0.0.9", 6379, "redis")
	h.d.handlePacket(ipv4TCP("10.0.0.9", 1521, flagFIN|flagPSH|flagURG), served) // xmas
	h.d.handlePacket(ipv4TCP("10.0.0.9", 3389, flagSYN), served)                 // syn

	ev, ok := h.c.last(kind)
	if !ok {
		t.Fatal("no portscan event for a mixed sweep")
	}
	if ev.Data["ports"] != 5 {
		t.Errorf("ports = %v, want 5", ev.Data["ports"])
	}
	// The presence of any raw probe makes this packet-level evidence...
	if ev.Data["method"] != "packet" {
		t.Errorf("method = %v, want packet", ev.Data["method"])
	}
	// ...and both signals are reported.
	if ev.Data["services"] != "ftp,redis,ssh" {
		t.Errorf("services = %v, want ftp,redis,ssh", ev.Data["services"])
	}
	if ev.Data["scan_types"] != "syn,xmas" {
		t.Errorf("scan_types = %v, want syn,xmas", ev.Data["scan_types"])
	}
}

func TestStrayResetAndGarbageIgnored(t *testing.T) {
	h := newHarness(t, Config{Threshold: 1, Window: time.Minute})
	served := servedPorts{tcp: map[int]bool{}, udp: map[int]bool{}}

	// A reset to a closed port is noise, not a probe.
	h.d.handlePacket(ipv4TCP("10.0.0.9", 4444, flagRST|flagACK), served)
	// Truncated and non-IPv4 buffers must not panic or count.
	h.d.handlePacket([]byte{0x45, 0x00}, served)
	h.d.handlePacket([]byte("not a packet"), served)

	if got := h.c.count(kind); got != 0 {
		t.Fatalf("portscan fired on noise, want 0 (got %d)", got)
	}
}
