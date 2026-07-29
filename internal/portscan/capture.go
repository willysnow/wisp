package portscan

import (
	"encoding/binary"
	"net"
)

// This file is the cross-platform half of the packet feeder: parsing and
// classification, with no syscalls. It compiles and is tested on every OS. The
// Linux-only socket that drives it lives in capture_linux.go; everywhere else
// capture_other.go stubs it out. Keeping the fragile logic — header parsing and
// scan-type classification — here, and only the raw socket there, bounds the
// Linux-only surface to a few dozen lines and makes the rest testable anywhere.

// servedPorts is the set of ports a listener already handles, split by
// transport. The packet feeder ignores probes to these: a connection to an open
// port is the event feeder's job, and the packet feeder's whole value is the
// closed ports no listener can see.
type servedPorts struct {
	tcp map[int]bool
	udp map[int]bool
}

// IP protocol numbers.
const (
	protoTCP = 6
	protoUDP = 17
)

// TCP control-flag bits.
const (
	flagFIN = 0x01
	flagSYN = 0x02
	flagRST = 0x04
	flagPSH = 0x08
	flagACK = 0x10
	flagURG = 0x20
)

// observePacket feeds one raw probe — always to a closed port — into the shared
// tracker. It is the packet feeder's entry point into the same correlation the
// event feeder uses.
func (d *Detector) observePacket(srcIP string, port int, scanType string) {
	if srcIP == "" || port == 0 || d.ignore[srcIP] {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.record(srcIP, 0, port, "", scanType, d.now())
}

// handlePacket parses one captured IPv4 packet and, if it is a probe to a port
// no listener serves, records it with its scan type. A packet to a served port
// is left to that listener (and the event feeder) so the two halves never
// double-count.
func (d *Detector) handlePacket(pkt []byte, served servedPorts) {
	ip, ok := parseIPv4(pkt)
	if !ok {
		return
	}
	switch ip.proto {
	case protoTCP:
		hdr, ok := parseTCP(ip.payload)
		if !ok || served.tcp[hdr.dstPort] {
			return
		}
		scan := classifyTCP(hdr.flags)
		if scan == "" {
			return
		}
		d.observePacket(ip.src, hdr.dstPort, scan)
	case protoUDP:
		port, ok := parseUDPDst(ip.payload)
		if !ok || served.udp[port] {
			return
		}
		d.observePacket(ip.src, port, "udp")
	}
}

// classifyTCP names the scan a TCP packet to a closed port represents. Because
// the caller has already excluded served ports, anything that reaches here is a
// probe to a port with nothing behind it — there is no benign reason to send it.
//
// A packet carrying RST is the exception: a stray reset to a closed port is
// noise, not a probe, so it is dropped.
func classifyTCP(flags byte) string {
	switch {
	case flags&flagRST != 0:
		return ""
	case flags&flagSYN != 0 && flags&flagACK == 0:
		return "syn"
	case flags == 0:
		return "null"
	case flags == flagFIN:
		return "fin"
	case flags == flagFIN|flagPSH|flagURG:
		return "xmas"
	case flags == flagFIN|flagACK:
		return "maimon"
	case flags == flagACK:
		return "ack"
	case flags&flagSYN != 0 && flags&flagACK != 0:
		return "synack"
	default:
		return "flags"
	}
}

type ipHeader struct {
	proto   byte
	src     string
	payload []byte
}

// parseIPv4 reads the fields the feeder needs from an IPv4 packet. Everything
// comes off the wire, so a short or non-IPv4 buffer yields ok=false.
func parseIPv4(pkt []byte) (ipHeader, bool) {
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
		return ipHeader{}, false
	}
	ihl := int(pkt[0]&0x0f) * 4
	if ihl < 20 || len(pkt) < ihl {
		return ipHeader{}, false
	}
	return ipHeader{
		proto:   pkt[9],
		src:     net.IP(pkt[12:16]).String(),
		payload: pkt[ihl:],
	}, true
}

type tcpHeader struct {
	dstPort int
	flags   byte
}

func parseTCP(p []byte) (tcpHeader, bool) {
	if len(p) < 14 {
		return tcpHeader{}, false
	}
	return tcpHeader{
		dstPort: int(binary.BigEndian.Uint16(p[2:4])),
		flags:   p[13],
	}, true
}

func parseUDPDst(p []byte) (int, bool) {
	if len(p) < 8 {
		return 0, false
	}
	return int(binary.BigEndian.Uint16(p[2:4])), true
}
