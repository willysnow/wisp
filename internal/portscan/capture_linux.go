//go:build linux

package portscan

import (
	"context"

	"golang.org/x/sys/unix"
)

// StartCapture opens a pure-Go AF_PACKET socket and drives the packet feeder,
// giving the detector the closed-port probes a listener can never see: stealth
// SYN/NULL/FIN/XMAS scans and UDP sweeps.
//
// It needs CAP_NET_RAW. If the socket cannot be opened — no capability, a
// container without NET_RAW — it says so once and returns; the fan-out feeder
// keeps working, so wisp never fails to start over this. The socket only reads,
// never writes: it is a passive sniffer, which is why it is acceptable where the
// packet-*forging* of TCP/IP fingerprint spoofing is not.
func (d *Detector) StartCapture(ctx context.Context, tcp, udp map[int]bool, logf func(string, ...any)) {
	// SOCK_DGRAM strips the link-layer header, so reads start at the IP packet;
	// ETH_P_IP scopes delivery to IPv4. The protocol must be in network byte
	// order.
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_DGRAM, int(htons(unix.ETH_P_IP)))
	if err != nil {
		logf("portscan: packet-level detection unavailable (%v); running fan-out detection only", err)
		return
	}
	logf("portscan: packet-level detection active (AF_PACKET; needs CAP_NET_RAW)")

	served := servedPorts{tcp: tcp, udp: udp}
	go func() {
		<-ctx.Done()
		_ = unix.Close(fd) // unblocks the read loop on shutdown
	}()
	go d.captureLoop(fd, served)
}

func (d *Detector) captureLoop(fd int, served servedPorts) {
	buf := make([]byte, 65536)
	for {
		n, from, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			return // the socket was closed on shutdown, or a fatal read error
		}
		// Skip frames this host sent — our own RSTs to the scanner, the LLMNR
		// prober's queries — so the decoy never detects itself.
		if ll, ok := from.(*unix.SockaddrLinklayer); ok && ll.Pkttype == unix.PACKET_OUTGOING {
			continue
		}
		d.handlePacket(buf[:n], served)
	}
}

// htons puts a 16-bit value in network byte order, which the AF_PACKET protocol
// argument is given in.
func htons(v uint16) uint16 { return v<<8 | v>>8 }
