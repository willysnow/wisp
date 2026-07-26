// Package ntpsvc emulates an NTP server, primarily to detect amplification
// reconnaissance.
//
// The signal here is mode 7 (`monlist`): a request that asks the server for its
// list of recent clients. It has no legitimate modern use, and a ~230-byte
// request draws a multi-kilobyte reply, which is why it was the basis of some
// of the largest DDoS attacks on record. Anyone sending one to your internal
// NTP server is looking for a reflector.
//
// IMPORTANT: this service never answers mode 7. Replying — even with a
// realistic-looking payload — would turn the honeypot itself into a working
// amplifier pointed at whatever address the attacker spoofed. Detection must
// not create the attack it detects.
package ntpsvc

import (
	"context"
	"encoding/binary"
	"net"
	"time"

	"github.com/willysnow/wisp/internal/event"
	"github.com/willysnow/wisp/internal/service"
)

const name = "ntp"

// packetSize is the length of a standard NTP packet without extensions.
const packetSize = 48

// ntpEpochOffset converts Unix time to NTP time — NTP counts from 1900-01-01,
// Unix from 1970-01-01.
const ntpEpochOffset = 2208988800

// NTP association modes (RFC 5905 §7.3), plus the non-standard private mode.
const (
	modeClient  = 3
	modeServer  = 4
	modePrivate = 7 // mode 7 — where monlist lives
)

type Service struct {
	addr string
}

func New(addr string) *Service { return &Service{addr: addr} }

func (s *Service) Name() string { return name }
func (s *Service) Addr() string { return s.addr }

func (s *Service) ServePacket(ctx context.Context, pc net.PacketConn, emit event.Emitter) error {
	return service.AcceptPackets(ctx, pc, func(pc net.PacketConn, from net.Addr, payload []byte) {
		s.handle(pc, from, payload, emit)
	})
}

func (s *Service) handle(pc net.PacketConn, from net.Addr, payload []byte, emit event.Emitter) {
	ev := event.New(name, "request", from, pc.LocalAddr())

	if len(payload) < 1 {
		ev.Kind = "malformed"
		emit.Emit(ev)
		return
	}

	// First byte packs leap indicator (2 bits), version (3), mode (3).
	flags := payload[0]
	version := (flags >> 3) & 0x07
	mode := flags & 0x07

	ev.Data["mode"] = mode
	ev.Data["version"] = version
	ev.Data["bytes"] = len(payload)

	switch mode {
	case modePrivate:
		// Mode 7 with request code 42 is monlist specifically; other mode 7
		// codes are still administrative queries nobody should be sending.
		ev.Kind = "monlist_probe"
		if len(payload) >= 4 {
			ev.Data["request_code"] = payload[3]
		}
		ev.Data["note"] = "amplification reconnaissance; not answered"
		emit.Emit(ev)
		// Deliberately silent. See the package comment.
		return

	case modeClient:
		emit.Emit(ev)
		if len(payload) >= packetSize {
			_, _ = pc.WriteTo(s.serverReply(payload), from)
		}
		return

	default:
		emit.Emit(ev)
		return
	}
}

// serverReply builds a plausible mode 4 answer to a client request, echoing the
// client's transmit timestamp back as the origin timestamp the way a real
// server does.
func (s *Service) serverReply(req []byte) []byte {
	resp := make([]byte, packetSize)

	version := (req[0] >> 3) & 0x07
	resp[0] = (version << 3) | modeServer
	resp[1] = 3      // stratum 3 — a plausible downstream server
	resp[2] = req[2] // echo the client's poll interval
	resp[3] = 0xEC   // precision ~ 2^-20 s

	// Root delay and dispersion: small non-zero values.
	binary.BigEndian.PutUint32(resp[4:8], 0x00000100)
	binary.BigEndian.PutUint32(resp[8:12], 0x00000100)
	copy(resp[12:16], []byte("LOCL")) // reference identifier

	now := ntpTimestamp(time.Now())
	binary.BigEndian.PutUint64(resp[16:24], now) // reference
	copy(resp[24:32], req[40:48])                // origin = client's transmit
	binary.BigEndian.PutUint64(resp[32:40], now) // receive
	binary.BigEndian.PutUint64(resp[40:48], now) // transmit

	return resp
}

// ntpTimestamp renders t as a 64-bit NTP timestamp: 32 bits of seconds since
// the NTP epoch, then 32 bits of fractional second.
func ntpTimestamp(t time.Time) uint64 {
	secs := uint64(t.Unix() + ntpEpochOffset)
	frac := uint64(t.Nanosecond()) << 32 / 1e9
	return secs<<32 | frac
}
