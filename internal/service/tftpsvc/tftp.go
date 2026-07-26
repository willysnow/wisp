// Package tftpsvc emulates a TFTP server (RFC 1350).
//
// TFTP has no authentication at all, which makes the requested filename the
// entire signal: a client asking for a router config, a boot image, or
// /etc/passwd has told you what it is looking for and, usually, what it thinks
// this box is.
package tftpsvc

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"

	"github.com/willysnow/wisp/internal/event"
	"github.com/willysnow/wisp/internal/service"
)

const name = "tftp"

// TFTP opcodes.
const (
	opRRQ   = 1 // read request
	opWRQ   = 2 // write request
	opError = 5
)

// TFTP error codes.
const (
	errFileNotFound     = 1
	errAccessViolation  = 2
	errIllegalOperation = 4
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

	if len(payload) < 4 {
		ev.Kind = "malformed"
		ev.Data["bytes"] = len(payload)
		emit.Emit(ev)
		return
	}

	opcode := binary.BigEndian.Uint16(payload[:2])
	filename, mode := parseRequest(payload[2:])

	switch opcode {
	case opRRQ:
		ev.Data["operation"] = "read"
	case opWRQ:
		// A write is strictly worse than a read: something is trying to plant a
		// file, not just take one.
		ev.Kind = "write_request"
		ev.Data["operation"] = "write"
	default:
		ev.Kind = "malformed"
		ev.Data["opcode"] = opcode
		emit.Emit(ev)
		_, _ = pc.WriteTo(errorPacket(errIllegalOperation, "Illegal TFTP operation"), from)
		return
	}

	ev.Data["filename"] = filename
	ev.Data["mode"] = mode
	emit.Emit(ev)

	// Refuse everything. Serving a real file would make this an open file
	// server; accepting a write would make it a malware drop.
	if opcode == opWRQ {
		_, _ = pc.WriteTo(errorPacket(errAccessViolation, "Access violation"), from)
		return
	}
	_, _ = pc.WriteTo(errorPacket(errFileNotFound, "File not found"), from)
}

// parseRequest pulls the NUL-terminated filename and transfer mode out of an
// RRQ/WRQ body. A truncated packet yields whatever was readable rather than an
// error — a malformed request is still a recorded interaction.
func parseRequest(b []byte) (filename, mode string) {
	parts := bytes.SplitN(b, []byte{0}, 3)
	if len(parts) > 0 {
		filename = printable(parts[0])
	}
	if len(parts) > 1 {
		mode = printable(parts[1])
	}
	return filename, mode
}

func errorPacket(code uint16, msg string) []byte {
	buf := make([]byte, 4, 4+len(msg)+1)
	binary.BigEndian.PutUint16(buf[0:2], opError)
	binary.BigEndian.PutUint16(buf[2:4], code)
	buf = append(buf, msg...)
	return append(buf, 0)
}

// printable strips control and non-ASCII bytes so a hostile filename cannot
// corrupt the JSONL event log.
func printable(b []byte) string {
	out := make([]byte, 0, len(b))
	for _, c := range b {
		if c < 0x20 || c > 0x7e {
			out = append(out, '.')
			continue
		}
		out = append(out, c)
	}
	return string(out)
}
