// Package service defines the contract every honeypot listener implements.
package service

import (
	"context"
	"net"
	"time"

	"github.com/willysnow/wisp/internal/event"
)

// idleTimeout bounds how long one connection may hold a goroutine. Scanners
// routinely open a socket and never speak; without this they accumulate.
const idleTimeout = 60 * time.Second

// Service is the part every listener shares. Implementations additionally
// satisfy StreamService (TCP) or PacketService (UDP) — the runner type-switches
// to decide how to bind.
type Service interface {
	// Name is the identifier that appears in event.Service.
	Name() string

	// Addr is the listen address, e.g. "0.0.0.0:2323".
	Addr() string
}

// StreamService is a connection-oriented (TCP) service.
type StreamService interface {
	Service

	// Serve blocks until ctx is cancelled or ln fails. Returning nil means a
	// clean shutdown; anything else is logged as a service-level failure.
	Serve(ctx context.Context, ln net.Listener, emit event.Emitter) error
}

// PacketService is a datagram (UDP) service.
type PacketService interface {
	Service

	ServePacket(ctx context.Context, pc net.PacketConn, emit event.Emitter) error
}

// Accept runs the accept loop shared by every TCP service: one goroutine per
// connection, a deadline so nothing hangs forever, and a clean exit when ctx is
// cancelled rather than an error on the closed listener.
func Accept(ctx context.Context, ln net.Listener, handle func(net.Conn)) error {
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go func(c net.Conn) {
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(idleTimeout))
			handle(c)
		}(conn)
	}
}

// AcceptPackets is Accept's UDP counterpart. handle is called synchronously —
// datagram handlers here only parse and reply, so a goroutine per packet would
// be pure overhead and an amplification-friendly way to exhaust memory.
func AcceptPackets(ctx context.Context, pc net.PacketConn, handle func(pc net.PacketConn, from net.Addr, payload []byte)) error {
	go func() {
		<-ctx.Done()
		_ = pc.Close()
	}()

	// 4 KiB covers every datagram these services care about. Anything larger is
	// truncated rather than allocated for.
	buf := make([]byte, 4096)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		payload := make([]byte, n)
		copy(payload, buf[:n])
		handle(pc, from, payload)
	}
}
