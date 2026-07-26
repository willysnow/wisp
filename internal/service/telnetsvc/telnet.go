// Package telnetsvc emulates a telnet login.
//
// Telnet is among the highest-signal services a honeypot can run: essentially
// nothing legitimate speaks it on a modern network, so a single connection is
// already suspicious and a login attempt is close to conclusive.
package telnetsvc

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/willysnow/wisp/internal/event"
	"github.com/willysnow/wisp/internal/service"
)

const name = "telnet"

// Telnet protocol bytes (RFC 854).
const (
	iac  = 255 // Interpret As Command — introduces a negotiation sequence
	se   = 240 // End of subnegotiation
	sb   = 250 // Begin subnegotiation
	will = 251
	wont = 252
	do   = 253
	dont = 254

	optEcho = 1
)

// maxLine bounds a single credential field. Real usernames are short; a
// megabyte-long "username" is an attack on us, not a login attempt.
const maxLine = 512

// maxAttempts before hanging up, matching typical telnetd behaviour.
const maxAttempts = 3

type Service struct {
	addr   string
	banner string
}

func New(addr, banner string) *Service {
	return &Service{addr: addr, banner: banner}
}

func (s *Service) Name() string { return name }
func (s *Service) Addr() string { return s.addr }

func (s *Service) Serve(ctx context.Context, ln net.Listener, emit event.Emitter) error {
	return service.Accept(ctx, ln, func(c net.Conn) { s.handle(c, emit) })
}

func (s *Service) handle(conn net.Conn, emit event.Emitter) {
	remote, local := conn.RemoteAddr(), conn.LocalAddr()
	emit.Emit(event.New(name, "connect", remote, local))

	r := bufio.NewReader(conn)

	// Tell the client we will handle echoing. Real telnetd does this so it can
	// suppress echo during the password prompt; skipping it makes us look wrong
	// to anything that inspects the negotiation.
	_, _ = conn.Write([]byte{iac, will, optEcho})

	if s.banner != "" {
		_, _ = fmt.Fprintf(conn, "\r\n%s\r\n\r\n", s.banner)
	}

	for attempt := 0; attempt < maxAttempts; attempt++ {
		_, _ = conn.Write([]byte("login: "))
		user, err := readLine(r)
		if err != nil {
			return
		}

		_, _ = conn.Write([]byte("Password: "))
		pass, err := readLine(r)
		if err != nil {
			return
		}

		if user == "" && pass == "" {
			continue
		}

		ev := event.New(name, "login_password", remote, local)
		ev.Data["username"] = user
		ev.Data["password"] = pass
		emit.Emit(ev)

		// Always the same rejection, never "no such user" — anything that
		// distinguishes a valid account from an invalid one lets the attacker
		// enumerate users for free.
		_, _ = conn.Write([]byte("\r\nLogin incorrect\r\n"))
	}
}

// readLine reads one CR/LF-terminated line, stripping telnet negotiation
// sequences. Clients negotiate options during the login exchange, so a naive
// read would splice IAC control bytes into the captured username.
func readLine(r *bufio.Reader) (string, error) {
	var out []byte
	for len(out) < maxLine {
		b, err := r.ReadByte()
		if err != nil {
			return string(out), err
		}
		switch b {
		case iac:
			if err := skipNegotiation(r); err != nil {
				return string(out), err
			}
		case '\n':
			return strings.TrimRight(string(out), "\r"), nil
		case 0:
			// Telnet transmits a bare CR as CR NUL; drop the NUL.
		default:
			out = append(out, b)
		}
	}
	return string(out), nil
}

// skipNegotiation consumes the remainder of an IAC sequence. The leading IAC
// has already been read.
func skipNegotiation(r *bufio.Reader) error {
	cmd, err := r.ReadByte()
	if err != nil {
		return err
	}
	switch cmd {
	case will, wont, do, dont:
		_, err = r.ReadByte() // the option byte
		return err
	case sb:
		// Subnegotiation runs until IAC SE.
		for {
			b, err := r.ReadByte()
			if err != nil {
				return err
			}
			if b != iac {
				continue
			}
			next, err := r.ReadByte()
			if err != nil {
				return err
			}
			if next == se {
				return nil
			}
		}
	}
	return nil
}
