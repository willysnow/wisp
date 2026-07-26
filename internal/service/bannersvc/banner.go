// Package bannersvc is a generic TCP catcher for ports that do not warrant a
// full protocol emulator.
//
// It optionally sends a banner, records whatever the client says first, and
// hangs up. That is enough to detect a port scan or a targeted probe, and it
// covers the long tail — VNC, MSSQL, MongoDB, a printer port — without writing
// a parser for each. Where a real emulator exists, prefer it: this one cannot
// capture credentials.
package bannersvc

import (
	"context"
	"net"
	"strings"
	"unicode"

	"github.com/willysnow/wisp/internal/event"
	"github.com/willysnow/wisp/internal/service"
)

// maxCapture bounds how much of the client's first message is recorded.
const maxCapture = 2048

type Service struct {
	name   string
	addr   string
	banner string
}

// New returns a catcher that identifies itself as name in emitted events —
// name it after whatever the port is pretending to be ("vnc", "mssql"), since
// that is what an operator needs to see in the alert.
func New(name, addr, banner string) *Service {
	return &Service{name: name, addr: addr, banner: banner}
}

func (s *Service) Name() string { return s.name }
func (s *Service) Addr() string { return s.addr }

func (s *Service) Serve(ctx context.Context, ln net.Listener, emit event.Emitter) error {
	return service.Accept(ctx, ln, func(c net.Conn) { s.handle(c, emit) })
}

func (s *Service) handle(conn net.Conn, emit event.Emitter) {
	remote, local := conn.RemoteAddr(), conn.LocalAddr()

	if s.banner != "" {
		_, _ = conn.Write([]byte(s.banner))
	}

	buf := make([]byte, maxCapture)
	n, _ := conn.Read(buf)

	ev := event.New(s.name, "connect", remote, local)
	ev.Data["emulation"] = "banner"
	if n > 0 {
		ev.Kind = "probe"
		ev.Data["bytes"] = n
		ev.Data["payload"] = printable(buf[:n])
	}
	emit.Emit(ev)
}

// printable renders the captured bytes for a log line, replacing control and
// non-ASCII bytes with '.' the way a hex viewer would. Binary protocols are
// common on these ports and raw bytes would corrupt the JSONL output.
func printable(b []byte) string {
	var out strings.Builder
	out.Grow(len(b))
	for _, c := range b {
		if c > unicode.MaxASCII || !unicode.IsPrint(rune(c)) {
			out.WriteByte('.')
			continue
		}
		out.WriteByte(c)
	}
	return out.String()
}
