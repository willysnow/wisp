// Package ftpsvc emulates an FTP control channel.
//
// Only the login exchange is implemented — no data channel, no directory
// listing. Everything worth capturing (USER, PASS, and the client's stated
// intent via subsequent commands) crosses the control channel in cleartext
// before any transfer would begin.
package ftpsvc

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/willysnow/wisp/internal/event"
	"github.com/willysnow/wisp/internal/service"
)

const name = "ftp"

// maxLine bounds one command. RFC 959 allows 512 bytes including CRLF.
const maxLine = 512

// maxCommands before hanging up, so a client cannot loop forever.
const maxCommands = 64

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

	_, _ = fmt.Fprintf(conn, "220 %s\r\n", s.banner)

	r := bufio.NewReader(conn)
	// The username is remembered across commands so the PASS event can report
	// the pair. FTP splits credentials across two commands by design.
	var user string

	for i := 0; i < maxCommands; i++ {
		line, err := readLine(r)
		if err != nil {
			return
		}
		verb, arg := splitCommand(line)

		switch verb {
		case "USER":
			user = arg
			_, _ = fmt.Fprintf(conn, "331 Please specify the password.\r\n")

		case "PASS":
			ev := event.New(name, "login_password", remote, local)
			ev.Data["username"] = user
			ev.Data["password"] = arg
			emit.Emit(ev)
			// Uniform rejection: never reveal whether the account exists.
			_, _ = fmt.Fprintf(conn, "530 Login incorrect.\r\n")

		case "QUIT":
			_, _ = fmt.Fprintf(conn, "221 Goodbye.\r\n")
			return

		case "SYST":
			_, _ = fmt.Fprintf(conn, "215 UNIX Type: L8\r\n")

		case "FEAT":
			_, _ = fmt.Fprintf(conn, "211-Features:\r\n UTF8\r\n211 End\r\n")

		case "AUTH":
			// Refusing TLS keeps the rest of the session in cleartext, which is
			// the point — an encrypted session would hide the credentials.
			_, _ = fmt.Fprintf(conn, "530 Please login with USER and PASS.\r\n")

		default:
			// Post-login commands still carry intent worth recording: a client
			// going straight for STOR or SITE EXEC is not browsing.
			if verb != "" {
				ev := event.New(name, "command", remote, local)
				ev.Data["command"] = verb
				if arg != "" {
					ev.Data["arg"] = arg
				}
				emit.Emit(ev)
			}
			_, _ = fmt.Fprintf(conn, "530 Please login with USER and PASS.\r\n")
		}
	}
}

func readLine(r *bufio.Reader) (string, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return "", err
	}
	if len(line) > maxLine {
		line = line[:maxLine]
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// splitCommand separates the verb from its argument. FTP verbs are
// case-insensitive, so they are normalised for the switch.
func splitCommand(line string) (verb, arg string) {
	line = strings.TrimSpace(line)
	if i := strings.IndexByte(line, ' '); i >= 0 {
		return strings.ToUpper(line[:i]), strings.TrimSpace(line[i+1:])
	}
	return strings.ToUpper(line), ""
}
