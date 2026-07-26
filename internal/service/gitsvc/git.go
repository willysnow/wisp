// Package gitsvc emulates a git daemon.
//
// The git protocol (9418/tcp, unauthenticated by design) is what people stand
// up to share repositories internally and then forget about. What makes it
// worth a decoy is not the connection but the request: a git client states the
// full repository path before anything else happens, so the very first packet
// tells you what the intruder already knows about your naming.
//
// "Someone connected to 9418" is a connection log. "Someone asked for
// /srv/git/payments-api.git" is an alert with a lead in it — they did not
// guess that name.
package gitsvc

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strings"

	"github.com/willysnow/wisp/internal/event"
	"github.com/willysnow/wisp/internal/service"
)

const name = "git"

// maxPktLine is the protocol's own limit: four hex digits of length, so 65535
// including the header. Anything claiming more is malformed.
const maxPktLine = 65520

// logLimit bounds how much of a field reaches an event. Repository paths are
// short; a kilobyte of them is someone probing the parser.
const logLimit = 512

type Service struct {
	addr string
}

func New(addr string) *Service { return &Service{addr: addr} }

func (s *Service) Name() string { return name }
func (s *Service) Addr() string { return s.addr }

func (s *Service) Serve(ctx context.Context, ln net.Listener, emit event.Emitter) error {
	return service.Accept(ctx, ln, func(conn net.Conn) { s.handle(conn, emit) })
}

func (s *Service) handle(conn net.Conn, emit event.Emitter) {
	line, err := readPktLine(conn)
	if err != nil {
		// A connection that opens and says nothing is still worth recording:
		// it is what a port scan looks like from in here.
		ev := event.New(name, "connection", conn.RemoteAddr(), conn.LocalAddr())
		emit.Emit(ev)
		return
	}

	req := parseRequest(line)

	ev := event.New(name, kindFor(req.command), conn.RemoteAddr(), conn.LocalAddr())
	ev.Data["command"] = truncate(req.command)
	ev.Data["repository"] = truncate(req.repository)
	if req.host != "" {
		// The name the client was given for this machine. A client that says
		// "git.internal" reached us through a name someone published, not by
		// scanning an address range.
		ev.Data["host"] = truncate(req.host)
	}
	for k, v := range req.extra {
		ev.Data[k] = truncate(v)
	}
	emit.Emit(ev)

	// Answer the way a real daemon answers for a repository it will not serve.
	//
	// There is no version of this that keeps the client talking: git makes one
	// request per connection and gives up on an error either way. The request
	// itself is the whole take, so the reply's only job is to be unremarkable.
	_ = writePktLine(conn, fmt.Sprintf("ERR \n  Repository not exported: '%s'\n",
		sanitise(req.repository)))
}

// request is one git daemon request line, which has the shape
//
//	git-upload-pack /path/to/repo\0host=example.com\0\0version=2\0
//
// The trailing extra parameters arrive after an empty string, and only from
// clients that speak protocol v2.
type request struct {
	command    string
	repository string
	host       string
	extra      map[string]string
}

func parseRequest(line string) request {
	req := request{extra: map[string]string{}}

	// Command and repository are separated by the first space; everything from
	// the first NUL onwards is key=value metadata.
	head, rest, _ := strings.Cut(line, "\x00")
	req.command, req.repository, _ = strings.Cut(strings.TrimRight(head, "\n"), " ")

	for _, field := range strings.Split(rest, "\x00") {
		if field == "" {
			continue
		}
		k, v, ok := strings.Cut(field, "=")
		if !ok {
			continue
		}
		if k == "host" {
			req.host = v
			continue
		}
		req.extra[k] = v
	}
	return req
}

// kindFor separates reading from writing.
//
// git-upload-pack is a clone or a fetch — reconnaissance. git-receive-pack is
// a push: an attempt to put code into your infrastructure, which is never
// accidental and shares a kind with the other write attempts wisp records.
func kindFor(command string) string {
	switch command {
	case "git-receive-pack":
		return "write_request"
	case "git-upload-pack", "git-upload-archive":
		return "repo_request"
	}
	return "probe"
}

// readPktLine reads one pkt-line: four hex digits of total length, then the
// payload.
func readPktLine(r io.Reader) (string, error) {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return "", err
	}

	size, err := hex.DecodeString(string(header[:]))
	if err != nil {
		return "", fmt.Errorf("malformed pkt-line length %q", header)
	}
	length := int(size[0])<<8 | int(size[1])

	switch {
	case length == 0:
		return "", nil // flush packet
	case length < 4 || length > maxPktLine:
		return "", fmt.Errorf("pkt-line length %d out of range", length)
	}

	payload := make([]byte, length-4)
	if _, err := io.ReadFull(r, payload); err != nil {
		return "", err
	}
	return string(payload), nil
}

func writePktLine(w io.Writer, payload string) error {
	if len(payload) > maxPktLine-4 {
		payload = payload[:maxPktLine-4]
	}
	_, err := fmt.Fprintf(w, "%04x%s", len(payload)+4, payload)
	return err
}

// sanitise keeps attacker-controlled text out of the shape of our own reply.
// The path is echoed back the way a real daemon echoes it, but not the control
// characters that would let someone forge extra protocol lines in a log or a
// terminal.
func sanitise(s string) string {
	s = truncate(s)
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
}

func truncate(s string) string {
	if len(s) <= logLimit {
		return s
	}
	return s[:logLimit] + "..."
}
