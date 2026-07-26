// Package redissvc emulates an unauthenticated Redis server.
//
// Exposed Redis is one of the most reliably exploited services on the internet,
// and the attack is scripted: CONFIG SET dir /root/.ssh, CONFIG SET dbfilename
// authorized_keys, SET a "<public key>", SAVE. The whole takeover is visible in
// the command sequence, so this service records commands rather than just the
// connection — the sequence is the intelligence.
//
// Unlike the SSH and FTP services, this one answers +OK rather than rejecting.
// No real access is granted (nothing is stored, nothing executes), and an
// attacker who believes the box is open runs their full playbook where we can
// see it.
package redissvc

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/willysnow/wisp/internal/event"
	"github.com/willysnow/wisp/internal/service"
)

const name = "redis"

const (
	// maxArgs and maxArgLen bound a single command so a malformed or hostile
	// length prefix cannot make us allocate arbitrarily.
	maxArgs   = 128
	maxArgLen = 64 << 10

	// maxCommands per connection before hanging up.
	maxCommands = 256

	// argLogLimit bounds how much of an argument reaches the event log. Key
	// material pasted into SET is long and only the prefix identifies it.
	argLogLimit = 512
)

type Service struct {
	addr    string
	version string
}

func New(addr, version string) *Service {
	return &Service{addr: addr, version: version}
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

	for i := 0; i < maxCommands; i++ {
		args, err := readCommand(r)
		if err != nil {
			return
		}
		if len(args) == 0 {
			continue
		}
		verb := strings.ToUpper(args[0])

		// AUTH carries a credential and deserves its own event kind so it lands
		// alongside SSH and FTP logins rather than in the command stream.
		if verb == "AUTH" {
			ev := event.New(name, "login_password", remote, local)
			switch len(args) {
			case 2:
				ev.Data["password"] = truncate(args[1])
			case 3:
				// Redis 6+ ACL form: AUTH <username> <password>
				ev.Data["username"] = truncate(args[1])
				ev.Data["password"] = truncate(args[2])
			}
			emit.Emit(ev)
			_, _ = conn.Write([]byte("+OK\r\n"))
			continue
		}

		ev := event.New(name, "command", remote, local)
		ev.Data["command"] = verb
		if len(args) > 1 {
			ev.Data["args"] = truncate(strings.Join(args[1:], " "))
		}
		emit.Emit(ev)

		if verb == "QUIT" {
			_, _ = conn.Write([]byte("+OK\r\n"))
			return
		}
		_, _ = conn.Write([]byte(s.reply(verb, args)))
	}
}

// reply produces a plausible response. Anything unrecognised gets +OK, which
// keeps a scripted attacker moving through their playbook.
func (s *Service) reply(verb string, args []string) string {
	switch verb {
	case "PING":
		if len(args) > 1 {
			return bulk(args[1])
		}
		return "+PONG\r\n"

	case "ECHO":
		if len(args) > 1 {
			return bulk(args[1])
		}
		return bulk("")

	case "INFO":
		return bulk(s.info())

	case "CONFIG":
		if len(args) >= 2 && strings.ToUpper(args[1]) == "GET" {
			// CONFIG GET dir is the first step of the takeover script; the
			// answer needs to look like a real data directory.
			param := ""
			if len(args) >= 3 {
				param = args[2]
			}
			return array(param, configValue(param))
		}
		return "+OK\r\n"

	case "DBSIZE":
		return ":0\r\n"

	case "COMMAND", "KEYS", "SCAN", "ACL":
		return "*0\r\n"

	case "GET":
		return "$-1\r\n" // nil — the key does not exist

	case "SELECT", "SET", "SAVE", "BGSAVE", "FLUSHALL", "SLAVEOF", "REPLICAOF",
		"MODULE", "EVAL", "SCRIPT", "CLIENT", "DEL":
		return "+OK\r\n"
	}
	return "+OK\r\n"
}

func (s *Service) info() string {
	return strings.Join([]string{
		"# Server",
		"redis_version:" + s.version,
		"redis_mode:standalone",
		"os:Linux 5.15.0-91-generic x86_64",
		"arch_bits:64",
		"tcp_port:6379",
		"# Keyspace",
		"",
	}, "\r\n")
}

func configValue(param string) string {
	switch strings.ToLower(param) {
	case "dir":
		return "/var/lib/redis"
	case "dbfilename":
		return "dump.rdb"
	case "requirepass":
		return ""
	case "maxmemory":
		return "0"
	}
	return ""
}

// readCommand parses one command in either RESP array form (what real clients
// send) or inline form (what netcat and most exploit scripts send).
func readCommand(r *bufio.Reader) ([]string, error) {
	prefix, err := r.Peek(1)
	if err != nil {
		return nil, err
	}
	if prefix[0] != '*' {
		line, err := readLine(r)
		if err != nil {
			return nil, err
		}
		return strings.Fields(line), nil
	}

	line, err := readLine(r) // "*N"
	if err != nil {
		return nil, err
	}
	n, err := strconv.Atoi(strings.TrimPrefix(line, "*"))
	if err != nil || n < 0 {
		return nil, fmt.Errorf("bad multibulk header %q", line)
	}
	if n > maxArgs {
		return nil, fmt.Errorf("multibulk count %d exceeds limit", n)
	}

	args := make([]string, 0, n)
	for i := 0; i < n; i++ {
		hdr, err := readLine(r) // "$len"
		if err != nil {
			return nil, err
		}
		length, err := strconv.Atoi(strings.TrimPrefix(hdr, "$"))
		if err != nil {
			return nil, fmt.Errorf("bad bulk header %q", hdr)
		}
		if length < 0 {
			args = append(args, "")
			continue
		}
		if length > maxArgLen {
			return nil, fmt.Errorf("bulk length %d exceeds limit", length)
		}
		buf := make([]byte, length+2) // payload plus trailing CRLF
		if _, err := readFull(r, buf); err != nil {
			return nil, err
		}
		args = append(args, string(buf[:length]))
	}
	return args, nil
}

func readFull(r *bufio.Reader, buf []byte) (int, error) {
	n := 0
	for n < len(buf) {
		m, err := r.Read(buf[n:])
		n += m
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

func readLine(r *bufio.Reader) (string, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func bulk(s string) string { return fmt.Sprintf("$%d\r\n%s\r\n", len(s), s) }
func array(v ...string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "*%d\r\n", len(v))
	for _, s := range v {
		b.WriteString(bulk(s))
	}
	return b.String()
}

func truncate(s string) string {
	if len(s) <= argLogLimit {
		return s
	}
	return s[:argLogLimit] + "...[truncated]"
}
