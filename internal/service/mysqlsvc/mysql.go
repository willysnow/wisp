// Package mysqlsvc emulates a MySQL server far enough to capture the one thing
// an intruder came to 3306 for: an account name and a password response that
// cracks offline.
//
// It works the way the SMB and MongoDB decoys do. A client that reaches a MySQL
// server authenticates before it can run a query, so the server issues a random
// scramble and the client answers with SHA1(pw) XOR SHA1(scramble || SHA1(SHA1(pw)))
// — a value keyed by the password. Choose the scramble, record it, and the answer
// is a credential that cracks offline:
//
//	mysql  auth_attempt  username=root  database=app
//	       netmysql=$mysqlna$1122...8899*aabb...ccdd  hashcat_mode=11200
//
// That line is hashcat mode 11200, ready to paste. It is not "someone touched
// 3306" — it is who they were and a value that reveals their password to anyone
// with a wordlist.
//
// The decoy advertises mysql_native_password rather than MySQL 8's default
// caching_sha2_password on purpose: native's response is a clean 20-byte value
// a wordlist can attack, while caching_sha2 needs TLS or an RSA exchange to
// carry the actual secret and yields nothing crackable. A client that offers a
// different plugin is switched to native, the same way a real server switches
// one whose default does not match.
//
// Nothing is ever granted. Every authentication ends in ER_ACCESS_DENIED_ERROR,
// for the same reason the MongoDB decoy always answers AuthenticationFailed and
// the SMB decoy always answers STATUS_LOGON_FAILURE: a door that is merely
// locked invites a key, and the key is the whole point. The handshake never
// completes, so there is no query, no table, and no result to get wrong.
package mysqlsvc

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"sync/atomic"

	"github.com/willysnow/wisp/internal/event"
	"github.com/willysnow/wisp/internal/service"
)

const name = "mysql"

// logLimit bounds any single captured field before it reaches the event log. A
// hashcat line is a few hundred bytes; a value far larger is a client trying to
// bloat the log rather than authenticate.
const logLimit = 1024

var errBadLength = errors.New("mysql: packet length out of range")

type Service struct {
	addr string
	// version is what the server calls itself in the handshake — the string a
	// client and every fingerprinting tool reads first. It should match the
	// device persona: a box claiming to be a particular appliance should report
	// the MySQL build that appliance ships.
	version string
}

// New builds the decoy. An empty version falls back to a plausible current
// server build.
func New(addr, version string) *Service {
	if version == "" {
		version = "8.0.36"
	}
	return &Service{addr: addr, version: version}
}

func (s *Service) Name() string { return name }
func (s *Service) Addr() string { return s.addr }

func (s *Service) Serve(ctx context.Context, ln net.Listener, emit event.Emitter) error {
	return service.Accept(ctx, ln, func(c net.Conn) { s.handle(c, emit) })
}

// handle drives the whole exchange, which is a fixed sequence rather than a
// request/response loop: send the handshake, read the response, switch the
// client to native auth if it did not already send a native response, emit the
// captured credential, and refuse. There is no state past the refusal because
// authentication never succeeds.
func (s *Service) handle(nc net.Conn, emit event.Emitter) {
	var scramble [20]byte
	if _, err := rand.Read(scramble[:]); err != nil {
		return
	}

	// A connection on which the client never completed the handshake is a bare
	// port touch — a scan — and worth exactly one event.
	spoke := false
	defer func() {
		if !spoke {
			emit.Emit(event.New(name, "connection", nc.RemoteAddr(), nc.LocalAddr()))
		}
	}()

	if err := writePacket(nc, 0, s.handshake(scramble, nextConnID())); err != nil {
		return
	}

	seq, payload, err := readPacket(nc)
	if err != nil {
		return
	}
	req, ok := parseHandshakeResponse(payload)
	if !ok {
		if req.ssl {
			// An SSLRequest: the client wants to negotiate TLS before it sends a
			// username. The decoy does not advertise or speak TLS, so there is
			// nothing crackable coming; record that a client got this far and
			// close.
			ev := event.New(name, "probe", nc.RemoteAddr(), nc.LocalAddr())
			ev.Data["tls_requested"] = true
			emit.Emit(ev)
			spoke = true
		}
		return
	}
	spoke = true

	authResp := req.authResp
	usedScramble := scramble[:]

	// If the client did not hand over a clean native response — a caching_sha2
	// client, or one that sent an empty response expecting a challenge — switch
	// it to mysql_native_password against a fresh scramble and read the reply.
	// That reply is the raw 20-byte native response, nothing else.
	if !isNative(req.plugin) || len(authResp) != 20 {
		var s2 [20]byte
		if _, err := rand.Read(s2[:]); err == nil {
			if err := writePacket(nc, seq+1, authSwitchRequest(s2)); err == nil {
				if seq2, p2, err := readPacket(nc); err == nil {
					seq = seq2
					if len(p2) >= 20 {
						authResp = p2[:20]
						usedScramble = s2[:]
					}
				}
			}
		}
	}

	s.capture(nc, emit, req, authResp, usedScramble)

	host, _ := event.SplitHostPortString(nc.RemoteAddr().String())
	_ = writePacket(nc, seq+1, errorPacket(req.username, host))
}

// capture records the credential and refuses nothing here — the refusal is the
// caller's ERR packet. Only a 20-byte response yields a hashcat line; a shorter
// or missing one still leaves the account name and the source worth logging.
func (s *Service) capture(nc net.Conn, emit event.Emitter, req loginReq, authResp, scramble []byte) {
	ev := event.New(name, "auth_attempt", nc.RemoteAddr(), nc.LocalAddr())
	ev.Data["username"] = truncate(req.username)
	if req.database != "" {
		ev.Data["database"] = truncate(req.database)
	}

	if len(authResp) == 20 {
		ev.Data["netmysql"] = formatNativeHash(scramble, authResp)
		ev.Data["hashcat_mode"] = 11200
	} else if len(authResp) == 0 {
		// An empty response is an anonymous or no-password attempt. The account
		// name is still the point.
		ev.Data["no_password"] = true
	}

	// The connection attributes are the strongest fingerprint the client sends:
	// its driver and version, and often the program name a developer set.
	if a := req.attrs; a != nil {
		if cn := a["_client_name"]; cn != "" {
			client := cn
			if cv := a["_client_version"]; cv != "" {
				client += " " + cv
			}
			ev.Data["client"] = truncate(client)
		}
		if pn := a["program_name"]; pn != "" {
			ev.Data["program"] = truncate(pn)
		}
		if os := a["_os"]; os != "" {
			ev.Data["client_os"] = truncate(os)
		}
	}

	emit.Emit(ev)
}

// isNative reports whether a client's stated auth plugin is the native one. An
// empty plugin means the client did not name one, which against a server that
// advertised native means it computed a native response.
func isNative(plugin string) bool {
	return plugin == "" || plugin == nativePassword
}

// connections numbers the thread ids the server hands out. It starts somewhere
// arbitrary rather than at zero: a server reporting connection id 1 to everyone
// has obviously just been started for their benefit.
var connections atomic.Uint32

func init() {
	var b [4]byte
	if _, err := rand.Read(b[:]); err == nil {
		connections.Store(binary.LittleEndian.Uint32(b[:])%40000 + 100)
	} else {
		connections.Store(100)
	}
}

func nextConnID() uint32 { return connections.Add(1) }
