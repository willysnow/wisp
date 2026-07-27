// Package vncsvc emulates a VNC (RFB) server far enough to capture the one thing
// an intruder came to 5900 for: the challenge-response a client returns for VNC
// Authentication, which cracks offline back to the password.
//
// It works the way the SMB and MongoDB decoys do. A real VNC server offering VNC
// Authentication sends a 16-byte challenge; the client encrypts it with DES
// keyed by the password and sends the 16 bytes back. Choose the challenge, record
// it next to the response, and the pair is a credential that cracks offline:
//
//	vnc  auth_attempt  challenge=<hex>  response=<hex>
//	     vnc_hash=$vnc$*<challenge>*<response>  john_format=vnc
//
// That line is John the Ripper's `vnc` format, ready to paste (there is no clean
// single hashcat mode for it — the DES uses a bit-reversed key over two blocks).
// It is not "someone touched 5900" — it is a value that reveals the password to
// anyone with a wordlist.
//
// The decoy advertises only VNC Authentication, never "None", for the same
// reason the MongoDB decoy insists authentication is required: a server that lets
// a client straight in captures nothing, and the challenge-response is the whole
// point. Nothing is ever accepted; every attempt ends in a security-result
// failure, so no framebuffer is ever served — this decoy stops at the handshake
// and never reaches the state where it could paint a screen.
package vncsvc

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strings"

	"github.com/willysnow/wisp/internal/event"
	"github.com/willysnow/wisp/internal/service"
	"github.com/willysnow/wisp/internal/service/httpdecoy"
)

const name = "vnc"

// logLimit bounds any single captured field before it reaches the event log.
const logLimit = 1024

// secVNCAuth is the RFB security type for VNC Authentication — the only one this
// decoy ever offers. Type 1 (None) would let a client in without a
// challenge-response, which is the artifact worth having.
const secVNCAuth = 2

// challengeSize is the fixed length of a VNC auth challenge and its response.
const challengeSize = 16

// securityResultFailed is the SecurityResult a real server sends for a wrong
// password, and the only one this decoy ever sends.
const securityResultFailed = 1

type Service struct {
	addr string
	// banner is the RFB ProtocolVersion the server offers first, e.g.
	// "RFB 003.008\n". It fixes which security handshake the exchange uses.
	banner string
}

// New builds the decoy. version is an RFB protocol version like "3.8"; an empty
// or unparseable value falls back to 3.8, the most common modern one.
func New(addr, version string) *Service {
	return &Service{addr: addr, banner: formatVersion(version)}
}

func (s *Service) Name() string { return name }
func (s *Service) Addr() string { return s.addr }

func (s *Service) Serve(ctx context.Context, ln net.Listener, emit event.Emitter) error {
	return service.Accept(ctx, ln, func(c net.Conn) { s.handle(c, emit) })
}

// handle drives the RFB handshake, a fixed sequence: offer the protocol version,
// read the client's, offer VNC Authentication, send the challenge, record the
// response, and refuse. There is nothing past the refusal because authentication
// never succeeds.
//
// One interaction produces one primary event: a bare scan that reads the banner
// and leaves is a `connection`; a client that speaks its version but does not
// complete the exchange is a `probe`; a client that returns a challenge-response
// is an `auth_attempt`.
func (s *Service) handle(nc net.Conn, emit event.Emitter) {
	var (
		spoke         bool
		captured      bool
		clientVersion string
	)
	defer func() {
		switch {
		case captured:
			// auth_attempt already emitted.
		case spoke:
			ev := event.New(name, "probe", nc.RemoteAddr(), nc.LocalAddr())
			ev.Data["client_version"] = sanitiseVersion(clientVersion)
			emit.Emit(ev)
		default:
			emit.Emit(event.New(name, "connection", nc.RemoteAddr(), nc.LocalAddr()))
		}
	}()

	if _, err := nc.Write([]byte(s.banner)); err != nil {
		return
	}

	var cv [12]byte
	if _, err := io.ReadFull(nc, cv[:]); err != nil {
		return
	}
	spoke = true
	clientVersion = string(cv[:])
	minor := parseMinor(cv[:])

	// The security handshake. From RFB 3.7 the server offers a list of types and
	// the client picks one; 3.3 has the server dictate a single type. Either way
	// the decoy names only VNC Authentication.
	if minor >= 7 {
		if _, err := nc.Write([]byte{1, secVNCAuth}); err != nil {
			return
		}
		var sel [1]byte
		if _, err := io.ReadFull(nc, sel[:]); err != nil {
			return
		}
		if sel[0] != secVNCAuth {
			// The client refused the only type on offer. Its choice is still
			// worth the probe the defer will emit.
			return
		}
	} else {
		var st [4]byte
		binary.BigEndian.PutUint32(st[:], secVNCAuth)
		if _, err := nc.Write(st[:]); err != nil {
			return
		}
	}

	var challenge [challengeSize]byte
	if _, err := rand.Read(challenge[:]); err != nil {
		return
	}
	if _, err := nc.Write(challenge[:]); err != nil {
		return
	}

	var response [challengeSize]byte
	if _, err := io.ReadFull(nc, response[:]); err != nil {
		return
	}
	s.capture(nc, emit, clientVersion, challenge[:], response[:])
	captured = true

	// Always refused. A locked door invites the next key.
	var result [4]byte
	binary.BigEndian.PutUint32(result[:], securityResultFailed)
	if _, err := nc.Write(result[:]); err != nil {
		return
	}
	// From RFB 3.8 a failed result carries a reason string; earlier versions do
	// not, and sending one to a 3.3 client would desynchronise it.
	if minor >= 8 {
		writeReason(nc, "Authentication failure")
	}
}

// capture records the challenge-response as a crackable artifact.
func (s *Service) capture(nc net.Conn, emit event.Emitter, clientVersion string, challenge, response []byte) {
	ev := event.New(name, "auth_attempt", nc.RemoteAddr(), nc.LocalAddr())
	ev.Data["client_version"] = sanitiseVersion(clientVersion)
	ev.Data["challenge"] = hex.EncodeToString(challenge)
	ev.Data["response"] = hex.EncodeToString(response)
	// John the Ripper's `vnc` format, challenge then response. Given both, a
	// cracker computes DES(challenge, key-from-password) and checks it against
	// the response — which is why the challenge the decoy chose has to be
	// recorded alongside it.
	ev.Data["vnc_hash"] = "$vnc$*" + hex.EncodeToString(challenge) + "*" + hex.EncodeToString(response)
	ev.Data["john_format"] = "vnc"
	emit.Emit(ev)
}

// writeReason writes the U32-length-prefixed reason string an RFB 3.8 server
// appends to a failed SecurityResult.
func writeReason(w io.Writer, reason string) {
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(reason)))
	_, _ = w.Write(hdr[:])
	_, _ = w.Write([]byte(reason))
}

// formatVersion turns a "major.minor" string into the 12-byte RFB
// ProtocolVersion banner. Anything unparseable falls back to 3.8.
func formatVersion(version string) string {
	major, minor := 3, 8
	if a, b, ok := parseTwo(version); ok {
		major, minor = a, b
	}
	return fmt.Sprintf("RFB %03d.%03d\n", major, minor)
}

func parseTwo(s string) (int, int, bool) {
	parts := strings.Split(strings.TrimSpace(s), ".")
	if len(parts) != 2 {
		return 0, 0, false
	}
	a, ok1 := atoi(parts[0])
	b, ok2 := atoi(parts[1])
	if !ok1 || !ok2 {
		return 0, 0, false
	}
	return a, b, true
}

func atoi(s string) (int, bool) {
	if s == "" {
		return 0, false
	}
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + int(c-'0')
	}
	return n, true
}

// parseMinor reads the minor version from a client's ProtocolVersion, which is
// the three digits after the dot in "RFB 003.008\n". A malformed value falls
// back to 3, the oldest handshake and the safe assumption.
func parseMinor(b []byte) int {
	if len(b) < 12 {
		return 3
	}
	n := 0
	for _, c := range b[8:11] {
		if c < '0' || c > '9' {
			return 3
		}
		n = n*10 + int(c-'0')
	}
	return n
}

// sanitiseVersion trims the banner's newline and strips control characters, so
// an attacker-supplied version string reaches the log as plain text.
func sanitiseVersion(s string) string {
	s = httpdecoy.Truncate(s, logLimit)
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
}
