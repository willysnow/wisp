// Package smbsvc emulates an SMB2/3 file server far enough to capture the one
// thing an intruder came to 445 for: a NetNTLMv2 hash and the account name that
// produced it.
//
// This is the module that answers "why not just run OpenCanary". OpenCanary's
// SMB is not OpenCanary at all — it is an external Samba install with a
// full_audit VFS module writing to syslog for OpenCanary to tail, which is the
// ugliest link in its dependency chain and the reason a lot of people never get
// it running. Here it is native: one static binary, no Samba, no VFS module.
//
// The capture works the way the MongoDB decoy's does. A modern client that
// reaches a share authenticates with NTLMv2 before it can read anything, so the
// server issues a challenge and the client answers with an HMAC over that
// challenge keyed by a value derived from the password. Choose the challenge
// yourself — a fixed one, the way Responder does — and the answer the client
// sends back is a credential that cracks offline:
//
//	smb  auth_attempt  username=jsmith  domain=CORP  workstation=WKS-4021
//	     netntlmv2=jsmith::CORP:1122334455667788:<NTproof>:<blob>
//
// That line is hashcat mode 5600, ready to paste. It is not "someone touched
// the share" — it is who they were and a value that reveals their password to
// anyone with a wordlist and an afternoon.
//
// Nothing is ever granted. Every authentication ends in STATUS_LOGON_FAILURE,
// for the same reason the MongoDB decoy always answers AuthenticationFailed and
// the Kubernetes decoy always answers 403: a door that is merely locked invites
// a key, and the key is the whole point. The session never completes, so there
// is no tree connect, no share, and no file operation to get wrong — the decoy
// cannot serve a byte because it never reaches the state where it could.
package smbsvc

import (
	"context"
	"encoding/binary"
	"io"
	"net"

	"github.com/willysnow/wisp/internal/event"
	"github.com/willysnow/wisp/internal/ntlm"
	"github.com/willysnow/wisp/internal/service"
)

// identity is what this "server" calls itself in the NTLM challenge — the names
// a client folds into the material it hashes.
func (s *Service) identity() ntlm.Identity {
	return ntlm.Identity{Computer: s.computerName, Domain: s.domainName, DNS: s.dnsName}
}

const name = "smb"

// SMB2 command codes. These four are the whole conversation a credential
// capture needs; a real server has a dozen more that only matter once a session
// exists, which here it never does.
const (
	cmdNegotiate    = 0x0000
	cmdSessionSetup = 0x0001
	cmdLogoff       = 0x0002
	cmdTreeConnect  = 0x0003
)

// NT status codes. MORE_PROCESSING_REQUIRED is how a server says "your
// credential is not complete, keep going" mid-handshake; LOGON_FAILURE is the
// only way this decoy ever ends one.
const (
	statusSuccess           = 0x00000000
	statusMoreProcessingReq = 0xC0000016
	statusLogonFailure      = 0xC000006D
	statusAccessDenied      = 0xC0000022
)

// smbHeaderSize is the fixed SMB2 "sync" header.
const smbHeaderSize = 64

// maxMessage caps one SMB message. A real server negotiates transaction sizes
// in the megabytes, but a decoy that never serves a file has no use for a large
// one, and the difference is memory a stranger would otherwise get to allocate
// from a single length field. The direct-TCP transport can only express 24
// bits of length anyway.
const maxMessage = 1 << 20

// logLimit bounds any single captured field before it reaches the event log.
// A NetNTLMv2 line is a few hundred bytes; a value far larger than that is a
// client trying to bloat the log rather than authenticate.
const logLimit = 4096

// protocolSMB2 and protocolSMB1 are the four-byte markers that begin every
// message of each version. The client's first packet may be either.
var (
	protocolSMB2 = [4]byte{0xFE, 'S', 'M', 'B'}
	protocolSMB1 = [4]byte{0xFF, 'S', 'M', 'B'}
)

type Service struct {
	addr string

	// computerName and domainName are what this "server" calls itself. They go
	// into the NTLM challenge's target-info block, which the client copies into
	// the material it hashes — so they are part of the disguise and worth
	// matching to the device persona. A NAS on 445 named DISKSTATION should say
	// DISKSTATION here too.
	computerName string
	domainName   string
	dnsName      string

	// serverGUID identifies this server in the negotiate response. Generated
	// once and kept for the process: a GUID that changed per connection is not
	// what a real server looks like to anything that connects twice.
	serverGUID [16]byte
}

// New builds the decoy. computerName and domainName shape what the server calls
// itself; empty values fall back to something a small file server would
// plausibly report.
func New(addr, computerName, domainName string) *Service {
	if computerName == "" {
		computerName = "FILESERVER"
	}
	if domainName == "" {
		domainName = "WORKGROUP"
	}

	s := &Service{
		addr:         addr,
		computerName: computerName,
		domainName:   domainName,
		dnsName:      "",
	}
	// A stable but not-obviously-patterned GUID. Derived rather than random so
	// it survives a restart; see the persona and TLS certificates for why a
	// value that changes on every restart is a honeypot fingerprint.
	guid := stableBytes(computerName+domainName, 16)
	copy(s.serverGUID[:], guid)
	// RFC 4122 version/variant nibbles, so anything that inspects it as a UUID
	// sees a well-formed one.
	s.serverGUID[6] = (s.serverGUID[6] & 0x0F) | 0x40
	s.serverGUID[8] = (s.serverGUID[8] & 0x3F) | 0x80
	return s
}

func (s *Service) Name() string { return name }
func (s *Service) Addr() string { return s.addr }

func (s *Service) Serve(ctx context.Context, ln net.Listener, emit event.Emitter) error {
	return service.Accept(ctx, ln, func(c net.Conn) { s.handle(c, emit) })
}

// header is the parsed SMB2 sync header. Only the fields the decoy acts on are
// kept; the rest of the 64 bytes are read past.
type header struct {
	command   uint16
	messageID uint64
	sessionID uint64
	treeID    uint32
	creditReq uint16
}

// conn is the per-connection state. NTLM spans two session-setup round trips,
// and the fixed challenge issued in the first has to be remembered to make
// sense of the response in the second — though here it is a constant, kept as
// state so the code reads the way the protocol works.
type conn struct {
	net.Conn
	svc  *Service
	emit event.Emitter

	challenge [8]byte
	// captured is set once a hash has been logged, so a client that retries
	// authentication on the same connection does not produce a page of
	// identical events.
	captured bool
	spoke    bool
}

func (s *Service) handle(nc net.Conn, emit event.Emitter) {
	c := &conn{Conn: nc, svc: s, emit: emit}
	c.challenge = ntlm.FixedChallenge

	// A connection on which nothing was ever said is a bare port touch — a
	// scan — and worth exactly one event. A client that speaks produces its own
	// more specific events instead.
	defer func() {
		if !c.spoke {
			emit.Emit(event.New(name, "connection", nc.RemoteAddr(), nc.LocalAddr()))
		}
	}()

	for {
		msg, err := readTransport(nc)
		if err != nil {
			return
		}
		if !c.dispatch(msg) {
			return
		}
	}
}

// dispatch routes one transport message. It returns false when the connection
// should close.
func (c *conn) dispatch(msg []byte) bool {
	if len(msg) < 4 {
		return false
	}

	var marker [4]byte
	copy(marker[:], msg[:4])

	switch marker {
	case protocolSMB1:
		// A legacy multi-protocol negotiate. The only thing worth doing with it
		// is steering the client up to SMB2, after which everything else here
		// applies.
		c.spoke = true
		return c.handleSMB1Negotiate(msg)

	case protocolSMB2:
		return c.handleSMB2(msg)

	default:
		// Not SMB at all. A scanner throwing bytes at 445 gets nothing back,
		// which is what a real server does with a malformed first packet.
		return false
	}
}

// handleSMB2 parses the SMB2 header and dispatches on the command. It walks a
// compound (chained) request, because a client is allowed to pack session setup
// behind other commands, and answers each with its own message.
func (c *conn) handleSMB2(msg []byte) bool {
	c.spoke = true

	if len(msg) < smbHeaderSize {
		return false
	}

	h, ok := parseHeader(msg)
	if !ok {
		return false
	}

	switch h.command {
	case cmdNegotiate:
		return c.writeMessage(h, statusSuccess, c.negotiateResponse(msg))

	case cmdSessionSetup:
		return c.sessionSetup(h, msg)

	case cmdLogoff:
		return c.writeMessage(h, statusSuccess, logoffResponse())

	case cmdTreeConnect:
		// Reaching tree connect means the client believes it authenticated,
		// which against this decoy it never did. Refusing keeps the state
		// machine honest: nothing past the handshake is real.
		return c.writeMessage(h, statusAccessDenied, errorResponse())

	default:
		// Any other command needs a session this decoy never grants.
		return c.writeMessage(h, statusAccessDenied, errorResponse())
	}
}

func parseHeader(msg []byte) (header, bool) {
	if len(msg) < smbHeaderSize {
		return header{}, false
	}
	if binary.LittleEndian.Uint16(msg[4:6]) != smbHeaderSize {
		// StructureSize is always 64. A wrong value is a malformed or non-SMB2
		// packet.
		return header{}, false
	}

	return header{
		command:   binary.LittleEndian.Uint16(msg[12:14]),
		creditReq: binary.LittleEndian.Uint16(msg[14:16]),
		messageID: binary.LittleEndian.Uint64(msg[24:32]),
		treeID:    binary.LittleEndian.Uint32(msg[36:40]),
		sessionID: binary.LittleEndian.Uint64(msg[40:48]),
	}, true
}

// readTransport reads one message off the direct-TCP transport used on 445: a
// four-byte prefix whose first byte is zero and whose remaining three are the
// big-endian length of the SMB message that follows.
func readTransport(r io.Reader) ([]byte, error) {
	var prefix [4]byte
	if _, err := io.ReadFull(r, prefix[:]); err != nil {
		return nil, err
	}

	// The high byte is a message type that is always zero for SMB over TCP.
	// Only the low 24 bits are length, which is also why maxMessage cannot be
	// exceeded here even by a hostile prefix.
	length := int(prefix[1])<<16 | int(prefix[2])<<8 | int(prefix[3])
	if length == 0 || length > maxMessage {
		return nil, errBadLength
	}

	msg := make([]byte, length)
	if _, err := io.ReadFull(r, msg); err != nil {
		return nil, err
	}
	return msg, nil
}

// writeMessage frames an SMB2 response: the sync header echoing the request's
// ids, then the body, behind the transport length prefix.
func (c *conn) writeMessage(reqHdr header, status uint32, body []byte) bool {
	hdr := buildResponseHeader(reqHdr, status)
	msg := append(hdr, body...)

	if len(msg) > maxMessage {
		return false
	}

	var frame [4]byte
	frame[0] = 0
	frame[1] = byte(len(msg) >> 16)
	frame[2] = byte(len(msg) >> 8)
	frame[3] = byte(len(msg))

	if _, err := c.Write(append(frame[:], msg...)); err != nil {
		return false
	}
	return true
}

// buildResponseHeader writes the 64-byte sync header for a response, echoing
// the request's command, message id, session id and tree id, and setting the
// server-to-redir flag every response carries.
func buildResponseHeader(req header, status uint32) []byte {
	h := make([]byte, smbHeaderSize)
	copy(h[0:4], protocolSMB2[:])
	binary.LittleEndian.PutUint16(h[4:6], smbHeaderSize)       // StructureSize
	binary.LittleEndian.PutUint16(h[6:8], 1)                   // CreditCharge
	binary.LittleEndian.PutUint32(h[8:12], status)             // Status
	binary.LittleEndian.PutUint16(h[12:14], req.command)       // Command
	binary.LittleEndian.PutUint16(h[14:16], grantCredits(req)) // CreditResponse
	binary.LittleEndian.PutUint32(h[16:20], 0x00000001)        // Flags: SERVER_TO_REDIR
	binary.LittleEndian.PutUint32(h[20:24], 0)                 // NextCommand
	binary.LittleEndian.PutUint64(h[24:32], req.messageID)     // MessageId
	binary.LittleEndian.PutUint32(h[32:36], 0xFEFF)            // Reserved (Windows uses 0xFEFF)
	binary.LittleEndian.PutUint32(h[36:40], req.treeID)        // TreeId
	binary.LittleEndian.PutUint64(h[40:48], req.sessionID)     // SessionId
	// Signature stays zero: this decoy never establishes the session key that
	// signing needs, and every response it sends is one a real server also
	// sends unsigned.
	return h
}

// grantCredits hands back at least one credit so a well-behaved client is never
// starved into stalling before it sends the message that carries the hash.
func grantCredits(req header) uint16 {
	if req.creditReq == 0 {
		return 1
	}
	return req.creditReq
}

// logoffResponse and errorResponse are the two fixed bodies the decoy sends
// besides negotiate and session setup.
func logoffResponse() []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint16(b[0:2], 4) // StructureSize
	return b
}

// errorResponse is the SMB2 error response body: StructureSize 9, then zeros.
// The status lives in the header; the body just has to be well-formed.
func errorResponse() []byte {
	b := make([]byte, 9)
	binary.LittleEndian.PutUint16(b[0:2], 9)
	return b
}
