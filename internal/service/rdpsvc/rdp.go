// Package rdpsvc emulates a Windows Remote Desktop server far enough to capture
// the one thing an intruder came to 3389 for: a NetNTLMv2 hash and the account
// that produced it.
//
// It captures at two depths. The X.224 negotiation that opens every session is
// in the clear, and a client volunteers the account it is about to try as a
// routing cookie — `mstshash=<username>` — so the targeted username is known
// before a credential is sent. Then the decoy selects CredSSP (Network Level
// Authentication), the modern default, and runs the handshake to its point of
// value: over TLS, CredSSP carries an NTLM exchange, so the server issues a
// challenge and the client answers with a NetNTLMv2 response keyed by the
// password:
//
//	rdp  auth_attempt  username=jsmith  domain=CORP
//	     netntlmv2=jsmith::CORP:1122334455667788:<NTproof>:<blob>  hashcat_mode=5600
//
// That is the identical artifact the SMB decoy captures, over a different
// transport — and it shares the code: the NTLM challenge and the NetNTLMv2
// extraction live in internal/ntlm, which both decoys wrap.
//
// Nothing is ever granted. The handshake stops at the AUTHENTICATE, before the
// public-key exchange a real success continues with, so no session is ever
// established.
package rdpsvc

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"

	"github.com/willysnow/wisp/internal/event"
	"github.com/willysnow/wisp/internal/ntlm"
	"github.com/willysnow/wisp/internal/service"
	"github.com/willysnow/wisp/internal/service/httpdecoy"
	"github.com/willysnow/wisp/internal/tlsutil"
)

const name = "rdp"

// logLimit bounds any single captured field before it reaches the event log.
const logLimit = 256

// maxPDU caps one TPKT frame, and maxCredSSP one CredSSP TSRequest. Both are
// tens to hundreds of bytes in practice; a larger one is not a real client.
const (
	maxPDU     = 4096
	maxCredSSP = 1 << 16
)

// credSSPVersion is the protocol version the decoy reports. 6 is current; the
// decoy stops at the NTLM AUTHENTICATE, before the version-sensitive public-key
// exchange, so it does not have to match the client exactly.
const credSSPVersion = 6

// TPKT and X.224 constants.
const (
	tpktVersion = 0x03
	x224CR      = 0xE0 // Connection Request
	x224CC      = 0xD0 // Connection Confirm
)

// RDP negotiation message types and the security protocols they carry.
const (
	negTypeRequest  = 0x01
	negTypeResponse = 0x02

	protoRDP      = 0x00000000
	protoSSL      = 0x00000001
	protoHybrid   = 0x00000002 // CredSSP / Network Level Authentication
	protoHybridEx = 0x00000008
)

var errNotRDP = errors.New("rdp: not a TPKT/X.224 connection request")

type Service struct {
	addr      string
	tlsConfig *tls.Config
	// identity is what this "server" calls itself in the NTLM challenge. A fixed,
	// plausible name rather than the sensor's own, so the decoy does not leak the
	// real host.
	identity ntlm.Identity
}

// New builds the decoy. cert and key back the TLS the CredSSP handshake runs
// inside; they are generated on first run if absent.
func New(addr, cert, key string) (*Service, error) {
	const commonName = "RDPSERVER"
	tlsCert, err := tlsutil.LoadOrCreate(cert, key, commonName, []string{commonName})
	if err != nil {
		return nil, err
	}
	return &Service{
		addr: addr,
		tlsConfig: &tls.Config{
			Certificates: []tls.Certificate{tlsCert},
			MinVersion:   tls.VersionTLS12,
		},
		identity: ntlm.Identity{Computer: commonName, Domain: "WORKGROUP"},
	}, nil
}

func (s *Service) Name() string { return name }
func (s *Service) Addr() string { return s.addr }

func (s *Service) Serve(ctx context.Context, ln net.Listener, emit event.Emitter) error {
	return service.Accept(ctx, ln, func(c net.Conn) { s.handle(c, emit) })
}

func (s *Service) handle(nc net.Conn, emit event.Emitter) {
	body, err := readTPKT(nc)
	if err != nil {
		emit.Emit(event.New(name, "connection", nc.RemoteAddr(), nc.LocalAddr()))
		return
	}
	cr, ok := parseConnectionRequest(body)
	if !ok {
		emit.Emit(event.New(name, "connection", nc.RemoteAddr(), nc.LocalAddr()))
		return
	}
	s.emitProbe(nc, cr, emit)

	// Answer the negotiation by selecting the strongest security offered.
	selected := selectProtocol(cr.requested)
	if _, err := nc.Write(buildConnectionConfirm(cr.srcRef, selected)); err != nil {
		return
	}
	// Only CredSSP carries the NTLM exchange that yields a hash. A client that
	// asked only for standard RDP or plain TLS is left at the negotiation — the
	// probe already recorded who it was.
	if selected != protoHybrid {
		return
	}

	// The client now drives a TLS handshake, then CredSSP inside it.
	tlsConn := tls.Server(nc, s.tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		return
	}
	s.credssp(tlsConn, cr, emit)
}

// emitProbe records the negotiation: the account named in the mstshash cookie and
// the security the client offered.
func (s *Service) emitProbe(nc net.Conn, cr connectionRequest, emit event.Emitter) {
	ev := event.New(name, "probe", nc.RemoteAddr(), nc.LocalAddr())
	if cr.username != "" {
		ev.Data["username"] = truncate(cr.username)
	}
	if names := protocolNames(cr.requested); names != "" {
		ev.Data["requested"] = names
	}
	ev.Data["nla"] = cr.requested&protoHybrid != 0 || cr.requested&protoHybridEx != 0
	emit.Emit(ev)
}

// credssp runs the CredSSP handshake to the AUTHENTICATE and captures the hash.
//
// The client's tokens are SPNEGO-wrapped NTLM, and — as in SMB — the NTLM message
// is found by its signature rather than by decoding the wrapper. So the only DER
// the decoy builds is the TSRequest that carries its challenge; everything
// inbound is located by FindNTLMSSP.
func (s *Service) credssp(conn net.Conn, cr connectionRequest, emit event.Emitter) {
	// TSRequest 1: the client's NTLM NEGOTIATE.
	req, err := readDER(conn)
	if err != nil {
		return
	}
	token := ntlm.FindNTLMSSP(req)
	if kind, ok := ntlm.MessageType(token); !ok || kind != ntlm.TypeNegotiate {
		// No NTLM to challenge — a Kerberos attempt, or not CredSSP at all.
		return
	}

	// Reply with the NTLM CHALLENGE, SPNEGO-wrapped, inside a TSRequest.
	challenge := ntlm.Challenge(s.identity, ntlm.FixedChallenge)
	if _, err := conn.Write(tsRequest(ntlm.SPNEGOChallenge(challenge))); err != nil {
		return
	}

	// TSRequest 3: the client's NTLM AUTHENTICATE — the crackable message.
	req, err = readDER(conn)
	if err != nil {
		return
	}
	cred, ok := ntlm.ParseAuthenticate(ntlm.FindNTLMSSP(req), ntlm.FixedChallenge)
	if !ok {
		return
	}
	s.capture(conn, cr, cred, emit)
	// Nothing is granted: the connection closes here, before the public-key
	// exchange a real success continues with.
}

// capture records the NetNTLMv2 credential from the AUTHENTICATE.
func (s *Service) capture(conn net.Conn, cr connectionRequest, cred ntlm.Credential, emit event.Emitter) {
	ev := event.New(name, "auth_attempt", conn.RemoteAddr(), conn.LocalAddr())
	ev.Data["username"] = truncate(cred.User)
	if cred.Domain != "" {
		ev.Data["domain"] = truncate(cred.Domain)
	}
	if cred.Workstation != "" {
		ev.Data["workstation"] = truncate(cred.Workstation)
	}
	// The account the client typed into its RDP window, when it differs from the
	// one it authenticated as.
	if cr.username != "" && cr.username != cred.User {
		ev.Data["mstshash"] = truncate(cr.username)
	}

	switch cred.Version {
	case 2:
		ev.Data["ntlm_version"] = "v2"
		ev.Data["netntlmv2"] = truncate(cred.Hashcat)
		ev.Data["hashcat_mode"] = cred.HashcatMode()
	case 1:
		ev.Data["ntlm_version"] = "v1"
		ev.Data["netntlmv1"] = truncate(cred.Hashcat)
		ev.Data["hashcat_mode"] = cred.HashcatMode()
	}
	emit.Emit(ev)
}

// connectionRequest is what the decoy pulls out of an X.224 Connection Request.
type connectionRequest struct {
	srcRef    uint16
	username  string
	requested uint32
}

// parseConnectionRequest reads the TPKT body: an X.224 CR, then an optional
// routing cookie and an RDP negotiation request.
func parseConnectionRequest(body []byte) (connectionRequest, bool) {
	if len(body) < 7 || body[1] != x224CR {
		return connectionRequest{}, false
	}
	cr := connectionRequest{srcRef: binary.BigEndian.Uint16(body[4:6])}

	variable := body[7:]
	if i := bytes.Index(variable, []byte("\r\n")); i >= 0 && bytes.HasPrefix(variable, []byte("Cookie:")) {
		cr.username = mstshash(string(variable[:i]))
		variable = variable[i+2:]
	}
	if len(variable) >= 8 && variable[0] == negTypeRequest {
		cr.requested = binary.LittleEndian.Uint32(variable[4:8])
	}
	return cr, true
}

func mstshash(cookie string) string {
	const marker = "mstshash="
	i := strings.Index(cookie, marker)
	if i < 0 {
		return ""
	}
	return strings.TrimSpace(cookie[i+len(marker):])
}

func selectProtocol(requested uint32) uint32 {
	switch {
	case requested&protoHybrid != 0:
		return protoHybrid
	case requested&protoSSL != 0:
		return protoSSL
	default:
		return protoRDP
	}
}

func protocolNames(mask uint32) string {
	var out []string
	if mask == protoRDP {
		out = append(out, "rdp")
	}
	if mask&protoSSL != 0 {
		out = append(out, "ssl")
	}
	if mask&protoHybrid != 0 {
		out = append(out, "hybrid")
	}
	if mask&protoHybridEx != 0 {
		out = append(out, "hybrid-ex")
	}
	return strings.Join(out, ",")
}

func readTPKT(r io.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	if hdr[0] != tpktVersion {
		return nil, errNotRDP
	}
	length := int(hdr[2])<<8 | int(hdr[3])
	if length < 5 || length > maxPDU {
		return nil, errNotRDP
	}
	body := make([]byte, length-4)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	return body, nil
}

func buildConnectionConfirm(clientSrcRef uint16, selected uint32) []byte {
	neg := make([]byte, 8)
	neg[0] = negTypeResponse
	binary.LittleEndian.PutUint16(neg[2:4], 8)
	binary.LittleEndian.PutUint32(neg[4:8], selected)

	x224 := make([]byte, 7)
	x224[0] = byte(6 + len(neg)) // length indicator
	x224[1] = x224CC
	binary.BigEndian.PutUint16(x224[2:4], clientSrcRef) // dst ref echoes client's src ref
	binary.BigEndian.PutUint16(x224[4:6], 0)            // src ref
	x224[6] = 0                                         // class
	x224 = append(x224, neg...)

	total := 4 + len(x224)
	frame := []byte{tpktVersion, 0x00, byte(total >> 8), byte(total)}
	return append(frame, x224...)
}

// tsRequest wraps a SPNEGO negoToken in a CredSSP TSRequest — the one DER
// structure the decoy builds. The rest of CredSSP it reads by finding the NTLM
// signature, so no DER decoder is needed.
//
//	TSRequest ::= SEQUENCE { version [0] INTEGER, negoTokens [1] NegoData }
//	NegoData  ::= SEQUENCE OF SEQUENCE { negoToken [0] OCTET STRING }
func tsRequest(negoToken []byte) []byte {
	version := ntlm.DER(0xA0, ntlm.DER(0x02, []byte{credSSPVersion}))
	token := ntlm.DER(0xA0, ntlm.DER(0x04, negoToken)) // [0] negoToken
	item := ntlm.DER(0x30, token)                      // NegoData item
	negoData := ntlm.DER(0x30, item)                   // SEQUENCE OF
	negoTokens := ntlm.DER(0xA1, negoData)             // [1] negoTokens
	return ntlm.DER(0x30, ntlm.Concat(version, negoTokens))
}

// readDER reads one complete DER element and returns its bytes, so the NTLM
// message inside a TSRequest can be found without decoding the structure.
func readDER(r io.Reader) ([]byte, error) {
	var head [2]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return nil, err
	}
	lengthByte := head[1]
	var lenBytes []byte
	var length int
	if lengthByte < 0x80 {
		length = int(lengthByte)
	} else {
		n := int(lengthByte & 0x7f)
		if n == 0 || n > 4 {
			return nil, errNotRDP
		}
		lenBytes = make([]byte, n)
		if _, err := io.ReadFull(r, lenBytes); err != nil {
			return nil, err
		}
		for _, b := range lenBytes {
			length = length<<8 | int(b)
		}
	}
	if length < 0 || length > maxCredSSP {
		return nil, errNotRDP
	}
	content := make([]byte, length)
	if _, err := io.ReadFull(r, content); err != nil {
		return nil, err
	}
	full := append([]byte{head[0], head[1]}, lenBytes...)
	return append(full, content...), nil
}

func truncate(s string) string { return httpdecoy.Truncate(s, logLimit) }
