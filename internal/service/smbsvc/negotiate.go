package smbsvc

import (
	"time"
)

// SMB2 dialect revisions, lowest to highest. The server picks one the client
// offered; the choice barely matters here because the credential capture
// happens in session setup, which is identical across all of them — but picking
// a modern one keeps a modern file server from looking like a decade-old one.
const (
	dialect202  = 0x0202
	dialect210  = 0x0210
	dialect300  = 0x0300
	dialect302  = 0x0302
	dialect311  = 0x0311
	dialectWild = 0x02FF // the "send me a real SMB2 negotiate" wildcard
)

// SMB2 negotiate context types (3.1.1 only).
const (
	ctxPreauthIntegrity = 0x0001
	ctxEncryption       = 0x0002
)

// handleSMB1Negotiate answers a legacy multi-protocol negotiate by steering the
// client up to SMB2.
//
// Windows and every serious tool still open with an SMB1 negotiate that lists
// SMB2 dialects, purely to discover what the server speaks. The right answer is
// an SMB2 negotiate response carrying the wildcard dialect, which means "I speak
// SMB2, ask me again in it" — after which the client sends a real SMB2
// negotiate and the rest of this file takes over. The decoy never actually
// speaks SMB1, which is correct: SMB1 is disabled on anything worth imitating in
// 2026.
func (c *conn) handleSMB1Negotiate(msg []byte) bool {
	// Only an SMB1 NEGOTIATE (command 0x72) is worth answering. Anything else in
	// SMB1 is a client that thinks it has a session, which it does not.
	if len(msg) < 5 || msg[4] != 0x72 {
		return false
	}

	synthetic := header{command: cmdNegotiate, messageID: 0, creditReq: 1}
	return c.writeMessage(synthetic, statusSuccess, c.buildNegotiate(dialectWild, false))
}

// negotiateResponse parses an SMB2 negotiate request and builds the response
// selecting a dialect the client offered.
func (c *conn) negotiateResponse(msg []byte) []byte {
	dialect := c.pickDialect(msg)
	return c.buildNegotiate(dialect, dialect == dialect311)
}

// pickDialect reads the client's offered dialect list and chooses the best one
// this decoy supports. A malformed or empty list falls back to 2.1, which every
// client understands.
func (c *conn) pickDialect(msg []byte) uint16 {
	body := msg[smbHeaderSize:]
	if len(body) < 4 {
		return dialect210
	}

	count := int(le.Uint16(body[2:4]))
	// Dialects begin at body offset 36. A client cannot offer more than a
	// handful, so an absurd count is a malformed packet rather than a real one.
	const dialectsAt = 36
	if count <= 0 || count > 64 || len(body) < dialectsAt+count*2 {
		return dialect210
	}

	best := uint16(0)
	for i := 0; i < count; i++ {
		d := le.Uint16(body[dialectsAt+i*2:])
		if c.supported(d) && d > best {
			best = d
		}
	}
	if best == 0 {
		return dialect210
	}
	return best
}

func (c *conn) supported(d uint16) bool {
	switch d {
	case dialect202, dialect210, dialect300, dialect302, dialect311:
		return true
	}
	return false
}

// buildNegotiate lays out the SMB2 NEGOTIATE response body.
//
// The security buffer is the part that matters: it carries a SPNEGO token
// advertising NTLMSSP and nothing else, so a client with a Kerberos ticket it
// cannot use here falls straight through to NTLM — which is the mechanism whose
// handshake hands over a crackable hash.
func (c *conn) buildNegotiate(dialect uint16, contexts bool) []byte {
	security := spnegoNegTokenInit()

	w := &buf{}
	w.u16(65)      // StructureSize (64 fixed + 1)
	w.u16(0x0001)  // SecurityMode: SIGNING_ENABLED, not required
	w.u16(dialect) // DialectRevision
	if contexts {
		w.u16(2) // NegotiateContextCount
	} else {
		w.u16(0) // Reserved
	}
	w.raw(c.svc.serverGUID[:]) // ServerGuid
	w.u32(0x00000004)          // Capabilities: LARGE_MTU
	w.u32(0x00800000)          // MaxTransactSize
	w.u32(0x00800000)          // MaxReadSize
	w.u32(0x00800000)          // MaxWriteSize
	w.u64(nowFiletime())       // SystemTime
	w.u64(0)                   // ServerStartTime

	// The security-buffer and context offsets are measured from the start of
	// the SMB2 header, so everything below is smbHeaderSize plus its position
	// in this body.
	const fixed = 64 // the negotiate response's fixed part
	secOffset := smbHeaderSize + fixed
	w.u16(uint16(secOffset))     // SecurityBufferOffset
	w.u16(uint16(len(security))) // SecurityBufferLength

	// NegotiateContextOffset: the contexts follow the security buffer, aligned
	// to 8 bytes. Left zero when there are none.
	ctxOffsetPos := w.len()
	w.u32(0) // patched below when contexts are present

	w.raw(security)

	if contexts {
		w.align(8)
		ctxOffset := smbHeaderSize + w.len()
		le.PutUint32(w.b[ctxOffsetPos:], uint32(ctxOffset))
		w.raw(preauthIntegrityContext())
		w.align(8)
		w.raw(encryptionContext())
	}

	return w.bytes()
}

// preauthIntegrityContext is required in a 3.1.1 negotiate response, or a strict
// client aborts. It only ever has to be offered: the preauth hash it commits to
// is checked once a session is signed, and this decoy fails authentication
// before any session exists, so the algorithm is announced and never used.
func preauthIntegrityContext() []byte {
	data := &buf{}
	data.u16(1)      // HashAlgorithmCount
	data.u16(32)     // SaltLength
	data.u16(0x0001) // SHA-512, the only defined algorithm
	data.raw(stableBytes("preauth-salt", 32))

	return negotiateContext(ctxPreauthIntegrity, data.bytes())
}

// encryptionContext advertises one cipher. Like the preauth context it is only
// declared: encryption turns on after authentication, which never succeeds.
func encryptionContext() []byte {
	data := &buf{}
	data.u16(1)      // CipherCount
	data.u16(0x0002) // AES-128-GCM

	return negotiateContext(ctxEncryption, data.bytes())
}

func negotiateContext(ctxType uint16, data []byte) []byte {
	w := &buf{}
	w.u16(ctxType)
	w.u16(uint16(len(data)))
	w.u32(0) // Reserved
	w.raw(data)
	return w.bytes()
}

// nowFiletime is the current time as a Windows FILETIME: 100-nanosecond
// intervals since 1601-01-01. A server that reported a zero or an obviously
// wrong time would be a tell.
func nowFiletime() uint64 {
	const epochDelta = 116444736000000000 // 1601→1970 in 100ns units
	return uint64(time.Now().UTC().UnixNano()/100) + epochDelta
}
