package smbsvc

import (
	"github.com/willysnow/wisp/internal/event"
)

// sessionSetup drives the two-step NTLM handshake.
//
// The client's first session setup carries an NTLMSSP NEGOTIATE, which the
// decoy answers with a CHALLENGE and the status that means "not done, keep
// going". The client's second carries the AUTHENTICATE — the message with the
// crackable response in it — which the decoy records and then refuses. There is
// no third step: authentication never succeeds here, so there is nothing after
// the refusal.
func (c *conn) sessionSetup(h header, msg []byte) bool {
	security := sessionSetupSecurity(msg)
	ntlm := findNTLMSSP(security)
	if ntlm == nil {
		// A session setup with no NTLM token — a Kerberos attempt, or an
		// anonymous bind. Nothing crackable is coming, so refuse and let the
		// client decide what to do next.
		return c.writeMessage(h, statusLogonFailure, sessionSetupResponse(spnegoReject()))
	}

	kind, ok := ntlmType(ntlm)
	if !ok {
		return c.writeMessage(h, statusLogonFailure, sessionSetupResponse(spnegoReject()))
	}

	switch kind {
	case ntlmNegotiate:
		// Issue the challenge. The session id is invented here and echoed by
		// the client on its next message; its value does not matter because no
		// real session is ever keyed to it.
		challenge := c.svc.buildChallenge(c.challenge)
		body := sessionSetupResponse(spnegoChallenge(challenge))

		resp := h
		if resp.sessionID == 0 {
			resp.sessionID = inventedSessionID
		}
		return c.writeMessage(resp, statusMoreProcessingReq, body)

	case ntlmAuthenticate:
		c.capture(ntlm)
		// Always refused. A locked door invites the next key, which is how a
		// single scan turns into a list of every credential the intruder
		// tried.
		return c.writeMessage(h, statusLogonFailure, sessionSetupResponse(spnegoReject()))

	default:
		return c.writeMessage(h, statusLogonFailure, sessionSetupResponse(spnegoReject()))
	}
}

// capture records the credential from an AUTHENTICATE message.
//
// Only the first per connection is emitted. A client that fails and retries —
// which is exactly what a password sprayer does — would otherwise turn one
// visitor into a page of near-identical events, and the rate limiter should not
// have to clean up after a decoy that volunteers the flood.
func (c *conn) capture(ntlm []byte) {
	if c.captured {
		return
	}

	cred, ok := parseAuthenticate(ntlm, c.challenge)
	if !ok {
		return
	}
	c.captured = true

	ev := event.New(name, "auth_attempt", c.RemoteAddr(), c.LocalAddr())
	ev.Data["username"] = cred.user
	if cred.domain != "" {
		ev.Data["domain"] = cred.domain
	}
	if cred.workstation != "" {
		ev.Data["workstation"] = cred.workstation
	}
	ev.Data["server_challenge"] = hexChallenge(c.challenge)

	switch cred.version {
	case 2:
		ev.Data["ntlm_version"] = "v2"
		ev.Data["netntlmv2"] = truncate(cred.hashcat)
		ev.Data["hashcat_mode"] = 5600
	case 1:
		ev.Data["ntlm_version"] = "v1"
		ev.Data["netntlmv1"] = truncate(cred.hashcat)
		ev.Data["hashcat_mode"] = 5500
	}

	c.emit.Emit(ev)
}

// sessionSetupSecurity extracts the security buffer from a SESSION_SETUP
// request using its own offset and length fields, bounds-checked against the
// message. The offset is measured from the start of the SMB2 header.
func sessionSetupSecurity(msg []byte) []byte {
	body := msg[smbHeaderSize:]
	if len(body) < 24 {
		return nil
	}
	// SESSION_SETUP request: SecurityBufferOffset at body+12, length at body+14.
	offset := int(le.Uint16(body[12:14]))
	length := int(le.Uint16(body[14:16]))
	return sliceField(msg, length, offset)
}

// sessionSetupResponse builds the SESSION_SETUP response body around a security
// buffer. StructureSize is 9, and the buffer follows the fixed part.
func sessionSetupResponse(security []byte) []byte {
	const fixed = 8 // the response's fixed part
	offset := smbHeaderSize + fixed

	w := &buf{}
	w.u16(9) // StructureSize (8 fixed + 1)
	w.u16(0) // SessionFlags
	w.u16(uint16(offset))
	w.u16(uint16(len(security)))
	w.raw(security)
	return w.bytes()
}

// inventedSessionID is handed to a client mid-handshake so it has something to
// echo. It is never keyed to anything, because no session is ever established.
const inventedSessionID = 0x0000000100000009

func hexChallenge(c [8]byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 16)
	for i, b := range c {
		out[i*2] = digits[b>>4]
		out[i*2+1] = digits[b&0x0F]
	}
	return string(out)
}
