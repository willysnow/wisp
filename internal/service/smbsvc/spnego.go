package smbsvc

// SPNEGO/GSS-API token construction.
//
// Only the outbound direction is built here — the negotiate response's advert
// and the challenge wrapper. Inbound SPNEGO is not decoded at all: the NTLM
// message inside it is found by its signature (see findNTLMSSP), because the
// range of DER a real client emits is wider than it is worth parsing, and none
// of the wrapper's contents matter to a decoy that only wants the NTLM token.

// Object identifiers, DER-encoded (the value bytes, without tag or length).
var (
	oidSPNEGO  = []byte{0x2b, 0x06, 0x01, 0x05, 0x05, 0x02}                         // 1.3.6.1.5.5.2
	oidNTLMSSP = []byte{0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a} // 1.3.6.1.4.1.311.2.2.10
)

// spnegoNegTokenInit is the security buffer in the negotiate response.
//
// It advertises exactly one mechanism, NTLMSSP. A real domain server also
// offers Kerberos, but offering it here would only invite a client holding a
// ticket to try Kerberos and give up when it fails — and Kerberos hands over
// nothing crackable. Advertising NTLM alone routes every client straight to the
// handshake that does.
func spnegoNegTokenInit() []byte {
	mechType := der(0x06, oidNTLMSSP) // MechType (OID)
	mechList := der(0x30, mechType)   // MechTypeList SEQUENCE OF
	mechTypes := der(0xA0, mechList)  // mechTypes [0]
	negInit := der(0x30, mechTypes)   // NegTokenInit SEQUENCE
	negToken := der(0xA0, negInit)    // NegotiationToken [0]

	inner := append(der(0x06, oidSPNEGO), negToken...)
	return der(0x60, inner) // [APPLICATION 0] GSS-API InitialContextToken
}

// spnegoChallenge wraps an NTLMSSP CHALLENGE in a SPNEGO NegTokenResp — a
// continuation token, so no GSS-API application wrapper, tagged [1].
func spnegoChallenge(ntlm []byte) []byte {
	negState := der(0xA0, der(0x0A, []byte{0x01})) // [0] negState: accept-incomplete
	supported := der(0xA1, der(0x06, oidNTLMSSP))  // [1] supportedMech
	response := der(0xA2, der(0x04, ntlm))         // [2] responseToken

	seq := der(0x30, concat(negState, supported, response))
	return der(0xA1, seq) // NegotiationToken [1]
}

// spnegoReject is the security buffer sent with a failed authentication: a
// NegTokenResp whose negState says reject. A client reads it as "that
// credential was refused", which is precisely the message a locked server
// sends and precisely what keeps the intruder trying another one.
func spnegoReject() []byte {
	negState := der(0xA0, der(0x0A, []byte{0x02})) // [0] negState: reject
	seq := der(0x30, negState)
	return der(0xA1, seq)
}

// der wraps content in a DER tag/length/value. Lengths are encoded in the
// short form under 128 and the minimal long form above it, which covers every
// token this file builds.
func der(tag byte, content []byte) []byte {
	out := []byte{tag}
	out = append(out, derLen(len(content))...)
	return append(out, content...)
}

func derLen(n int) []byte {
	switch {
	case n < 0x80:
		return []byte{byte(n)}
	case n < 0x100:
		return []byte{0x81, byte(n)}
	default:
		return []byte{0x82, byte(n >> 8), byte(n)}
	}
}

func concat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}
