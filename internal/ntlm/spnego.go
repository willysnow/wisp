package ntlm

// SPNEGO/GSS-API token construction, and the DER primitives it and CredSSP share.
//
// Only the outbound direction is built here — the mechanism advertisement and
// the challenge/reject wrappers. Inbound SPNEGO is not decoded: the NTLM message
// inside it is found by its signature (see FindNTLMSSP), because the range of DER
// a real client emits is wider than it is worth parsing, and none of the
// wrapper's contents matter to a decoy that only wants the NTLM token.

// Object identifiers, DER-encoded (the value bytes, without tag or length).
var (
	oidSPNEGO  = []byte{0x2b, 0x06, 0x01, 0x05, 0x05, 0x02}                         // 1.3.6.1.5.5.2
	oidNTLMSSP = []byte{0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a} // 1.3.6.1.4.1.311.2.2.10
)

// SPNEGONegTokenInit is the mechanism advertisement a server offers first.
//
// It advertises exactly one mechanism, NTLMSSP. A real domain server also offers
// Kerberos, but offering it here would only invite a client holding a ticket to
// try Kerberos and give up when it fails — and Kerberos hands over nothing
// crackable. Advertising NTLM alone routes every client straight to the
// handshake that does.
func SPNEGONegTokenInit() []byte {
	mechType := DER(0x06, oidNTLMSSP) // MechType (OID)
	mechList := DER(0x30, mechType)   // MechTypeList SEQUENCE OF
	mechTypes := DER(0xA0, mechList)  // mechTypes [0]
	negInit := DER(0x30, mechTypes)   // NegTokenInit SEQUENCE
	negToken := DER(0xA0, negInit)    // NegotiationToken [0]

	inner := append(DER(0x06, oidSPNEGO), negToken...)
	return DER(0x60, inner) // [APPLICATION 0] GSS-API InitialContextToken
}

// SPNEGOChallenge wraps an NTLMSSP CHALLENGE in a SPNEGO NegTokenResp — a
// continuation token, so no GSS-API application wrapper, tagged [1].
func SPNEGOChallenge(ntlm []byte) []byte {
	negState := DER(0xA0, DER(0x0A, []byte{0x01})) // [0] negState: accept-incomplete
	supported := DER(0xA1, DER(0x06, oidNTLMSSP))  // [1] supportedMech
	response := DER(0xA2, DER(0x04, ntlm))         // [2] responseToken

	seq := DER(0x30, Concat(negState, supported, response))
	return DER(0xA1, seq) // NegotiationToken [1]
}

// SPNEGOReject is the token sent with a failed authentication: a NegTokenResp
// whose negState says reject. A client reads it as "that credential was refused",
// which keeps the intruder trying another one.
func SPNEGOReject() []byte {
	negState := DER(0xA0, DER(0x0A, []byte{0x02})) // [0] negState: reject
	seq := DER(0x30, negState)
	return DER(0xA1, seq)
}

// DER wraps content in a tag/length/value. Lengths use the short form under 128
// and the minimal long form above it, which covers every token built here and in
// CredSSP.
func DER(tag byte, content []byte) []byte {
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

// Concat joins byte slices, the shape DER building leans on.
func Concat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}
