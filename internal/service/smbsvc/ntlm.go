package smbsvc

import (
	"bytes"
	"encoding/hex"
)

// NTLMSSP message signature and message types.
var ntlmSignature = []byte("NTLMSSP\x00")

const (
	ntlmNegotiate    = 1 // type 1, client → server
	ntlmChallenge    = 2 // type 2, server → client (carries our challenge)
	ntlmAuthenticate = 3 // type 3, client → server (carries the hash)
)

// NTLMSSP negotiate flags, the subset this decoy sets or checks. The names are
// the ones in MS-NLMP.
const (
	flagUnicode     = 0x00000001
	flagRequestTgt  = 0x00000004
	flagSign        = 0x00000010
	flagNTLM        = 0x00000200
	flagAlwaysSign  = 0x00008000
	flagTargetSrv   = 0x00020000
	flagExtendedSec = 0x00080000
	flagTargetInfo  = 0x00800000
	flagVersion     = 0x02000000
	flag128         = 0x20000000
	flag56          = 0x80000000
)

// NTLMv2 target-info AV-pair ids.
const (
	avEOL         = 0x0000
	avNbComputer  = 0x0001
	avNbDomain    = 0x0002
	avDnsComputer = 0x0003
	avDnsDomain   = 0x0004
	avTimestamp   = 0x0007
)

// findNTLMSSP locates the NTLM message inside a session-setup security buffer.
//
// The buffer is SPNEGO — GSS-API DER wrapping the NTLM token — and real clients
// vary enough in how they encode that wrapper that fully decoding the ASN.1 is
// more ways to fail than to succeed. The NTLM message begins with a fixed
// eight-byte signature, so finding it and parsing from there is what actually
// works against the range of tools that reach a honeypot. The bytes before the
// signature are the SPNEGO framing, and none of them carry anything this decoy
// needs.
func findNTLMSSP(security []byte) []byte {
	i := bytes.Index(security, ntlmSignature)
	if i < 0 {
		return nil
	}
	return security[i:]
}

// ntlmType reads the message type from an NTLM message.
func ntlmType(ntlm []byte) (int, bool) {
	if len(ntlm) < 12 || !bytes.Equal(ntlm[:8], ntlmSignature) {
		return 0, false
	}
	return int(le.Uint32(ntlm[8:12])), true
}

// buildChallenge assembles an NTLMSSP CHALLENGE (type 2).
//
// This is the message that decides whether the credential the decoy captures is
// worth anything. It carries the fixed server challenge — the value a cracker
// has to know — and the target-info block the client folds into its response,
// so both halves of what makes the eventual hash verifiable originate here.
func (s *Service) buildChallenge(challenge [8]byte) []byte {
	targetName := utf16le(s.domainName)
	targetInfo := s.targetInfo()

	flags := uint32(flagUnicode | flagRequestTgt | flagNTLM | flagAlwaysSign |
		flagTargetSrv | flagExtendedSec | flagTargetInfo | flagVersion | flag128 | flag56)

	const fixed = 56 // header including the 8-byte Version field
	nameOffset := fixed
	infoOffset := fixed + len(targetName)

	w := &buf{}
	w.raw(ntlmSignature)
	w.u32(ntlmChallenge)
	// TargetNameFields
	w.u16(uint16(len(targetName)))
	w.u16(uint16(len(targetName)))
	w.u32(uint32(nameOffset))
	w.u32(flags)
	w.raw(challenge[:])
	w.zeros(8) // Reserved
	// TargetInfoFields
	w.u16(uint16(len(targetInfo)))
	w.u16(uint16(len(targetInfo)))
	w.u32(uint32(infoOffset))
	w.raw(ntlmVersion())
	w.raw(targetName)
	w.raw(targetInfo)
	return w.bytes()
}

// targetInfo builds the AV-pair block. A modern client requires it to compute an
// NTLMv2 response at all, and the names in it are part of the disguise: they say
// what this server claims to be, and they end up inside the material the client
// hashes.
func (s *Service) targetInfo() []byte {
	dnsComputer := s.computerName
	dnsDomain := s.domainName
	if s.dnsName != "" {
		dnsComputer = s.computerName + "." + s.dnsName
		dnsDomain = s.dnsName
	}

	w := &buf{}
	avPair(w, avNbDomain, utf16le(s.domainName))
	avPair(w, avNbComputer, utf16le(s.computerName))
	avPair(w, avDnsDomain, utf16le(dnsDomain))
	avPair(w, avDnsComputer, utf16le(dnsComputer))
	// Timestamp: a current FILETIME. A client that supports it will echo it into
	// its response, and a zero here would be an obvious tell.
	ts := &buf{}
	ts.u64(nowFiletime())
	avPair(w, avTimestamp, ts.bytes())
	avPair(w, avEOL, nil)
	return w.bytes()
}

func avPair(w *buf, id uint16, value []byte) {
	w.u16(id)
	w.u16(uint16(len(value)))
	w.raw(value)
}

// ntlmVersion is the 8-byte OS version block: 10.0.20348, NTLM revision 15. A
// server that advertises VERSION and then sends zeros would stand out.
func ntlmVersion() []byte {
	w := &buf{}
	w.u8(10)     // ProductMajorVersion
	w.u8(0)      // ProductMinorVersion
	w.u16(20348) // ProductBuild
	w.zeros(3)   // Reserved
	w.u8(0x0F)   // NTLMRevisionCurrent
	return w.bytes()
}

// credential is what the decoy pulls out of an NTLMSSP AUTHENTICATE message.
type credential struct {
	user        string
	domain      string
	workstation string
	version     int    // 1 or 2
	hashcat     string // the crackable line, ready to paste
}

// parseAuthenticate reads an NTLMSSP AUTHENTICATE (type 3) and extracts the
// account and the crackable response.
//
// Every field is a length/offset pair pointing elsewhere in the same message,
// and every one of them comes from a stranger, so each is read bounds-checked
// and a bad pointer yields an empty field rather than a panic.
func parseAuthenticate(ntlm []byte, challenge [8]byte) (credential, bool) {
	if len(ntlm) < 64 {
		return credential{}, false
	}

	lmResp := field(ntlm, 12)
	ntResp := field(ntlm, 20)
	domain := field(ntlm, 28)
	user := field(ntlm, 36)
	workstation := field(ntlm, 44)

	cred := credential{
		user:        truncate(fromUTF16le(user)),
		domain:      truncate(fromUTF16le(domain)),
		workstation: truncate(fromUTF16le(workstation)),
	}

	// An NTLMv2 NT response is the 16-byte proof followed by the client's
	// challenge blob; anything longer than 24 bytes is v2. Exactly 24 is the
	// legacy v1 response, which a downgrade attack or an ancient client still
	// produces.
	switch {
	case len(ntResp) > 24:
		cred.version = 2
		cred.hashcat = formatNetNTLMv2(cred.user, cred.domain, challenge, ntResp)
	case len(ntResp) == 24 && len(lmResp) == 24:
		cred.version = 1
		cred.hashcat = formatNetNTLMv1(cred.user, cred.domain, challenge, lmResp, ntResp)
	default:
		// A response with no usable NT part — an anonymous or malformed bind.
		// The account name is still worth having even without a hash.
		return cred, cred.user != ""
	}

	return cred, true
}

// field reads the length/offset descriptor at pos and returns the bytes it
// points at. NTLM descriptors are Len(2), MaxLen(2), Offset(4).
func field(msg []byte, pos int) []byte {
	if pos+8 > len(msg) {
		return nil
	}
	length := int(le.Uint16(msg[pos : pos+2]))
	offset := int(le.Uint32(msg[pos+4 : pos+8]))
	return sliceField(msg, length, offset)
}

// formatNetNTLMv2 renders hashcat mode 5600:
//
//	user::domain:serverchallenge:NTproofstr:blob
//
// NTproofstr is the first 16 bytes of the NT response; blob is the rest. Given
// those, a cracker computes NTOWFv2 from a guessed password and checks that
// HMAC-MD5(NTOWFv2, serverchallenge+blob) equals NTproofstr — which is exactly
// why the fixed challenge has to be recorded alongside it.
func formatNetNTLMv2(user, domain string, challenge [8]byte, ntResp []byte) string {
	proof := ntResp[:16]
	blob := ntResp[16:]
	return user + "::" + domain + ":" +
		hex.EncodeToString(challenge[:]) + ":" +
		hex.EncodeToString(proof) + ":" +
		hex.EncodeToString(blob)
}

// formatNetNTLMv1 renders hashcat mode 5500:
//
//	user::domain:LMresponse:NTresponse:serverchallenge
func formatNetNTLMv1(user, domain string, challenge [8]byte, lmResp, ntResp []byte) string {
	return user + "::" + domain + ":" +
		hex.EncodeToString(lmResp) + ":" +
		hex.EncodeToString(ntResp) + ":" +
		hex.EncodeToString(challenge[:])
}
