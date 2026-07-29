// Package ntlm builds and reads the three NTLMSSP messages a decoy needs to
// capture a NetNTLMv2 hash: it issues a CHALLENGE and parses the AUTHENTICATE a
// client answers with, into a line hashcat can crack.
//
// It exists because two protocols want the same thing over different transports.
// The SMB decoy carries NTLM inside SMB2 session setup; the RDP decoy carries it
// inside CredSSP over TLS. The framing differs, but the NTLM challenge, the
// target-info block a modern client folds into its response, and the NetNTLMv2
// extraction are identical — so they live here, and both decoys wrap them.
//
// Choosing the challenge is the point. A NetNTLMv2 response is only crackable
// offline if whoever cracks it knows the challenge the client hashed against, so
// a decoy commits to one — [FixedChallenge], the value Responder uses, which
// every existing cracking workflow already expects — and records it beside the
// captured response.
package ntlm

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"time"
	"unicode/utf16"
)

// FixedChallenge is the 8-byte server challenge every handshake here is answered
// with. 1122334455667788 is the value Responder and Impacket's ntlmrelayx use,
// so a captured response drops straight into an existing workflow. Knowing the
// challenge does not help attack the server that issued it; the credential
// captured is the intruder's.
var FixedChallenge = [8]byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}

// NTLMSSP message types.
const (
	TypeNegotiate    = 1 // client → server
	TypeChallenge    = 2 // server → client (carries our challenge)
	TypeAuthenticate = 3 // client → server (carries the hash)
)

// ntlmSignature begins every NTLMSSP message.
var ntlmSignature = []byte("NTLMSSP\x00")

// Negotiate flags this package sets in a CHALLENGE. Names are from MS-NLMP.
const (
	flagUnicode     = 0x00000001
	flagRequestTgt  = 0x00000004
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

var le = binary.LittleEndian

// Identity is what the "server" calls itself in the challenge's target-info
// block, which the client copies into the material it hashes — so it is part of
// the disguise, and worth matching to the device persona.
type Identity struct {
	Computer string
	Domain   string
	DNS      string
}

// FindNTLMSSP locates the NTLM message inside a security buffer.
//
// That buffer is usually SPNEGO — GSS-API DER wrapping the NTLM token — and real
// clients vary enough in how they encode the wrapper that fully decoding it is
// more ways to fail than to succeed. The NTLM message begins with a fixed
// eight-byte signature, so finding it and parsing from there is what actually
// works against the range of tools a honeypot meets. It is transport-agnostic:
// SMB's session-setup buffer and CredSSP's negoToken both carry the token this
// way.
func FindNTLMSSP(buf []byte) []byte {
	i := bytes.Index(buf, ntlmSignature)
	if i < 0 {
		return nil
	}
	return buf[i:]
}

// MessageType reads the message type from an NTLM message.
func MessageType(msg []byte) (int, bool) {
	if len(msg) < 12 || !bytes.Equal(msg[:8], ntlmSignature) {
		return 0, false
	}
	return int(le.Uint32(msg[8:12])), true
}

// Challenge assembles an NTLMSSP CHALLENGE (type 2).
//
// It carries the fixed server challenge and the target-info block the client
// folds into its response, so both halves of what makes the eventual hash
// verifiable originate here.
func Challenge(id Identity, challenge [8]byte) []byte {
	targetName := utf16le(id.Domain)
	info := buildTargetInfo(id)

	flags := uint32(flagUnicode | flagRequestTgt | flagNTLM | flagAlwaysSign |
		flagTargetSrv | flagExtendedSec | flagTargetInfo | flagVersion | flag128 | flag56)

	const fixed = 56 // header including the 8-byte Version field
	nameOffset := fixed
	infoOffset := fixed + len(targetName)

	w := &buf{}
	w.raw(ntlmSignature)
	w.u32(TypeChallenge)
	w.u16(uint16(len(targetName)))
	w.u16(uint16(len(targetName)))
	w.u32(uint32(nameOffset))
	w.u32(flags)
	w.raw(challenge[:])
	w.zeros(8) // Reserved
	w.u16(uint16(len(info)))
	w.u16(uint16(len(info)))
	w.u32(uint32(infoOffset))
	w.raw(ntlmVersion())
	w.raw(targetName)
	w.raw(info)
	return w.bytes()
}

// buildTargetInfo builds the AV-pair block a modern client requires to compute an
// NTLMv2 response, with the names that say what this server claims to be.
func buildTargetInfo(id Identity) []byte {
	dnsComputer := id.Computer
	dnsDomain := id.Domain
	if id.DNS != "" {
		dnsComputer = id.Computer + "." + id.DNS
		dnsDomain = id.DNS
	}

	w := &buf{}
	avPair(w, avNbDomain, utf16le(id.Domain))
	avPair(w, avNbComputer, utf16le(id.Computer))
	avPair(w, avDnsDomain, utf16le(dnsDomain))
	avPair(w, avDnsComputer, utf16le(dnsComputer))
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

// Credential is what ParseAuthenticate pulls out of an AUTHENTICATE message.
type Credential struct {
	User        string
	Domain      string
	Workstation string
	Version     int    // 1 or 2
	Hashcat     string // the crackable line, ready to paste
}

// HashcatMode reports the hashcat mode for the captured version: 5600 for
// NetNTLMv2, 5500 for NetNTLMv1.
func (c Credential) HashcatMode() int {
	switch c.Version {
	case 2:
		return 5600
	case 1:
		return 5500
	default:
		return 0
	}
}

// ParseAuthenticate reads an NTLMSSP AUTHENTICATE (type 3) and extracts the
// account and the crackable response. Every field is a length/offset pair
// pointing elsewhere in the same message, all from a stranger, so each is read
// bounds-checked and a bad pointer yields an empty field rather than a panic.
func ParseAuthenticate(msg []byte, challenge [8]byte) (Credential, bool) {
	if len(msg) < 64 {
		return Credential{}, false
	}

	lmResp := field(msg, 12)
	ntResp := field(msg, 20)
	domain := field(msg, 28)
	user := field(msg, 36)
	workstation := field(msg, 44)

	cred := Credential{
		User:        fromUTF16le(user),
		Domain:      fromUTF16le(domain),
		Workstation: fromUTF16le(workstation),
	}

	// An NTLMv2 NT response is a 16-byte proof followed by the client's blob;
	// anything longer than 24 bytes is v2. Exactly 24 is the legacy v1 response.
	switch {
	case len(ntResp) > 24:
		cred.Version = 2
		cred.Hashcat = formatNetNTLMv2(cred.User, cred.Domain, challenge, ntResp)
	case len(ntResp) == 24 && len(lmResp) == 24:
		cred.Version = 1
		cred.Hashcat = formatNetNTLMv1(cred.User, cred.Domain, challenge, lmResp, ntResp)
	default:
		// No usable NT part — an anonymous or malformed bind. The account name is
		// still worth having.
		return cred, cred.User != ""
	}
	return cred, true
}

// field reads the length/offset descriptor at pos — Len(2), MaxLen(2), Offset(4)
// — and returns the bytes it points at.
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

// nowFiletime is the current time as a Windows FILETIME: 100-nanosecond
// intervals since 1601. A client that supports the timestamp AV-pair echoes it
// into its response, and a zero here would be a tell.
func nowFiletime() uint64 {
	const epochDiff = 116444736000000000 // 100-ns intervals from 1601 to 1970
	return uint64(time.Now().UnixNano()/100) + epochDiff
}

// buf is a tiny growable little-endian writer.
type buf struct{ b []byte }

func (w *buf) u8(v byte)     { w.b = append(w.b, v) }
func (w *buf) u16(v uint16)  { w.b = le.AppendUint16(w.b, v) }
func (w *buf) u32(v uint32)  { w.b = le.AppendUint32(w.b, v) }
func (w *buf) u64(v uint64)  { w.b = le.AppendUint64(w.b, v) }
func (w *buf) raw(p []byte)  { w.b = append(w.b, p...) }
func (w *buf) zeros(n int)   { w.b = append(w.b, make([]byte, n)...) }
func (w *buf) bytes() []byte { return w.b }

// utf16le encodes a string the way every name in NTLM travels.
func utf16le(s string) []byte {
	units := utf16.Encode([]rune(s))
	out := make([]byte, len(units)*2)
	for i, u := range units {
		le.PutUint16(out[i*2:], u)
	}
	return out
}

// fromUTF16le decodes a UTF-16LE string, tolerating an odd trailing byte rather
// than rejecting the whole field — a captured username with one byte lopped off
// is still worth logging.
func fromUTF16le(b []byte) string {
	n := len(b) / 2
	units := make([]uint16, n)
	for i := 0; i < n; i++ {
		units[i] = le.Uint16(b[i*2:])
	}
	return string(utf16.Decode(units))
}

// sliceField reads a Len/Offset pair bounds-checked against the whole message;
// an offset that runs off the end yields nothing rather than a panic.
func sliceField(msg []byte, length, offset int) []byte {
	if length <= 0 || offset < 0 || offset+length > len(msg) {
		return nil
	}
	return msg[offset : offset+length]
}
