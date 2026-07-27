package mssqlsvc

import (
	"encoding/binary"
	"errors"
	"io"
	"strconv"
	"strings"
	"unicode/utf16"

	"github.com/willysnow/wisp/internal/service/httpdecoy"
)

var le = binary.LittleEndian

var errBadLength = errors.New("mssql: packet length out of range")

// TDS packet types. PRELOGIN and LOGIN7 are the client's two steps of the
// handshake; the server answers both with a tabular-result packet.
const (
	pktSQLBatch = 0x01
	pktLogin7   = 0x10
	pktSSPI     = 0x11
	pktPrelogin = 0x12
	pktReply    = 0x04
)

// TDS packet status flags. EOM marks the last packet of a message; a message
// larger than one packet sets it only on the final one.
const statusEOM = 0x01

// packetHeaderSize is the fixed 8-byte TDS packet header.
const packetHeaderSize = 8

// maxPacket caps one TDS packet. The 16-bit length field cannot express more,
// and a decoy that only reads a login has no use for a large one.
const maxPacket = 1 << 16

// maxMessage caps a message reassembled across packets, so a client cannot make
// the decoy accumulate unbounded memory from a stream of EOM-clear packets.
const maxMessage = 1 << 20

// PRELOGIN option tokens.
const (
	preloginVersion    = 0x00
	preloginEncryption = 0x01
	preloginInstOpt    = 0x02
	preloginMARS       = 0x04
	preloginTerminator = 0xFF
)

// PRELOGIN encryption negotiation values. The decoy answers NOT_SUP: it has no
// TLS to offer, and NOT_SUP is the clearest way to tell a willing client to send
// its LOGIN7 — and the password inside it — in the clear.
const (
	encryptOff    = 0x00
	encryptOn     = 0x01
	encryptNotSup = 0x02
	encryptReq    = 0x03
)

// buf is a little-endian writer for TDS tokens, with big-endian helpers for the
// PRELOGIN option table, which is the one place TDS is big-endian.
type buf struct{ b []byte }

func (w *buf) u8(v byte)      { w.b = append(w.b, v) }
func (w *buf) u16(v uint16)   { w.b = le.AppendUint16(w.b, v) }
func (w *buf) u16be(v uint16) { w.b = binary.BigEndian.AppendUint16(w.b, v) }
func (w *buf) u32(v uint32)   { w.b = le.AppendUint32(w.b, v) }
func (w *buf) u64(v uint64)   { w.b = le.AppendUint64(w.b, v) }
func (w *buf) raw(p []byte)   { w.b = append(w.b, p...) }
func (w *buf) bytes() []byte  { return w.b }

// readMessage reads one TDS message, concatenating packet payloads until the
// EOM flag is set. The message type is taken from the first packet.
func readMessage(r io.Reader) (msgType byte, payload []byte, err error) {
	var out []byte
	for {
		var hdr [packetHeaderSize]byte
		if _, err = io.ReadFull(r, hdr[:]); err != nil {
			return 0, nil, err
		}
		if len(out) == 0 {
			msgType = hdr[0]
		}
		status := hdr[1]
		length := int(hdr[2])<<8 | int(hdr[3]) // big-endian, includes the header
		if length < packetHeaderSize || length > maxPacket {
			return msgType, nil, errBadLength
		}
		body := make([]byte, length-packetHeaderSize)
		if _, err = io.ReadFull(r, body); err != nil {
			return msgType, nil, err
		}
		out = append(out, body...)
		if len(out) > maxMessage {
			return msgType, nil, errBadLength
		}
		if status&statusEOM != 0 {
			return msgType, out, nil
		}
	}
}

// writeMessage frames a payload as a single TDS packet with EOM set.
func writeMessage(w io.Writer, msgType byte, payload []byte) error {
	total := packetHeaderSize + len(payload)
	if total > maxPacket {
		return errBadLength
	}
	hdr := [packetHeaderSize]byte{
		msgType,
		statusEOM,
		byte(total >> 8), byte(total), // length, big-endian
		0, 0, // SPID
		1, // PacketID
		0, // Window
	}
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

// prelogin is what the decoy reads out of the client's PRELOGIN.
type prelogin struct {
	encryption byte
	haveEnc    bool
	instance   string
	version    []byte
}

// parsePrelogin walks the PRELOGIN option table. Each entry is a token, a
// 2-byte big-endian offset, and a 2-byte big-endian length, ending at a 0xFF
// terminator; the data lives at the offsets, measured from the start of the
// payload. Everything is bounds-checked because it all comes from a stranger.
func parsePrelogin(p []byte) prelogin {
	var pl prelogin
	i := 0
	for i < len(p) {
		token := p[i]
		if token == preloginTerminator {
			break
		}
		if i+5 > len(p) {
			break
		}
		off := int(p[i+1])<<8 | int(p[i+2])
		length := int(p[i+3])<<8 | int(p[i+4])
		i += 5

		data := slice(p, off, length)
		switch token {
		case preloginVersion:
			pl.version = data
		case preloginEncryption:
			if len(data) >= 1 {
				pl.encryption = data[0]
				pl.haveEnc = true
			}
		case preloginInstOpt:
			pl.instance = trimNul(string(data))
		}
	}
	return pl
}

// preloginResponse builds the server's PRELOGIN answer: its version, an
// ENCRYPTION value of NOT_SUP, and the two zero options a real server includes.
// The option table's offsets are computed from a fixed header of five bytes per
// option plus the terminator.
func preloginResponse(version [6]byte) []byte {
	opts := []struct {
		token byte
		data  []byte
	}{
		{preloginVersion, version[:]},
		{preloginEncryption, []byte{encryptNotSup}},
		{preloginInstOpt, []byte{0x00}},
		{preloginMARS, []byte{0x00}},
	}

	headerLen := len(opts)*5 + 1 // 5 bytes per option + terminator
	var table, data buf
	off := headerLen
	for _, o := range opts {
		table.u8(o.token)
		table.u16be(uint16(off))
		table.u16be(uint16(len(o.data)))
		off += len(o.data)
		data.raw(o.data)
	}
	table.u8(preloginTerminator)
	return append(table.bytes(), data.bytes()...)
}

// login is what the decoy pulls out of a LOGIN7 message.
type login struct {
	tdsMajor   byte
	hostname   string
	username   string
	password   string
	appName    string
	serverName string
	library    string
	database   string
	integrated bool
}

// parseLogin7 reads the LOGIN7 record. The fixed header is 36 bytes; then a
// block of (offset, length) descriptors — lengths in UTF-16 characters — points
// at the variable data later in the same message. Every descriptor comes from a
// stranger, so each read is bounds-checked and a bad pointer yields an empty
// field rather than a panic.
func parseLogin7(p []byte) (login, bool) {
	const fixed = 36
	const olBlock = 58 // the OffsetLength block, ClientID and SSPI included
	if len(p) < fixed+olBlock {
		return login{}, false
	}

	var l login
	l.tdsMajor = p[7] // TDSVersion is 4 bytes at offset 4; the major is its high byte

	str := func(ibPos int) string {
		off := int(le.Uint16(p[ibPos : ibPos+2]))
		cch := int(le.Uint16(p[ibPos+2 : ibPos+4]))
		return fromUTF16le(slice(p, off, cch*2))
	}

	l.hostname = str(fixed + 0)
	l.username = str(fixed + 4)
	// Password: same descriptor form, but the bytes are obfuscated.
	{
		off := int(le.Uint16(p[fixed+8 : fixed+10]))
		cch := int(le.Uint16(p[fixed+10 : fixed+12]))
		l.password = decodePassword(slice(p, off, cch*2))
	}
	l.appName = str(fixed + 12)
	l.serverName = str(fixed + 16)
	// fixed+20: ibExtension/unused — skipped.
	l.library = str(fixed + 24)
	// fixed+28: language — skipped.
	l.database = str(fixed + 32)
	// fixed+36..fixed+42: ClientID (6 bytes) — skipped.

	// SSPI: a non-zero length means the client is doing Windows/integrated auth
	// and carried an NTLM/SPNEGO blob instead of a password.
	cbSSPI := int(le.Uint16(p[fixed+44 : fixed+46]))
	cbSSPILong := int(le.Uint32(p[fixed+54 : fixed+58]))
	if cbSSPI == 0xFFFF {
		cbSSPI = cbSSPILong
	}
	l.integrated = cbSSPI > 0

	return l, true
}

// loginError builds the SQL Server login-failure response: an ERROR token
// (18456, the code for a failed login) followed by a DONE token. The status
// lives in the token; refusing here is what turns a scan into a list of every
// credential tried.
func loginError(username, serverName string, tdsMajor byte) []byte {
	var body buf
	body.u32(18456) // Number: login failed
	body.u8(1)      // State
	body.u8(14)     // Class (severity)
	writeUSVarchar(&body, "Login failed for user '"+sanitise(username)+"'.")
	writeBVarchar(&body, serverName)
	writeBVarchar(&body, "") // procedure name
	body.u32(1)              // line number

	var w buf
	w.u8(0xAA) // ERROR token
	w.u16(uint16(len(body.bytes())))
	w.raw(body.bytes())

	// DONE token: DONE_ERROR, no current command, zero row count. The row-count
	// field widened from 4 to 8 bytes in TDS 7.2, so a pre-7.2 client is
	// answered with the width it expects.
	w.u8(0xFD)
	w.u16(0x0002) // Status: DONE_ERROR
	w.u16(0x0000) // CurCmd
	if tdsMajor >= 0x72 {
		w.u64(0)
	} else {
		w.u32(0)
	}
	return w.bytes()
}

// writeUSVarchar writes a US_VARCHAR: a 2-byte character count then UTF-16LE.
func writeUSVarchar(w *buf, s string) {
	units := utf16.Encode([]rune(s))
	w.u16(uint16(len(units)))
	for _, u := range units {
		w.u16(u)
	}
}

// writeBVarchar writes a B_VARCHAR: a 1-byte character count then UTF-16LE.
func writeBVarchar(w *buf, s string) {
	units := utf16.Encode([]rune(s))
	if len(units) > 255 {
		units = units[:255]
	}
	w.u8(byte(len(units)))
	for _, u := range units {
		w.u16(u)
	}
}

// decodePassword reverses SQL Server's LOGIN7 password obfuscation: swap each
// byte's nibbles and XOR with 0xA5, then read the result as UTF-16LE. It is not
// encryption — it is trivially reversible — so what the decoy recovers is the
// cleartext password, not a hash to crack.
func decodePassword(b []byte) string {
	out := make([]byte, len(b))
	for i, c := range b {
		swapped := (c >> 4) | (c << 4)
		out[i] = swapped ^ 0xA5
	}
	return fromUTF16le(out)
}

// slice returns length bytes at offset, bounds-checked against the whole
// message; an offset that runs off the end yields nothing rather than a panic.
func slice(msg []byte, offset, length int) []byte {
	if length <= 0 || offset < 0 || offset+length > len(msg) {
		return nil
	}
	return msg[offset : offset+length]
}

// fromUTF16le decodes a UTF-16LE string, tolerating an odd trailing byte rather
// than rejecting the whole field.
func fromUTF16le(b []byte) string {
	n := len(b) / 2
	units := make([]uint16, n)
	for i := 0; i < n; i++ {
		units[i] = le.Uint16(b[i*2:])
	}
	return string(utf16.Decode(units))
}

// parseVersion turns a "major.minor.build" string into the 6-byte UL_VERSION +
// sub-build block a PRELOGIN response carries.
func parseVersion(s string) [6]byte {
	parts := strings.Split(s, ".")
	num := func(i int) int {
		if i < len(parts) {
			n, _ := strconv.Atoi(strings.TrimSpace(parts[i]))
			return n
		}
		return 0
	}
	major, minor, build := num(0), num(1), num(2)
	return [6]byte{
		byte(major), byte(minor),
		byte(build >> 8), byte(build), // build number, big-endian
		0, 0, // sub-build
	}
}

func trimNul(s string) string { return strings.TrimRight(s, "\x00") }

func truncate(s string) string { return httpdecoy.Truncate(s, logLimit) }

// sanitise keeps attacker-controlled text out of the decoy's own error message
// as anything but plain characters.
func sanitise(s string) string {
	s = truncate(s)
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
}
