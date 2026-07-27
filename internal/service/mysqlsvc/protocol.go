package mysqlsvc

import (
	"encoding/binary"
	"encoding/hex"
	"io"
	"strings"

	"github.com/willysnow/wisp/internal/service/httpdecoy"
)

// le is a shorthand for the little-endian byte order MySQL uses throughout.
var le = binary.LittleEndian

// MySQL capability flags — the subset this decoy sets in its handshake or reads
// from the client's response. Names are the ones in the protocol manual.
const (
	capLongPassword     = 0x00000001
	capLongFlag         = 0x00000004
	capConnectWithDB    = 0x00000008
	capProtocol41       = 0x00000200
	capSSL              = 0x00000800
	capTransactions     = 0x00002000
	capSecureConnection = 0x00008000
	capPluginAuth       = 0x00080000
	capConnectAttrs     = 0x00100000
	capPluginAuthLenenc = 0x00200000
)

// serverCaps is what this "server" advertises. It deliberately omits capSSL: a
// server that never offers TLS is one a well-behaved client will speak to in
// the clear, which is the only way the password response reaches the decoy in a
// form it can turn into a hash. Everything here is what makes a modern client
// send a mysql_native_password response: PROTOCOL_41 and SECURE_CONNECTION give
// the 20-byte scramble form, PLUGIN_AUTH names the plugin, and CONNECT_ATTRS
// invites the client to volunteer its driver and program name.
const serverCaps = capLongPassword | capLongFlag | capConnectWithDB |
	capProtocol41 | capTransactions | capSecureConnection |
	capPluginAuth | capConnectAttrs | capPluginAuthLenenc

// nativePassword is the auth plugin the decoy advertises. It is the one whose
// response is a clean 20-byte value that cracks offline as hashcat mode 11200;
// caching_sha2_password — MySQL 8's default — needs TLS or an RSA exchange to
// carry the actual secret and yields nothing a wordlist can attack, so the decoy
// steers every client onto native, switching them if it has to.
const nativePassword = "mysql_native_password"

// charsetUTF8MB4 is utf8mb4_general_ci (collation 45). The exact value does not
// matter to the handshake; it only has to be a real one.
const charsetUTF8MB4 = 45

// statusAutocommit is the one server-status flag worth setting: a real server
// reports autocommit on by default.
const statusAutocommit = 0x0002

// maxPacket caps one MySQL packet. A handshake response is a few hundred bytes;
// anything far larger is a client trying to make the decoy allocate rather than
// authenticate. The 3-byte length field can express 16 MiB, so this also has to
// be enforced rather than assumed.
const maxPacket = 1 << 20

// buf is a tiny growable little-endian writer. The MySQL packets here are laid
// out by hand because their field order is the protocol.
type buf struct{ b []byte }

func (w *buf) u8(v byte)     { w.b = append(w.b, v) }
func (w *buf) u16(v uint16)  { w.b = le.AppendUint16(w.b, v) }
func (w *buf) u32(v uint32)  { w.b = le.AppendUint32(w.b, v) }
func (w *buf) raw(p []byte)  { w.b = append(w.b, p...) }
func (w *buf) zeros(n int)   { w.b = append(w.b, make([]byte, n)...) }
func (w *buf) bytes() []byte { return w.b }

// cstr writes a NUL-terminated string, the way names travel in the handshake.
func (w *buf) cstr(s string) {
	w.b = append(w.b, s...)
	w.b = append(w.b, 0)
}

// readPacket reads one MySQL packet: a 3-byte little-endian length, a 1-byte
// sequence id, then that many payload bytes. The sequence id is returned so a
// reply can be numbered to follow the request, which the protocol requires.
func readPacket(r io.Reader) (seq uint8, payload []byte, err error) {
	var hdr [4]byte
	if _, err = io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	length := int(hdr[0]) | int(hdr[1])<<8 | int(hdr[2])<<16
	seq = hdr[3]
	if length == 0 {
		return seq, nil, nil
	}
	if length > maxPacket {
		return seq, nil, errBadLength
	}
	payload = make([]byte, length)
	if _, err = io.ReadFull(r, payload); err != nil {
		return seq, nil, err
	}
	return seq, payload, nil
}

// writePacket frames a payload behind the 4-byte header.
func writePacket(w io.Writer, seq uint8, payload []byte) error {
	if len(payload) > maxPacket {
		return errBadLength
	}
	var hdr [4]byte
	hdr[0] = byte(len(payload))
	hdr[1] = byte(len(payload) >> 8)
	hdr[2] = byte(len(payload) >> 16)
	hdr[3] = seq
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

// handshake builds the Initial Handshake Packet (protocol version 10).
//
// The scramble it carries is the value the client hashes its password against,
// so recording it alongside the response the client sends back is what makes
// that response crackable offline — the same reason the SMB decoy commits to a
// fixed NTLM challenge and the MongoDB decoy keeps its SCRAM salt.
func (s *Service) handshake(scramble [20]byte, connID uint32) []byte {
	w := &buf{}
	w.u8(10) // protocol version
	w.cstr(s.version)
	w.u32(connID)
	w.raw(scramble[:8]) // auth-plugin-data-part-1
	w.u8(0)             // filler
	w.u16(uint16(serverCaps & 0xffff))
	w.u8(charsetUTF8MB4)
	w.u16(statusAutocommit)
	w.u16(uint16(serverCaps >> 16))
	w.u8(21)    // length of the whole auth-plugin-data (8 + 13)
	w.zeros(10) // reserved
	// auth-plugin-data-part-2: the remaining 12 scramble bytes plus a NUL, so
	// the client reads a full 20-byte scramble.
	w.raw(scramble[8:20])
	w.u8(0)
	w.cstr(nativePassword)
	return w.bytes()
}

// authSwitchRequest asks a client that did not already send a native-password
// response to send one now, against a fresh scramble. A real server issues this
// when its default plugin differs from what the client offered; here it is how
// the decoy pulls a crackable hash out of a caching_sha2 client.
func authSwitchRequest(scramble [20]byte) []byte {
	w := &buf{}
	w.u8(0xfe) // status: auth switch request
	w.cstr(nativePassword)
	w.raw(scramble[:20])
	w.u8(0)
	return w.bytes()
}

// errorPacket is the ERR packet the decoy always ends on: access denied, the
// answer a real server gives a wrong password. A locked door invites the next
// key, which is how one scan becomes a list of every credential tried.
func errorPacket(user, host string) []byte {
	w := &buf{}
	w.u8(0xff)
	w.u16(1045) // ER_ACCESS_DENIED_ERROR
	w.u8('#')
	w.raw([]byte("28000")) // SQLSTATE
	msg := "Access denied for user '" + sanitise(user) + "'@'" + sanitise(host) +
		"' (using password: YES)"
	w.raw([]byte(msg))
	return w.bytes()
}

// loginReq is what the decoy pulls out of a Handshake Response packet.
type loginReq struct {
	caps     uint32
	ssl      bool
	username string
	authResp []byte
	database string
	plugin   string
	attrs    map[string]string
}

// parseHandshakeResponse reads a Protocol::HandshakeResponse41. Every field
// past the fixed 32-byte prefix is variable-length and attacker-controlled, so
// each is bounds-checked and a short packet yields ok=false rather than a panic.
//
// A client that wants TLS sends only the 32-byte prefix first (an SSLRequest)
// with capSSL set; that is detected via the flag and reported by the caller,
// because this decoy has no TLS to offer it.
func parseHandshakeResponse(p []byte) (loginReq, bool) {
	if len(p) < 32 {
		return loginReq{}, false
	}
	r := loginReq{caps: le.Uint32(p[0:4])}
	r.ssl = r.caps&capSSL != 0
	if r.caps&capProtocol41 == 0 {
		// A pre-4.1 client. Nothing here speaks the old handshake, and no modern
		// scanner sends it.
		return r, false
	}
	// 4 caps, 4 max-packet, 1 charset, 23 reserved.
	pos := 32

	user, pos := readCString(p, pos)
	if pos < 0 {
		return r, false
	}
	r.username = user

	// The auth-response length is encoded three different ways depending on what
	// the client itself advertised.
	var ar []byte
	switch {
	case r.caps&capPluginAuthLenenc != 0:
		var n uint64
		n, pos = readLenencInt(p, pos)
		ar, pos = readN(p, pos, int(n))
	case r.caps&capSecureConnection != 0:
		if pos >= len(p) {
			return r, false
		}
		n := int(p[pos])
		pos++
		ar, pos = readN(p, pos, n)
	default:
		ar, pos = readCStringBytes(p, pos)
	}
	if pos < 0 {
		return r, false
	}
	r.authResp = ar

	if r.caps&capConnectWithDB != 0 {
		db, next := readCString(p, pos)
		if next >= 0 {
			r.database = db
			pos = next
		}
	}
	if r.caps&capPluginAuth != 0 {
		pl, next := readCString(p, pos)
		if next >= 0 {
			r.plugin = pl
			pos = next
		}
	}
	if r.caps&capConnectAttrs != 0 {
		r.attrs = parseAttrs(p, pos)
	}
	return r, true
}

// parseAttrs reads the CLIENT_CONNECT_ATTRS block: a length-encoded total,
// then key/value pairs of length-encoded strings. It is the MySQL equivalent of
// the MongoDB client document — the driver name, its version, and often the
// program name, a far stronger fingerprint than an address. Best-effort: a
// malformed block yields whatever parsed before it broke.
func parseAttrs(p []byte, pos int) map[string]string {
	total, pos := readLenencInt(p, pos)
	if pos < 0 {
		return nil
	}
	end := pos + int(total)
	if end > len(p) {
		end = len(p)
	}
	out := map[string]string{}
	for pos < end {
		var klen uint64
		klen, pos = readLenencInt(p, pos)
		if pos < 0 {
			break
		}
		var key []byte
		key, pos = readN(p, pos, int(klen))
		if pos < 0 {
			break
		}
		var vlen uint64
		vlen, pos = readLenencInt(p, pos)
		if pos < 0 {
			break
		}
		var val []byte
		val, pos = readN(p, pos, int(vlen))
		if pos < 0 {
			break
		}
		out[string(key)] = string(val)
	}
	return out
}

// formatNativeHash renders hashcat mode 11200:
//
//	$mysqlna$<scramble hex>*<response hex>
//
// Given the 20-byte scramble and the 20-byte response, a cracker computes
// SHA1(pw) XOR SHA1(scramble || SHA1(SHA1(pw))) from a guessed password and
// checks it against the response — which is exactly why the scramble the decoy
// chose has to be recorded next to it.
func formatNativeHash(scramble, response []byte) string {
	return "$mysqlna$" + hex.EncodeToString(scramble) + "*" + hex.EncodeToString(response)
}

// readCString reads a NUL-terminated string and returns the position after the
// terminator, or -1 if there is no terminator.
func readCString(p []byte, pos int) (string, int) {
	b, next := readCStringBytes(p, pos)
	return string(b), next
}

func readCStringBytes(p []byte, pos int) ([]byte, int) {
	if pos < 0 || pos > len(p) {
		return nil, -1
	}
	for i := pos; i < len(p); i++ {
		if p[i] == 0 {
			return p[pos:i], i + 1
		}
	}
	return nil, -1
}

// readN returns n bytes starting at pos and the position after them, or -1 if
// the packet is too short.
func readN(p []byte, pos, n int) ([]byte, int) {
	if pos < 0 || n < 0 || pos+n > len(p) {
		return nil, -1
	}
	return p[pos : pos+n], pos + n
}

// readLenencInt reads a length-encoded integer and returns the position after
// it, or -1 on a short packet.
func readLenencInt(p []byte, pos int) (uint64, int) {
	if pos < 0 || pos >= len(p) {
		return 0, -1
	}
	switch first := p[pos]; {
	case first < 0xfb:
		return uint64(first), pos + 1
	case first == 0xfc:
		if pos+3 > len(p) {
			return 0, -1
		}
		return uint64(le.Uint16(p[pos+1 : pos+3])), pos + 3
	case first == 0xfd:
		if pos+4 > len(p) {
			return 0, -1
		}
		return uint64(p[pos+1]) | uint64(p[pos+2])<<8 | uint64(p[pos+3])<<16, pos + 4
	case first == 0xfe:
		if pos+9 > len(p) {
			return 0, -1
		}
		return le.Uint64(p[pos+1 : pos+9]), pos + 9
	default:
		// 0xfb is NULL, 0xff is an error marker; neither is valid as a length
		// where the decoy reads one.
		return 0, -1
	}
}

// truncate bounds a captured field for the event log.
func truncate(s string) string { return httpdecoy.Truncate(s, logLimit) }

// sanitise keeps attacker-controlled text from carrying control characters back
// out in the decoy's own error message.
func sanitise(s string) string {
	s = truncate(s)
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
}
