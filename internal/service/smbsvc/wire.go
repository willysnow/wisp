package smbsvc

import (
	"encoding/binary"
	"errors"
	"unicode/utf16"

	"github.com/willysnow/wisp/internal/service/httpdecoy"
)

var errBadLength = errors.New("smb: message length out of range")

// le is a shorthand for the little-endian byte order SMB uses throughout.
var le = binary.LittleEndian

// buf is a tiny growable little-endian writer. The SMB structures are laid out
// by hand rather than with reflection because their field order is the protocol
// and a struct tag would only hide it.
type buf struct{ b []byte }

func (w *buf) u8(v byte)     { w.b = append(w.b, v) }
func (w *buf) u16(v uint16)  { w.b = le.AppendUint16(w.b, v) }
func (w *buf) u32(v uint32)  { w.b = le.AppendUint32(w.b, v) }
func (w *buf) u64(v uint64)  { w.b = le.AppendUint64(w.b, v) }
func (w *buf) raw(p []byte)  { w.b = append(w.b, p...) }
func (w *buf) zeros(n int)   { w.b = append(w.b, make([]byte, n)...) }
func (w *buf) len() int      { return len(w.b) }
func (w *buf) bytes() []byte { return w.b }

// align pads the buffer to an n-byte boundary, which SMB2 negotiate contexts
// and several other structures require.
func (w *buf) align(n int) {
	for len(w.b)%n != 0 {
		w.b = append(w.b, 0)
	}
}

// utf16le encodes a string the way every name in SMB and NTLM travels.
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

// sliceField reads a Len/Offset pair the way NTLM lays them out and returns the
// bytes it points at, bounds-checked against the whole message. Every field in
// an NTLM authenticate message is one of these, and every one of them comes
// from a stranger, so an offset that runs off the end has to yield nothing
// rather than a panic.
func sliceField(msg []byte, length, offset int) []byte {
	if length <= 0 || offset < 0 || offset+length > len(msg) {
		return nil
	}
	return msg[offset : offset+length]
}

// stableBytes derives n deterministic bytes from a seed, so identifiers that
// have to survive a restart — the server GUID here — do not change on every
// launch. It reuses the sensor's shared derivation for the same reason the
// other decoys do: a value that regenerates every time anyone looks is a
// honeypot fingerprint.
func stableBytes(seed string, n int) []byte {
	hexed := httpdecoy.StableID(seed, n*2)
	out := make([]byte, n)
	for i := 0; i < n; i++ {
		out[i] = fromHexPair(hexed[i*2], hexed[i*2+1])
	}
	return out
}

func fromHexPair(hi, lo byte) byte {
	return hexNibble(hi)<<4 | hexNibble(lo)
}

func hexNibble(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	default:
		return 0
	}
}

// truncate bounds a captured field for the event log.
func truncate(s string) string { return httpdecoy.Truncate(s, logLimit) }
