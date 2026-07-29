package snmpsvc

import "strings"

// BER identifier classes. SNMP uses universal tags for the primitives, a context
// class for its PDUs, and an application class for a few value types.
const (
	classUniversal = 0
	classContext   = 2
)

// Universal tag numbers the decoder recognises.
const (
	tagInteger     = 0x02
	tagOctetString = 0x04
	tagOID         = 0x06
	tagSequence    = 0x10
)

// tlv is one decoded BER element: a tag, whether it is constructed, and its
// content. SNMP is BER, not DER, so the reader is deliberately lenient about
// non-minimal lengths — it only needs definite-length elements, which is all a
// real SNMP message contains.
type tlv struct {
	class    byte
	tag      byte
	compound bool
	content  []byte
}

// isSequence, isInteger and isOctetString name the checks the parser repeats.
func (t tlv) isSequence() bool    { return t.class == classUniversal && t.tag == tagSequence }
func (t tlv) isInteger() bool     { return t.class == classUniversal && t.tag == tagInteger }
func (t tlv) isOctetString() bool { return t.class == classUniversal && t.tag == tagOctetString }

// readTLV decodes one BER element and returns it with the bytes that follow.
// Every input comes from a stranger, so a malformed length or a truncated body
// yields ok=false rather than a panic.
func readTLV(data []byte) (t tlv, rest []byte, ok bool) {
	if len(data) < 2 {
		return tlv{}, nil, false
	}
	id := data[0]
	t.class = id >> 6
	t.compound = id&0x20 != 0
	t.tag = id & 0x1f
	if t.tag == 0x1f {
		// A high-tag-number form. SNMP never uses one, so treat it as malformed
		// rather than growing a multi-byte-tag decoder no message here needs.
		return tlv{}, nil, false
	}

	lengthByte := data[1]
	var length, headerLen int
	if lengthByte < 0x80 {
		length = int(lengthByte)
		headerLen = 2
	} else {
		n := int(lengthByte & 0x7f)
		// n==0 is the indefinite form, which SNMP does not use; cap the rest so a
		// hostile length field cannot point past the datagram.
		if n == 0 || n > 4 || len(data) < 2+n {
			return tlv{}, nil, false
		}
		for i := 0; i < n; i++ {
			length = length<<8 | int(data[2+i])
		}
		headerLen = 2 + n
	}

	if length < 0 || headerLen+length > len(data) {
		return tlv{}, nil, false
	}
	t.content = data[headerLen : headerLen+length]
	return t, data[headerLen+length:], true
}

// children decodes a constructed element's content into its sequence of
// elements, stopping at the first malformed one.
func children(content []byte) []tlv {
	var out []tlv
	for len(content) > 0 {
		t, rest, ok := readTLV(content)
		if !ok {
			break
		}
		out = append(out, t)
		content = rest
	}
	return out
}

// decodeOID renders an OID's content bytes as a dotted string. The first byte
// packs the first two arcs as 40*x+y; the rest are base-128 varints.
func decodeOID(content []byte) string {
	if len(content) == 0 {
		return ""
	}
	var b strings.Builder
	first := int(content[0])
	b.WriteString(itoa(first / 40))
	b.WriteByte('.')
	b.WriteString(itoa(first % 40))

	value := 0
	for _, c := range content[1:] {
		value = value<<7 | int(c&0x7f)
		if c&0x80 == 0 {
			b.WriteByte('.')
			b.WriteString(itoa(value))
			value = 0
		}
	}
	return b.String()
}

// decodeInt reads a BER INTEGER as a signed value, bounded to the widths SNMP
// uses (version, request-id, counts). An over-long field yields 0.
func decodeInt(content []byte) int {
	if len(content) == 0 || len(content) > 8 {
		return 0
	}
	var v int64
	if content[0]&0x80 != 0 {
		v = -1 // sign-extend a negative value
	}
	for _, c := range content {
		v = v<<8 | int64(c)
	}
	return int(v)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
