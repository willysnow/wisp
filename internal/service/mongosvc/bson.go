package mongosvc

import (
	"encoding/binary"
	"fmt"
	"math"
	"time"
)

// A minimal BSON codec: enough to read a command and write a plausible reply,
// and nothing more.
//
// Hand-written rather than imported because the alternative is the official
// driver — a large dependency, for a decoy that needs to understand about a
// dozen commands. Every length here is checked against the remaining buffer
// before it is used: this parser's input comes from whoever connected to the
// honeypot, which is the definition of hostile.

// BSON element types. Anything not listed makes the parser stop rather than
// guess at a length it does not know.
const (
	typeDouble   = 0x01
	typeString   = 0x02
	typeDocument = 0x03
	typeArray    = 0x04
	typeBinary   = 0x05
	typeUndef    = 0x06
	typeObjectID = 0x07
	typeBool     = 0x08
	typeDateTime = 0x09
	typeNull     = 0x0a
	typeRegex    = 0x0b
	typeInt32    = 0x10
	typeTimestmp = 0x11
	typeInt64    = 0x12
	typeDecimal  = 0x13
)

// maxDepth bounds nesting. A document nested a thousand levels deep is not a
// query, it is an attempt to exhaust our stack.
const maxDepth = 20

// doc is a decoded BSON document that remembers field order, because MongoDB's
// wire protocol puts the command name in the first field and a Go map would
// throw that away.
type doc struct {
	keys   []string
	values map[string]any
}

func (d doc) first() string {
	if len(d.keys) == 0 {
		return ""
	}
	return d.keys[0]
}

func (d doc) lookup(key string) (any, bool) {
	v, ok := d.values[key]
	return v, ok
}

func (d doc) str(key string) string {
	if v, ok := d.values[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func (d doc) sub(key string) (doc, bool) {
	if v, ok := d.values[key]; ok {
		if sub, ok := v.(doc); ok {
			return sub, true
		}
	}
	return doc{}, false
}

func (d doc) binary(key string) ([]byte, bool) {
	if v, ok := d.values[key]; ok {
		if b, ok := v.([]byte); ok {
			return b, true
		}
	}
	return nil, false
}

// parseDocument decodes one BSON document from the front of b.
func parseDocument(b []byte) (doc, error) { return parseDocumentDepth(b, 0) }

func parseDocumentDepth(b []byte, depth int) (doc, error) {
	out := doc{values: map[string]any{}}

	if depth > maxDepth {
		return out, fmt.Errorf("document nested deeper than %d", maxDepth)
	}
	if len(b) < 5 {
		return out, fmt.Errorf("document shorter than its own header")
	}

	size := int(int32(binary.LittleEndian.Uint32(b)))
	if size < 5 || size > len(b) {
		return out, fmt.Errorf("document claims %d bytes, %d available", size, len(b))
	}

	// The body sits between the 4-byte length and the terminating NUL.
	body := b[4 : size-1]
	for len(body) > 0 {
		kind := body[0]
		body = body[1:]

		key, rest, err := readCString(body)
		if err != nil {
			return out, err
		}
		body = rest

		value, rest, err := readValue(kind, body, depth)
		if err != nil {
			return out, err
		}
		body = rest

		if _, seen := out.values[key]; !seen {
			out.keys = append(out.keys, key)
		}
		out.values[key] = value
	}
	return out, nil
}

func readValue(kind byte, b []byte, depth int) (any, []byte, error) {
	switch kind {
	case typeDouble:
		if len(b) < 8 {
			return nil, nil, errShort("double")
		}
		return math.Float64frombits(binary.LittleEndian.Uint64(b)), b[8:], nil

	case typeString:
		s, rest, err := readString(b)
		return s, rest, err

	case typeDocument, typeArray:
		if len(b) < 4 {
			return nil, nil, errShort("document")
		}
		size := int(int32(binary.LittleEndian.Uint32(b)))
		if size < 5 || size > len(b) {
			return nil, nil, errShort("document")
		}
		sub, err := parseDocumentDepth(b[:size], depth+1)
		if err != nil {
			return nil, nil, err
		}
		return sub, b[size:], nil

	case typeBinary:
		if len(b) < 5 {
			return nil, nil, errShort("binary")
		}
		size := int(int32(binary.LittleEndian.Uint32(b)))
		if size < 0 || size+5 > len(b) {
			return nil, nil, errShort("binary")
		}
		// b[4] is the subtype, which nothing here needs to distinguish.
		return b[5 : 5+size], b[5+size:], nil

	case typeObjectID:
		if len(b) < 12 {
			return nil, nil, errShort("objectid")
		}
		return b[:12], b[12:], nil

	case typeBool:
		if len(b) < 1 {
			return nil, nil, errShort("bool")
		}
		return b[0] != 0, b[1:], nil

	case typeDateTime, typeTimestmp, typeInt64:
		if len(b) < 8 {
			return nil, nil, errShort("int64")
		}
		return int64(binary.LittleEndian.Uint64(b)), b[8:], nil

	case typeInt32:
		if len(b) < 4 {
			return nil, nil, errShort("int32")
		}
		return int32(binary.LittleEndian.Uint32(b)), b[4:], nil

	case typeNull, typeUndef:
		return nil, b, nil

	case typeDecimal:
		if len(b) < 16 {
			return nil, nil, errShort("decimal128")
		}
		return b[:16], b[16:], nil

	case typeRegex:
		_, rest, err := readCString(b)
		if err != nil {
			return nil, nil, err
		}
		_, rest, err = readCString(rest)
		return nil, rest, err
	}

	return nil, nil, fmt.Errorf("unsupported BSON type 0x%02x", kind)
}

func readCString(b []byte) (string, []byte, error) {
	for i, c := range b {
		if c == 0 {
			return string(b[:i]), b[i+1:], nil
		}
	}
	return "", nil, fmt.Errorf("unterminated cstring")
}

func readString(b []byte) (string, []byte, error) {
	if len(b) < 4 {
		return "", nil, errShort("string")
	}
	size := int(int32(binary.LittleEndian.Uint32(b)))
	if size < 1 || 4+size > len(b) {
		return "", nil, errShort("string")
	}
	// size includes the trailing NUL.
	return string(b[4 : 4+size-1]), b[4+size:], nil
}

func errShort(what string) error { return fmt.Errorf("truncated %s", what) }

// --- writing ---------------------------------------------------------------

// docBuilder assembles a BSON document. Fields keep the order they are added
// in, which is what makes a reply look like a real server's.
type docBuilder struct {
	buf []byte
}

func newDoc() *docBuilder { return &docBuilder{} }

func (d *docBuilder) element(kind byte, key string) {
	d.buf = append(d.buf, kind)
	d.buf = append(d.buf, key...)
	d.buf = append(d.buf, 0)
}

func (d *docBuilder) addDouble(key string, v float64) *docBuilder {
	d.element(typeDouble, key)
	d.buf = binary.LittleEndian.AppendUint64(d.buf, math.Float64bits(v))
	return d
}

func (d *docBuilder) addString(key, v string) *docBuilder {
	d.element(typeString, key)
	d.buf = binary.LittleEndian.AppendUint32(d.buf, uint32(len(v)+1))
	d.buf = append(d.buf, v...)
	d.buf = append(d.buf, 0)
	return d
}

func (d *docBuilder) addInt32(key string, v int32) *docBuilder {
	d.element(typeInt32, key)
	d.buf = binary.LittleEndian.AppendUint32(d.buf, uint32(v))
	return d
}

func (d *docBuilder) addInt64(key string, v int64) *docBuilder {
	d.element(typeInt64, key)
	d.buf = binary.LittleEndian.AppendUint64(d.buf, uint64(v))
	return d
}

func (d *docBuilder) addBool(key string, v bool) *docBuilder {
	d.element(typeBool, key)
	if v {
		d.buf = append(d.buf, 1)
	} else {
		d.buf = append(d.buf, 0)
	}
	return d
}

func (d *docBuilder) addDateTime(key string, t time.Time) *docBuilder {
	d.element(typeDateTime, key)
	d.buf = binary.LittleEndian.AppendUint64(d.buf, uint64(t.UnixMilli()))
	return d
}

func (d *docBuilder) addBinary(key string, subtype byte, v []byte) *docBuilder {
	d.element(typeBinary, key)
	d.buf = binary.LittleEndian.AppendUint32(d.buf, uint32(len(v)))
	d.buf = append(d.buf, subtype)
	d.buf = append(d.buf, v...)
	return d
}

func (d *docBuilder) addObjectID(key string, id []byte) *docBuilder {
	d.element(typeObjectID, key)
	d.buf = append(d.buf, id...)
	return d
}

func (d *docBuilder) addDoc(key string, sub *docBuilder) *docBuilder {
	d.element(typeDocument, key)
	d.buf = append(d.buf, sub.build()...)
	return d
}

// addStringArray writes a BSON array, whose keys are the decimal indices.
func (d *docBuilder) addStringArray(key string, values []string) *docBuilder {
	sub := newDoc()
	for i, v := range values {
		sub.addString(fmt.Sprint(i), v)
	}
	d.element(typeArray, key)
	d.buf = append(d.buf, sub.build()...)
	return d
}

func (d *docBuilder) build() []byte {
	out := make([]byte, 4, len(d.buf)+5)
	out = append(out, d.buf...)
	out = append(out, 0)
	binary.LittleEndian.PutUint32(out, uint32(len(out)))
	return out
}
