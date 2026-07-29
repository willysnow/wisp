// Package snmpsvc emulates an SNMP agent far enough to capture the one thing an
// intruder came to 161 for: the community string, which in SNMP v1 and v2c is
// the credential itself — sent in the clear on every request.
//
// SNMP is what onesixtyone and snmpwalk spray: a scanner works a list of
// communities ("public", "private", "cisco", the vendor defaults) against the
// port, and any that a device accepts hands over its whole configuration. The
// decoy records every community tried, the operation, and the OIDs asked for,
// the way the other decoys record a password:
//
//	snmp  auth_attempt  community=public  version=v2c  operation=GetRequest
//	      oids=1.3.6.1.2.1.1.1.0
//
// A SetRequest is stronger still — it is an attempt to reconfigure the device,
// stated in the OIDs it would change.
//
// The decoy never answers. SNMP is the internet's favourite UDP amplification
// protocol: a GETBULK reply can dwarf its request, so an agent that responded
// could be turned into a reflector aimed at someone else. Answering is not
// needed to capture the community — that arrives in the request — so this decoy
// listens, records, and stays silent, which is also what a firewalled agent
// looks like. Every request is parsed; nothing is ever sent back.
package snmpsvc

import (
	"context"
	"encoding/hex"
	"net"
	"strings"

	"github.com/willysnow/wisp/internal/event"
	"github.com/willysnow/wisp/internal/service"
	"github.com/willysnow/wisp/internal/service/httpdecoy"
)

const name = "snmp"

// logLimit bounds any single captured field before it reaches the event log.
const logLimit = 1024

// maxOIDs caps how many OIDs one request contributes to the log. A GETBULK can
// name many; the first handful is enough to show intent without a client
// choosing how long the decoy's log line is.
const maxOIDs = 16

// SNMP version numbers as they appear in the message.
const (
	versionV1  = 0
	versionV2c = 1
	versionV3  = 3
)

// PDU tag numbers within the context class.
var pduNames = map[byte]string{
	0: "GetRequest",
	1: "GetNextRequest",
	2: "GetResponse",
	3: "SetRequest",
	4: "Trap",
	5: "GetBulkRequest",
	6: "InformRequest",
	7: "SNMPv2-Trap",
	8: "Report",
}

type Service struct {
	addr string
}

func New(addr string) *Service {
	return &Service{addr: addr}
}

func (s *Service) Name() string { return name }
func (s *Service) Addr() string { return s.addr }

// ServePacket handles SNMP over UDP. handle never writes a reply, so the decoy
// cannot be used as an amplifier.
func (s *Service) ServePacket(ctx context.Context, pc net.PacketConn, emit event.Emitter) error {
	return service.AcceptPackets(ctx, pc, func(pc net.PacketConn, from net.Addr, payload []byte) {
		s.handle(from, payload, emit)
	})
}

func (s *Service) handle(from net.Addr, payload []byte, emit event.Emitter) {
	msg, _, ok := readTLV(payload)
	if !ok || !msg.isSequence() {
		return // not an SNMP message
	}

	version, rest, ok := readTLV(msg.content)
	if !ok || !version.isInteger() {
		return
	}

	switch decodeInt(version.content) {
	case versionV1:
		s.captureCommunity(from, "v1", rest, emit)
	case versionV2c:
		s.captureCommunity(from, "v2c", rest, emit)
	case versionV3:
		s.captureV3(from, rest, emit)
	}
	// Deliberately no response — see the package comment.
}

// captureCommunity records a v1/v2c request. After the version comes the
// community OCTET STRING, then the PDU, whose context tag is the operation and
// whose varbinds name the OIDs.
func (s *Service) captureCommunity(from net.Addr, version string, rest []byte, emit event.Emitter) {
	community, rest, ok := readTLV(rest)
	if !ok || !community.isOctetString() {
		return
	}

	ev := event.New(name, "auth_attempt", from, nil)
	ev.Data["version"] = version
	ev.Data["community"] = truncate(sanitise(string(community.content)))

	if pdu, _, ok := readTLV(rest); ok && pdu.class == classContext {
		ev.Data["operation"] = pduName(pdu.tag)
		if oids := requestOIDs(pdu.content); len(oids) > 0 {
			ev.Data["oids"] = strings.Join(oids, ", ")
		}
	}

	emit.Emit(ev)
}

// requestOIDs pulls the OIDs out of a PDU. The PDU is request-id, error-status
// and error-index (three integers), then the variable-bindings — a sequence of
// name/value sequences whose first element is the OID.
func requestOIDs(pdu []byte) []string {
	fields := children(pdu)
	if len(fields) < 4 {
		return nil
	}
	varbinds := fields[3]
	if !varbinds.isSequence() {
		return nil
	}

	var out []string
	for _, vb := range children(varbinds.content) {
		if !vb.isSequence() {
			continue
		}
		inner := children(vb.content)
		if len(inner) == 0 || inner[0].tag != tagOID || inner[0].class != classUniversal {
			continue
		}
		out = append(out, decodeOID(inner[0].content))
		if len(out) >= maxOIDs {
			break
		}
	}
	return out
}

// captureV3 records a v3 request. v3 replaces the community with a User-based
// Security Model: the username travels in the clear inside the security
// parameters, and the message may be authenticated with an HMAC keyed by the
// user's password. The decoy captures who the intruder tried to be and whether
// they claimed auth and privacy.
func (s *Service) captureV3(from net.Addr, rest []byte, emit event.Emitter) {
	globalData, rest, ok := readTLV(rest)
	if !ok || !globalData.isSequence() {
		return
	}
	secParams, _, ok := readTLV(rest)
	if !ok || !secParams.isOctetString() {
		return
	}

	ev := event.New(name, "auth_attempt", from, nil)
	ev.Data["version"] = "v3"

	// msgFlags is the third field of the global data: one byte whose low bits are
	// the auth and privacy flags.
	if g := children(globalData.content); len(g) >= 3 && g[2].isOctetString() && len(g[2].content) >= 1 {
		flags := g[2].content[0]
		ev.Data["auth"] = flags&0x01 != 0
		ev.Data["priv"] = flags&0x02 != 0
	}

	// The security parameters wrap a sequence: engineID, engineBoots, engineTime,
	// userName, then the auth and privacy parameters.
	if inner, _, ok := readTLV(secParams.content); ok && inner.isSequence() {
		f := children(inner.content)
		if len(f) >= 1 && f[0].isOctetString() {
			ev.Data["engine_id"] = hex.EncodeToString(f[0].content)
		}
		if len(f) >= 4 && f[3].isOctetString() {
			ev.Data["username"] = truncate(sanitise(string(f[3].content)))
		}
	}

	emit.Emit(ev)
}

func pduName(tag byte) string {
	if n, ok := pduNames[tag]; ok {
		return n
	}
	return "unknown"
}

func truncate(s string) string { return httpdecoy.Truncate(s, logLimit) }

// sanitise keeps a community string's control or non-ASCII bytes from corrupting
// the JSONL log; SNMP communities are ordinarily plain words but the field is
// attacker-controlled.
func sanitise(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return '.'
		}
		return r
	}, s)
}
