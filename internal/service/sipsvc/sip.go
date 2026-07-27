// Package sipsvc emulates a SIP (VoIP) server far enough to do two things a
// banner catcher on 5060 cannot: look like a live PBX so a scanner escalates
// from mapping to guessing, and capture the digest a REGISTER carries — a value
// that cracks offline back to the SIP account's password.
//
// SIP is what sipvicious, sipcli and friendly-scanner reach for: svmap finds a
// PBX, svwar enumerates its extensions, and svcrack sprays passwords at them.
// The decoy answers OPTIONS with 200 OK, which is how svmap concludes a PBX is
// live, and challenges REGISTER/INVITE/SUBSCRIBE with a digest nonce it chose
// and records. When the client answers with an Authorization digest, the pieces
// an offline cracker needs — username, realm, the recorded nonce, the request
// method and URI, and the response — are captured together:
//
//	sip  auth_attempt  username=1001  realm=asterisk  method=REGISTER
//	     sip_hash=$sip$*...*MD5*<response>  hashcat_mode=11400
//
// That line is hashcat mode 11400 (and John the Ripper's SIP format), ready to
// paste. It is not "someone probed 5060" — it is a value that reveals the
// extension's password to anyone with a wordlist.
//
// Nothing is ever registered. Every credential ends in 403 Forbidden, for the
// same reason the MongoDB decoy always answers AuthenticationFailed: a locked
// door invites the next key, and svcrack sprays keys.
package sipsvc

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"strings"

	"github.com/willysnow/wisp/internal/event"
	"github.com/willysnow/wisp/internal/service"
	"github.com/willysnow/wisp/internal/service/httpdecoy"
)

const name = "sip"

// logLimit bounds any single captured field before it reaches the event log.
const logLimit = 1024

// maxDatagram bounds the SIP message the decoy will parse. Requests that matter
// here — OPTIONS, REGISTER, INVITE — are well under this; the shared packet
// reader already truncates to 4 KiB.
const maxDatagram = 4096

type Service struct {
	addr string
	// realm and server shape the disguise. The realm is what the client folds
	// into HA1, so it is part of what makes the captured digest crackable and is
	// recorded from the client's own header. server names the PBX product.
	realm  string
	server string
	// nonce is the digest challenge. Chosen once and kept for the process — a
	// value a cracker has to know, so it is issued by the decoy and recorded
	// with every response, the way the SMB decoy commits to one NTLM challenge.
	nonce string
}

// New builds the decoy. Empty realm and server fall back to an Asterisk PBX,
// the product sipvicious most expects to find.
func New(addr, realm, server string) *Service {
	if realm == "" {
		realm = "asterisk"
	}
	if server == "" {
		server = "Asterisk PBX 18.10.0"
	}
	return &Service{addr: addr, realm: realm, server: server, nonce: newNonce()}
}

func (s *Service) Name() string { return name }
func (s *Service) Addr() string { return s.addr }

// ServePacket handles SIP over UDP, which is what the scanning tools use. Each
// datagram is one request; the response is small and roughly the size of the
// request, so the decoy is not a useful amplifier.
func (s *Service) ServePacket(ctx context.Context, pc net.PacketConn, emit event.Emitter) error {
	return service.AcceptPackets(ctx, pc, func(pc net.PacketConn, from net.Addr, payload []byte) {
		s.handle(pc, from, payload, emit)
	})
}

func (s *Service) handle(pc net.PacketConn, from net.Addr, payload []byte, emit event.Emitter) {
	if len(payload) == 0 || len(payload) > maxDatagram {
		return
	}
	req, ok := parseRequest(payload)
	if !ok {
		// Not a SIP request. A decoy that answered arbitrary UDP would be an
		// amplifier and a source of noise; a real server ignores it too.
		return
	}

	if req.auth != "" {
		s.capture(pc, from, req, emit)
		s.respond(pc, from, req, 403, "Forbidden", false)
		return
	}

	switch req.method {
	case "OPTIONS":
		// Answering keeps the disguise: this 200 is exactly what svmap reads as
		// "a live PBX", which is what escalates a scan into a password spray.
		s.emitProbe(from, req, emit)
		s.respond(pc, from, req, 200, "OK", false)
	case "REGISTER", "INVITE", "SUBSCRIBE":
		// Demand authentication. The 401 carries the challenge whose answer is
		// the credential worth having.
		s.emitProbe(from, req, emit)
		s.respond(pc, from, req, 401, "Unauthorized", true)
	default:
		s.emitProbe(from, req, emit)
		s.respond(pc, from, req, 405, "Method Not Allowed", false)
	}
}

// emitProbe records a request that carried no credential — a scan, an
// extension-enumeration attempt, or the first half of a challenge-response.
func (s *Service) emitProbe(from net.Addr, req sipRequest, emit event.Emitter) {
	ev := event.New(name, "probe", from, nil)
	ev.Data["method"] = truncate(req.method)
	if req.userAgent != "" {
		ev.Data["user_agent"] = truncate(req.userAgent)
	}
	if u := req.fromUser(); u != "" {
		ev.Data["from_user"] = truncate(u)
	}
	if u := req.toUser(); u != "" {
		ev.Data["to_user"] = truncate(u)
	}
	emit.Emit(ev)
}

// capture records the digest credential from an Authorization header.
func (s *Service) capture(pc net.PacketConn, from net.Addr, req sipRequest, emit event.Emitter) {
	d := parseDigest(req.auth)

	ev := event.New(name, "auth_attempt", from, nil)
	ev.Data["method"] = truncate(req.method)
	set := func(k, v string) {
		if v != "" {
			ev.Data[k] = truncate(v)
		}
	}
	set("username", d["username"])
	set("realm", d["realm"])
	set("nonce", d["nonce"])
	set("uri", d["uri"])
	set("response", d["response"])
	set("algorithm", d["algorithm"])
	set("qop", d["qop"])
	set("cnonce", d["cnonce"])
	set("nc", d["nc"])
	if req.userAgent != "" {
		ev.Data["user_agent"] = truncate(req.userAgent)
	}

	// Assemble the hashcat 11400 / John SIP line, but only for plain MD5 — a
	// MD5-sess or SHA-256 response is a different algorithm the format does not
	// describe, and a wrong line is worse than none.
	alg := strings.ToUpper(d["algorithm"])
	if (alg == "" || alg == "MD5") && d["response"] != "" && d["nonce"] != "" {
		host, _ := event.SplitAddr(from)
		ev.Data["sip_hash"] = formatSIPHash(host, req, d)
		ev.Data["hashcat_mode"] = 11400
	}

	emit.Emit(ev)
}

// respond writes a SIP response, echoing the Via/From/Call-ID/CSeq the client
// needs to match it to its request and adding a To tag. A 401 carries the digest
// challenge.
func (s *Service) respond(pc net.PacketConn, from net.Addr, req sipRequest, code int, reason string, challenge bool) {
	var b strings.Builder
	fmt.Fprintf(&b, "SIP/2.0 %d %s\r\n", code, reason)
	for _, v := range req.via {
		b.WriteString("Via: " + v + "\r\n")
	}
	if req.from != "" {
		b.WriteString("From: " + req.from + "\r\n")
	}
	b.WriteString("To: " + withTag(req.to) + "\r\n")
	if req.callID != "" {
		b.WriteString("Call-ID: " + req.callID + "\r\n")
	}
	if req.cseq != "" {
		b.WriteString("CSeq: " + req.cseq + "\r\n")
	}
	if challenge {
		fmt.Fprintf(&b, "WWW-Authenticate: Digest realm=\"%s\", nonce=\"%s\", algorithm=MD5\r\n",
			s.realm, s.nonce)
	}
	b.WriteString("Server: " + s.server + "\r\n")
	b.WriteString("Content-Length: 0\r\n\r\n")

	_, _ = pc.WriteTo([]byte(b.String()), from)
}

// formatSIPHash builds the hashcat-11400 line:
//
//	$sip$*server*client*user*realm*method*prefix*resource*suffix*nonce*cnonce*nc*qop*MD5*response
//
// The digest URI is split at its first colon into prefix and resource with an
// empty suffix, so that prefix + ":" + resource reproduces the URI and the
// format's HA2 = MD5(method:prefix:resource:suffix) equals the real
// MD5(method:uri). server and client are informational — the digest does not
// use them — so the SIP host and the source address fill them.
func formatSIPHash(client string, req sipRequest, d map[string]string) string {
	prefix, resource := splitURI(d["uri"])
	server := req.toHost()
	fields := []string{
		server, client,
		d["username"], d["realm"],
		req.method,
		prefix, resource, "", // URI prefix, resource, suffix
		d["nonce"], d["cnonce"], d["nc"], d["qop"],
		"MD5", d["response"],
	}
	return "$sip$*" + strings.Join(fields, "*")
}

// splitURI divides a digest URI at its first colon: "sip:1001@pbx" becomes
// prefix "sip", resource "1001@pbx". A URI with no colon is all resource.
func splitURI(uri string) (prefix, resource string) {
	if i := strings.IndexByte(uri, ':'); i >= 0 {
		return uri[:i], uri[i+1:]
	}
	return "", uri
}

// withTag ensures the To header has a tag, which a response must carry.
func withTag(to string) string {
	if to == "" {
		return "<sip:decoy>;tag=wisp"
	}
	if strings.Contains(strings.ToLower(to), "tag=") {
		return to
	}
	return to + ";tag=wisp"
}

func newNonce() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "0123456789abcdef0123456789abcdef"
	}
	return hex.EncodeToString(b[:])
}

func truncate(s string) string { return httpdecoy.Truncate(s, logLimit) }
