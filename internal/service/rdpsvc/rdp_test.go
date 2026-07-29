package rdpsvc

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/willysnow/wisp/internal/service"
	"github.com/willysnow/wisp/internal/service/servicetest"
)

func start(t *testing.T) *servicetest.StreamHarness {
	dir := t.TempDir()
	return servicetest.StartStream(t, func(addr string) service.StreamService {
		s, err := New(addr, filepath.Join(dir, "rdp-cert.pem"), filepath.Join(dir, "rdp-key.pem"))
		if err != nil {
			t.Fatalf("new: %v", err)
		}
		return s
	})
}

// buildCR builds a TPKT/X.224 Connection Request: an optional mstshash cookie,
// then the negotiation request naming the security protocols it supports.
func buildCR(cookieUser string, protocols uint32) []byte {
	var variable []byte
	if cookieUser != "" {
		variable = append(variable, []byte("Cookie: mstshash="+cookieUser+"\r\n")...)
	}
	neg := make([]byte, 8)
	neg[0] = negTypeRequest
	binary.LittleEndian.PutUint16(neg[2:4], 8)
	binary.LittleEndian.PutUint32(neg[4:8], protocols)
	variable = append(variable, neg...)

	x224 := make([]byte, 7)
	x224[0] = byte(6 + len(variable))
	x224[1] = x224CR
	binary.BigEndian.PutUint16(x224[2:4], 0)
	binary.BigEndian.PutUint16(x224[4:6], 0x1234)
	x224[6] = 0
	x224 = append(x224, variable...)

	total := 4 + len(x224)
	return append([]byte{tpktVersion, 0x00, byte(total >> 8), byte(total)}, x224...)
}

// readConfirm reads the Connection Confirm and returns the selected protocol.
func readConfirm(t *testing.T, conn net.Conn) uint32 {
	t.Helper()
	var hdr [4]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		t.Fatalf("read confirm header: %v", err)
	}
	length := int(hdr[2])<<8 | int(hdr[3])
	body := make([]byte, length-4)
	if _, err := io.ReadFull(conn, body); err != nil {
		t.Fatalf("read confirm body: %v", err)
	}
	if len(body) < 15 || body[1] != x224CC {
		t.Fatalf("reply is not a Connection Confirm: %x", body)
	}
	return binary.LittleEndian.Uint32(body[11:15])
}

func TestSSLNegotiationProbe(t *testing.T) {
	h := start(t)
	conn := h.Dial()

	// A client that asks only for plain TLS is answered and left at the
	// negotiation — no CredSSP path, so no TLS handshake follows here.
	if _, err := conn.Write(buildCR("guest", protoSSL)); err != nil {
		t.Fatalf("write CR: %v", err)
	}
	if got := readConfirm(t, conn); got != protoSSL {
		t.Fatalf("selected protocol = %#x, want SSL", got)
	}

	ev := h.WaitFor(t, "probe")
	if ev.Data["username"] != "guest" {
		t.Errorf("username = %v, want guest", ev.Data["username"])
	}
	if ev.Data["requested"] != "ssl" {
		t.Errorf("requested = %v, want ssl", ev.Data["requested"])
	}
	if ev.Data["nla"] != false {
		t.Errorf("nla = %v, want false", ev.Data["nla"])
	}
}

func TestCredSSPHashCaptured(t *testing.T) {
	h := start(t)
	conn := h.Dial()

	// Ask for CredSSP (NLA) and name the targeted account in the cookie.
	if _, err := conn.Write(buildCR("Administrator", protoHybrid|protoSSL)); err != nil {
		t.Fatalf("write CR: %v", err)
	}
	if got := readConfirm(t, conn); got != protoHybrid {
		t.Fatalf("selected protocol = %#x, want Hybrid", got)
	}

	probe := h.WaitFor(t, "probe")
	if probe.Data["username"] != "Administrator" || probe.Data["nla"] != true {
		t.Errorf("probe = %v, want username=Administrator nla=true", probe.Data)
	}

	// The client now drives TLS, then CredSSP inside it.
	tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("TLS handshake: %v", err)
	}

	// TSRequest 1: NTLM NEGOTIATE.
	if _, err := tlsConn.Write(tsRequest(ntlmNegotiate())); err != nil {
		t.Fatalf("write negotiate: %v", err)
	}
	// TSRequest 2: the server's CHALLENGE — read it to stay in step.
	if _, err := readDER(tlsConn); err != nil {
		t.Fatalf("read challenge: %v", err)
	}
	// TSRequest 3: NTLM AUTHENTICATE. The NT response is longer than 24 bytes, so
	// it is read as NTLMv2; the exact bytes stand in for a real one.
	ntResp := bytes.Repeat([]byte{0xAB}, 44)
	if _, err := tlsConn.Write(tsRequest(ntlmAuthenticate("jsmith", "CORP", ntResp))); err != nil {
		t.Fatalf("write authenticate: %v", err)
	}

	ev := h.WaitFor(t, "auth_attempt")
	if ev.Data["username"] != "jsmith" {
		t.Errorf("username = %v, want jsmith", ev.Data["username"])
	}
	if ev.Data["domain"] != "CORP" {
		t.Errorf("domain = %v, want CORP", ev.Data["domain"])
	}
	if ev.Data["mstshash"] != "Administrator" {
		t.Errorf("mstshash = %v, want Administrator", ev.Data["mstshash"])
	}
	if ev.Data["hashcat_mode"] != 5600 {
		t.Errorf("hashcat_mode = %v, want 5600", ev.Data["hashcat_mode"])
	}
	line, _ := ev.Data["netntlmv2"].(string)
	// user::domain:serverchallenge:NTproof:blob, with the recorded fixed challenge.
	wantPrefix := "jsmith::CORP:1122334455667788:" + hex.EncodeToString(ntResp[:16]) + ":"
	if !strings.HasPrefix(line, wantPrefix) {
		t.Fatalf("netntlmv2 = %q\nwant prefix %q", line, wantPrefix)
	}
}

func TestBareConnectionAndNonRDP(t *testing.T) {
	h := start(t)
	conn := h.Dial()
	conn.Close()
	if ev := h.WaitFor(t, "connection"); ev.Service != name {
		t.Errorf("service = %q, want %q", ev.Service, name)
	}

	h2 := start(t)
	c2 := h2.Dial()
	if _, err := c2.Write([]byte("GET / HTTP/1.1\r\n\r\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	h2.WaitFor(t, "connection")
	h2.Quiet(t, "probe")
}

// --- minimal NTLM message construction (the client half) ------------------

func utf16le(s string) []byte {
	units := utf16.Encode([]rune(s))
	out := make([]byte, len(units)*2)
	for i, u := range units {
		binary.LittleEndian.PutUint16(out[i*2:], u)
	}
	return out
}

func ntlmNegotiate() []byte {
	var w bytes.Buffer
	w.Write([]byte("NTLMSSP\x00"))
	_ = binary.Write(&w, binary.LittleEndian, uint32(1))          // type 1
	_ = binary.Write(&w, binary.LittleEndian, uint32(0x00088207)) // flags
	w.Write(make([]byte, 16))                                     // empty domain + workstation fields
	return w.Bytes()
}

// ntlmAuthenticate lays out a type-3 message with the payload after a 64-byte
// header (no Version), so the field offsets are straightforward.
func ntlmAuthenticate(user, domain string, ntResp []byte) []byte {
	u := utf16le(user)
	d := utf16le(domain)

	const base = 64
	offNT := base
	offDom := offNT + len(ntResp)
	offUser := offDom + len(d)

	var w bytes.Buffer
	w.Write([]byte("NTLMSSP\x00"))
	_ = binary.Write(&w, binary.LittleEndian, uint32(3)) // type 3
	field := func(length, offset int) {
		_ = binary.Write(&w, binary.LittleEndian, uint16(length))
		_ = binary.Write(&w, binary.LittleEndian, uint16(length))
		_ = binary.Write(&w, binary.LittleEndian, uint32(offset))
	}
	field(0, base) // LmChallengeResponse (empty)
	field(len(ntResp), offNT)
	field(len(d), offDom)                                         // DomainName
	field(len(u), offUser)                                        // UserName
	field(0, 0)                                                   // Workstation
	field(0, 0)                                                   // EncryptedRandomSessionKey
	_ = binary.Write(&w, binary.LittleEndian, uint32(0x00088205)) // NegotiateFlags
	// payload in the order the offsets declare
	w.Write(ntResp)
	w.Write(d)
	w.Write(u)
	return w.Bytes()
}
