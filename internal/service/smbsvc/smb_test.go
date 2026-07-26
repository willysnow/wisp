package smbsvc

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5" //nolint:gosec // NTLMv2 is defined in terms of HMAC-MD5; not our choice
	"encoding/hex"
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/md4" //nolint:staticcheck // NTLM hashes the password with MD4; not our choice

	"github.com/willysnow/wisp/internal/service"
	"github.com/willysnow/wisp/internal/service/servicetest"
)

func start(t *testing.T) (*servicetest.StreamHarness, net.Conn) {
	t.Helper()

	h := servicetest.StartStream(t, func(addr string) service.StreamService {
		return New(addr, "FILESERVER", "CORP")
	})
	conn := h.Dial()
	return h, conn
}

// --- the transport and a hand-written SMB2 client -------------------------

func sendTransport(t *testing.T, conn net.Conn, msg []byte) {
	t.Helper()

	frame := []byte{0, byte(len(msg) >> 16), byte(len(msg) >> 8), byte(len(msg))}
	if _, err := conn.Write(append(frame, msg...)); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func recvTransport(t *testing.T, conn net.Conn) []byte {
	t.Helper()

	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	var prefix [4]byte
	if _, err := readFull(conn, prefix[:]); err != nil {
		t.Fatalf("read prefix: %v", err)
	}
	length := int(prefix[1])<<16 | int(prefix[2])<<8 | int(prefix[3])
	msg := make([]byte, length)
	if _, err := readFull(conn, msg); err != nil {
		t.Fatalf("read body: %v", err)
	}
	return msg
}

func readFull(conn net.Conn, p []byte) (int, error) {
	got := 0
	for got < len(p) {
		n, err := conn.Read(p[got:])
		got += n
		if err != nil {
			return got, err
		}
	}
	return got, nil
}

// smb2 builds a request: the 64-byte sync header followed by body.
func smb2(command uint16, messageID, sessionID uint64, body []byte) []byte {
	h := make([]byte, smbHeaderSize)
	copy(h[0:4], protocolSMB2[:])
	le.PutUint16(h[4:6], smbHeaderSize)
	le.PutUint16(h[6:8], 1) // CreditCharge
	le.PutUint16(h[12:14], command)
	le.PutUint16(h[14:16], 1) // CreditRequest
	le.PutUint64(h[24:32], messageID)
	le.PutUint64(h[40:48], sessionID)
	return append(h, body...)
}

// respSessionID and respStatus pull the two header fields the client acts on.
func respStatus(msg []byte) uint32    { return le.Uint32(msg[8:12]) }
func respSessionID(msg []byte) uint64 { return le.Uint64(msg[40:48]) }
func respBody(msg []byte) []byte      { return msg[smbHeaderSize:] }

func negotiateRequest(dialects ...uint16) []byte {
	w := &buf{}
	w.u16(36) // StructureSize
	w.u16(uint16(len(dialects)))
	w.u16(1)                // SecurityMode: signing enabled
	w.u16(0)                // Reserved
	w.u32(0)                // Capabilities
	w.raw(make([]byte, 16)) // ClientGuid
	w.u64(0)                // ClientStartTime
	for _, d := range dialects {
		w.u16(d)
	}
	return w.bytes()
}

func sessionSetupRequest(security []byte) []byte {
	const fixed = 24
	offset := smbHeaderSize + fixed

	w := &buf{}
	w.u16(25) // StructureSize
	w.u8(0)   // Flags
	w.u8(1)   // SecurityMode
	w.u32(0)  // Capabilities
	w.u32(0)  // Channel
	w.u16(uint16(offset))
	w.u16(uint16(len(security)))
	w.u64(0) // PreviousSessionId
	w.raw(security)
	return w.bytes()
}

// --- NTLM message construction (the client half) --------------------------

func ntlmType1() []byte {
	w := &buf{}
	w.raw(ntlmSignature)
	w.u32(ntlmNegotiate)
	w.u32(flagUnicode | flagRequestTgt | flagNTLM | flagExtendedSec)
	w.zeros(16) // empty domain + workstation fields
	return w.bytes()
}

// ntlmType3 lays out an AUTHENTICATE message with the payload after a 64-byte
// header (no Version, no MIC), so the field offsets are straightforward.
func ntlmType3(user, domain, workstation string, lmResp, ntResp []byte) []byte {
	u := utf16le(user)
	d := utf16le(domain)
	ws := utf16le(workstation)

	const base = 64
	offLM := base
	offNT := offLM + len(lmResp)
	offDom := offNT + len(ntResp)
	offUser := offDom + len(d)
	offWS := offUser + len(u)

	w := &buf{}
	w.raw(ntlmSignature)
	w.u32(ntlmAuthenticate)
	field := func(length, offset int) {
		w.u16(uint16(length))
		w.u16(uint16(length))
		w.u32(uint32(offset))
	}
	field(len(lmResp), offLM) // LmChallengeResponse
	field(len(ntResp), offNT) // NtChallengeResponse
	field(len(d), offDom)     // DomainName
	field(len(u), offUser)    // UserName
	field(len(ws), offWS)     // Workstation
	field(0, 0)               // EncryptedRandomSessionKey
	w.u32(flagUnicode | flagNTLM | flagExtendedSec)
	// payload, in the order the offsets above declare
	w.raw(lmResp)
	w.raw(ntResp)
	w.raw(d)
	w.raw(u)
	w.raw(ws)
	return w.bytes()
}

// --- NTLMv2 cryptography (the genuine computation, for the round trip) -----

func md4sum(b []byte) []byte {
	h := md4.New()
	h.Write(b)
	return h.Sum(nil)
}

func hmacMD5(key, data []byte) []byte {
	m := hmac.New(md5.New, key)
	m.Write(data)
	return m.Sum(nil)
}

// ntowfv2 is the NTLMv2 key: HMAC-MD5(MD4(unicode(pass)), unicode(UPPER(user)+domain)).
func ntowfv2(pass, user, domain string) []byte {
	return hmacMD5(md4sum(utf16le(pass)), utf16le(strings.ToUpper(user)+domain))
}

// clientBlob builds the NTLMv2_CLIENT_CHALLENGE ("temp"): the structure whose
// bytes follow the 16-byte proof in an NTLMv2 NT response, and the exact thing
// hashcat calls the blob.
func clientBlob(timestamp uint64, clientChallenge [8]byte, targetInfo []byte) []byte {
	w := &buf{}
	w.u8(1) // RespType
	w.u8(1) // HiRespType
	w.u16(0)
	w.u32(0)
	w.u64(timestamp)
	w.raw(clientChallenge[:])
	w.u32(0)
	w.raw(targetInfo)
	w.u32(0)
	return w.bytes()
}

// ntlmv2Response computes the NT response an honest client would send, and
// returns it split the way the hash format needs.
func ntlmv2Response(pass, user, domain string, serverChallenge [8]byte, blob []byte) (ntResp, proof []byte) {
	key := ntowfv2(pass, user, domain)
	proof = hmacMD5(key, append(append([]byte(nil), serverChallenge[:]...), blob...))
	ntResp = append(append([]byte(nil), proof...), blob...)
	return ntResp, proof
}

// --- extracting our decoy's challenge from its response -------------------

func challengeAndTargetInfo(t *testing.T, ntlm []byte) (challenge [8]byte, targetInfo []byte) {
	t.Helper()

	if len(ntlm) < 48 {
		t.Fatalf("challenge message too short: %d bytes", len(ntlm))
	}
	copy(challenge[:], ntlm[24:32])
	tiLen := int(le.Uint16(ntlm[40:42]))
	tiOff := int(le.Uint32(ntlm[44:48]))
	if tiOff+tiLen > len(ntlm) {
		t.Fatalf("target info runs past the message")
	}
	targetInfo = ntlm[tiOff : tiOff+tiLen]
	return challenge, targetInfo
}

// handshake drives negotiate → session setup type1 → reads the challenge.
// Returns the connection's session id and the decoy's challenge + target info.
func handshake(t *testing.T, conn net.Conn) (sessionID uint64, challenge [8]byte, targetInfo []byte) {
	t.Helper()

	sendTransport(t, conn, smb2(cmdNegotiate, 0, 0, negotiateRequest(
		dialect202, dialect210, dialect300, dialect302)))
	neg := recvTransport(t, conn)
	if respStatus(neg) != statusSuccess {
		t.Fatalf("negotiate status = %#x, want success", respStatus(neg))
	}

	sendTransport(t, conn, smb2(cmdSessionSetup, 1, 0, sessionSetupRequest(ntlmType1())))
	resp := recvTransport(t, conn)
	if respStatus(resp) != statusMoreProcessingReq {
		t.Fatalf("session setup 1 status = %#x, want MORE_PROCESSING_REQUIRED", respStatus(resp))
	}

	ntlm := findNTLMSSP(sessionSecurity(t, respBody(resp)))
	if ntlm == nil {
		t.Fatal("no NTLM challenge in the session setup response")
	}
	if kind, _ := ntlmType(ntlm); kind != ntlmChallenge {
		t.Fatalf("response NTLM type = %d, want a challenge", kind)
	}

	challenge, targetInfo = challengeAndTargetInfo(t, ntlm)
	return respSessionID(resp), challenge, targetInfo
}

// sessionSecurity reads the security buffer out of a session-setup response.
func sessionSecurity(t *testing.T, body []byte) []byte {
	t.Helper()
	if len(body) < 8 {
		t.Fatal("session setup response too short")
	}
	off := int(le.Uint16(body[4:6])) - smbHeaderSize
	length := int(le.Uint16(body[6:8]))
	if off < 0 || off+length > len(body) {
		t.Fatalf("security buffer out of range: off=%d len=%d body=%d", off, length, len(body))
	}
	return body[off : off+length]
}

// TestNetNTLMv2IsCapturedAndCracks is the test the whole module exists to pass.
//
// A genuine NTLMv2 response is computed for a known password, sent through the
// decoy, and the emitted hashcat line is checked. Then — the part that matters —
// the proof is recomputed from the components of that very line using the known
// password, and must match. That is what "crackable offline" means made
// executable: if this passes, an analyst with the captured line and a wordlist
// containing the password recovers it, because that is exactly the computation
// hashcat mode 5600 runs.
func TestNetNTLMv2IsCapturedAndCracks(t *testing.T) {
	const (
		user     = "jsmith"
		domain   = "CORP"
		wksta    = "WKS-4021"
		password = "Winter2026!"
	)

	h, conn := start(t)
	sessionID, challenge, targetInfo := handshake(t, conn)

	if challenge != fixedChallenge {
		t.Errorf("server challenge = %x, want the fixed %x", challenge, fixedChallenge)
	}

	clientChallenge := [8]byte{0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04}
	blob := clientBlob(nowFiletime(), clientChallenge, targetInfo)
	ntResp, proof := ntlmv2Response(password, user, domain, challenge, blob)

	lmResp := make([]byte, 24) // an NTLMv2 client also sends LMv2 here; zeros suffice for the NT capture
	auth := ntlmType3(user, domain, wksta, lmResp, ntResp)
	sendTransport(t, conn, smb2(cmdSessionSetup, 2, sessionID, sessionSetupRequest(auth)))

	resp := recvTransport(t, conn)
	if respStatus(resp) != statusLogonFailure {
		t.Fatalf("auth status = %#x, want LOGON_FAILURE — nothing may be accepted", respStatus(resp))
	}

	ev := h.WaitFor(t, "auth_attempt")
	if ev.Data["username"] != user {
		t.Errorf("username = %v, want %q", ev.Data["username"], user)
	}
	if ev.Data["domain"] != domain {
		t.Errorf("domain = %v, want %q", ev.Data["domain"], domain)
	}
	if ev.Data["workstation"] != wksta {
		t.Errorf("workstation = %v, want %q", ev.Data["workstation"], wksta)
	}
	if ev.Data["ntlm_version"] != "v2" {
		t.Errorf("ntlm_version = %v, want v2", ev.Data["ntlm_version"])
	}

	line, _ := ev.Data["netntlmv2"].(string)
	if line == "" {
		t.Fatalf("no netntlmv2 line captured: %v", ev.Data)
	}

	// hashcat 5600 is user::domain:challenge:proof:blob — the empty LM slot
	// between the two colons after the username means a correct line splits into
	// six fields, not five.
	parts := strings.Split(line, ":")
	if len(parts) != 6 || parts[1] != "" {
		t.Fatalf("netntlmv2 = %q, want the hashcat 5600 shape user::domain:...", line)
	}
	gotUser, gotDomain := parts[0], parts[2]
	gotChallenge, gotProof, gotBlob := parts[3], parts[4], parts[5]
	if gotUser != user || gotDomain != domain {
		t.Errorf("line names %s::%s, want %s::%s", gotUser, gotDomain, user, domain)
	}
	if gotChallenge != hex.EncodeToString(fixedChallenge[:]) {
		t.Errorf("line challenge = %s, want the fixed one", gotChallenge)
	}
	if gotProof != hex.EncodeToString(proof) {
		t.Errorf("line proof = %s, want %s", gotProof, hex.EncodeToString(proof))
	}

	// The crack itself: recompute the proof from the line's own fields with the
	// known password, exactly as a cracker would.
	crackChallenge, _ := hex.DecodeString(gotChallenge)
	crackBlob, err := hex.DecodeString(gotBlob)
	if err != nil {
		t.Fatalf("blob is not hex: %v", err)
	}
	key := ntowfv2(password, gotUser, gotDomain)
	recomputed := hmacMD5(key, append(append([]byte(nil), crackChallenge...), crackBlob...))
	if hex.EncodeToString(recomputed) != gotProof {
		t.Fatal("the captured line does not crack with the real password — it is not a usable hash")
	}

	// And a wrong password must not verify, or the line would "crack" to
	// anything.
	wrong := ntowfv2("not-the-password", gotUser, gotDomain)
	if bytes.Equal(hmacMD5(wrong, append(append([]byte(nil), crackChallenge...), crackBlob...)), recomputed) {
		t.Fatal("a wrong password verified against the captured hash")
	}
}

// TestNothingIsEverAccepted. Every path through session setup ends in a logon
// failure; a regression that returned success would tell an intruder the share
// is theirs.
func TestNothingIsEverAccepted(t *testing.T) {
	h, conn := start(t)
	sessionID, challenge, targetInfo := handshake(t, conn)

	blob := clientBlob(nowFiletime(), [8]byte{1, 2, 3, 4, 5, 6, 7, 8}, targetInfo)
	ntResp, _ := ntlmv2Response("whatever", "admin", "CORP", challenge, blob)
	auth := ntlmType3("admin", "CORP", "PC", make([]byte, 24), ntResp)
	sendTransport(t, conn, smb2(cmdSessionSetup, 2, sessionID, sessionSetupRequest(auth)))

	resp := recvTransport(t, conn)
	if respStatus(resp) != statusLogonFailure {
		t.Errorf("status = %#x, want LOGON_FAILURE", respStatus(resp))
	}
	h.WaitFor(t, "auth_attempt")
}

// TestRepeatedAuthEmitsOneEvent. A sprayer retries on the same connection, and
// a decoy that logged every attempt would volunteer the very flood the rate
// limiter exists to survive.
func TestRepeatedAuthEmitsOneEvent(t *testing.T) {
	h, conn := start(t)
	sessionID, challenge, targetInfo := handshake(t, conn)

	for i := 0; i < 5; i++ {
		blob := clientBlob(nowFiletime(), [8]byte{byte(i)}, targetInfo)
		ntResp, _ := ntlmv2Response("p", "user", "CORP", challenge, blob)
		auth := ntlmType3("user", "CORP", "PC", make([]byte, 24), ntResp)
		sendTransport(t, conn, smb2(cmdSessionSetup, uint64(2+i), sessionID, sessionSetupRequest(auth)))
		recvTransport(t, conn)
	}

	// Give any stray events time to arrive before counting.
	time.Sleep(50 * time.Millisecond)
	if n := h.Count("auth_attempt"); n != 1 {
		t.Errorf("emitted %d auth_attempt events for one connection, want 1", n)
	}
}

// TestBareConnectionIsAScan. A TCP connect that says nothing is a port sweep,
// and worth exactly one event so it shows up without burying anything.
func TestBareConnectionIsAScan(t *testing.T) {
	h, conn := start(t)
	_ = conn.Close()

	ev := h.WaitFor(t, "connection")
	if ev.Service != "smb" {
		t.Errorf("service = %q, want smb", ev.Service)
	}
	if h.Count("auth_attempt") != 0 {
		t.Error("a silent connection produced an auth event")
	}
}

// TestNegotiateSelects311WithContexts. A modern client offering 3.1.1 has to be
// answered in 3.1.1 with the preauth-integrity context, or it aborts before it
// ever sends a credential.
func TestNegotiateSelects311WithContexts(t *testing.T) {
	_, conn := start(t)

	sendTransport(t, conn, smb2(cmdNegotiate, 0, 0, negotiateRequest(
		dialect202, dialect210, dialect300, dialect302, dialect311)))
	neg := recvTransport(t, conn)

	body := respBody(neg)
	if got := le.Uint16(body[4:6]); got != dialect311 {
		t.Errorf("selected dialect %#x, want 3.1.1 when offered", got)
	}
	if got := le.Uint16(body[6:8]); got != 2 {
		t.Errorf("negotiate context count = %d, want 2", got)
	}

	// The preauth-integrity context (0x0001) must be present, or a strict
	// client walks away.
	if !bytes.Contains(neg, []byte{0x01, 0x00}) {
		t.Error("no negotiate contexts in the response")
	}
}

// TestSMB1NegotiateUpgrades. The legacy multi-protocol negotiate has to be
// steered up to SMB2, or a Windows client that opens with it never gets to the
// handshake that leaks the hash.
func TestSMB1NegotiateUpgrades(t *testing.T) {
	_, conn := start(t)

	// A minimal SMB1 NEGOTIATE: the SMB1 header with command 0x72 and an empty
	// dialect list is enough to exercise the upgrade path.
	smb1 := make([]byte, 35)
	copy(smb1[0:4], protocolSMB1[:])
	smb1[4] = 0x72 // SMB_COM_NEGOTIATE
	sendTransport(t, conn, smb1)

	resp := recvTransport(t, conn)
	if !bytes.Equal(resp[0:4], protocolSMB2[:]) {
		t.Fatal("SMB1 negotiate was not answered in SMB2")
	}
	if got := le.Uint16(respBody(resp)[4:6]); got != dialectWild {
		t.Errorf("dialect = %#x, want the 0x02FF wildcard that triggers an SMB2 negotiate", got)
	}
}

// TestOversizedTransportIsRefused. The 24-bit length prefix comes from a
// stranger; a decoy that allocated whatever it claimed would be a memory
// exhaustion primitive on an open port.
func TestOversizedTransportIsRefused(t *testing.T) {
	_, conn := start(t)

	// Claim a 10 MB message — over the cap — then send nothing. The server must
	// close rather than wait on a buffer it should never have sized.
	_, _ = conn.Write([]byte{0x00, 0xA0, 0x00, 0x00})
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))

	var b [1]byte
	if _, err := conn.Read(b[:]); err == nil {
		t.Error("the server answered an over-limit length prefix instead of closing")
	}
}

// TestGarbageIsNotSMB. A scanner throwing random bytes at 445 gets the
// connection closed, the same as a real server faced with a non-SMB first
// packet.
func TestGarbageIsNotSMB(t *testing.T) {
	h, conn := start(t)

	sendTransport(t, conn, []byte("GET / HTTP/1.1\r\n\r\n"))
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	var b [1]byte
	_, err := conn.Read(b[:])
	if err == nil {
		t.Error("garbage got a reply")
	}

	// It still counts as a connection, because something touched the port.
	h.WaitFor(t, "connection")
}

// TestParseAuthenticateRejectsTruncation exercises the parser directly on a
// message whose field offsets point past the end — the shape a fuzzer finds
// first.
func TestParseAuthenticateRejectsTruncation(t *testing.T) {
	msg := make([]byte, 64)
	copy(msg, ntlmSignature)
	le.PutUint32(msg[8:12], ntlmAuthenticate)
	// Point the NT response at a wild offset with a large length.
	le.PutUint16(msg[20:22], 0xFFFF)
	le.PutUint32(msg[24:28], 0xFFFFFFF0)

	// Must not panic, and must not invent a credential from nothing.
	if _, ok := parseAuthenticate(msg, fixedChallenge); ok {
		t.Error("a truncated authenticate message was accepted")
	}
}

// TestChallengeTargetInfoIsWellFormed. A real client folds the target-info
// AV-pair chain into the material it hashes and rejects a malformed one, so a
// structural bug here would be invisible to the round-trip test (which hashes
// whatever it is given) but fatal against Windows. Walk the chain the way a
// client does: each pair is Id(2)+Len(2)+Value, and it must end in EOL.
func TestChallengeTargetInfoIsWellFormed(t *testing.T) {
	_, conn := start(t)
	_, _, targetInfo := handshake(t, conn)

	seen := map[uint16]string{}
	i := 0
	sawEOL := false
	for i+4 <= len(targetInfo) {
		id := le.Uint16(targetInfo[i : i+2])
		l := int(le.Uint16(targetInfo[i+2 : i+4]))
		i += 4
		if i+l > len(targetInfo) {
			t.Fatalf("AV pair %#x claims %d bytes past the end", id, l)
		}
		if id == avEOL {
			if l != 0 {
				t.Errorf("EOL pair has length %d, want 0", l)
			}
			sawEOL = true
			i += l
			break
		}
		seen[id] = fromUTF16le(targetInfo[i : i+l])
		i += l
	}

	if !sawEOL {
		t.Error("target info does not terminate in an EOL pair")
	}
	if seen[avNbDomain] != "CORP" {
		t.Errorf("NbDomainName = %q, want CORP", seen[avNbDomain])
	}
	if seen[avNbComputer] != "FILESERVER" {
		t.Errorf("NbComputerName = %q, want FILESERVER", seen[avNbComputer])
	}
	if _, ok := seen[avDnsComputer]; !ok {
		t.Error("no DnsComputerName pair")
	}
}

// TestNegotiateAdvertisesNTLMSSP walks the SPNEGO token in the negotiate
// response as DER far enough to confirm it reaches the NTLMSSP mechanism OID. A
// client parses this to decide what to authenticate with; a malformed advert or
// the wrong OID sends it somewhere other than the handshake that leaks the hash.
func TestNegotiateAdvertisesNTLMSSP(t *testing.T) {
	_, conn := start(t)

	sendTransport(t, conn, smb2(cmdNegotiate, 0, 0, negotiateRequest(dialect210)))
	neg := recvTransport(t, conn)

	body := respBody(neg)
	secOff := int(le.Uint16(body[56:58])) - smbHeaderSize
	secLen := int(le.Uint16(body[58:60]))
	if secOff < 0 || secOff+secLen > len(body) {
		t.Fatalf("security buffer out of range: off=%d len=%d", secOff, secLen)
	}
	security := body[secOff : secOff+secLen]

	// The whole token has to parse as DER — a client's ASN.1 decoder will reject
	// it otherwise — and the NTLMSSP OID has to appear inside it.
	if !validDER(security) {
		t.Errorf("the SPNEGO advert is not well-formed DER: %x", security)
	}
	if !bytes.Contains(security, oidNTLMSSP) {
		t.Error("the negotiate advert does not offer the NTLMSSP mechanism")
	}
}

// validDER walks a DER structure, descending into constructed elements, and
// reports whether every tag/length is consistent to the end. It is only as
// complete as these tokens need — short and long-form lengths, constructed and
// primitive — which is exactly the subset the SPNEGO builder emits.
func validDER(b []byte) bool {
	i := 0
	for i < len(b) {
		if i+2 > len(b) {
			return false
		}
		tag := b[i]
		i++
		length := int(b[i])
		i++
		if length&0x80 != 0 {
			n := length & 0x7F
			if n == 0 || n > 2 || i+n > len(b) {
				return false
			}
			length = 0
			for k := 0; k < n; k++ {
				length = length<<8 | int(b[i])
				i++
			}
		}
		if i+length > len(b) {
			return false
		}
		// Constructed (bit 6 set): the content is itself DER. Recurse.
		if tag&0x20 != 0 {
			if !validDER(b[i : i+length]) {
				return false
			}
		}
		i += length
	}
	return true
}
