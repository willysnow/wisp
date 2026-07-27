package sipsvc

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/willysnow/wisp/internal/service"
	"github.com/willysnow/wisp/internal/service/servicetest"
)

func start(t *testing.T) *servicetest.PacketHarness {
	return servicetest.StartPacket(t, func(addr string) service.PacketService {
		return New(addr, "", "")
	})
}

func md5hex(s string) string {
	sum := md5.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}

// digestResponse computes a SIP/HTTP digest response the way a real client does,
// so the tests can play a client that actually authenticates.
func digestResponse(user, realm, pass, method, uri, nonce, qop, nc, cnonce string) string {
	ha1 := md5hex(user + ":" + realm + ":" + pass)
	ha2 := md5hex(method + ":" + uri)
	if qop == "" {
		return md5hex(ha1 + ":" + nonce + ":" + ha2)
	}
	return md5hex(ha1 + ":" + nonce + ":" + nc + ":" + cnonce + ":" + qop + ":" + ha2)
}

func registerNoAuth() string {
	return strings.Join([]string{
		"REGISTER sip:pbx.local SIP/2.0",
		"Via: SIP/2.0/UDP 10.0.0.5:5060;branch=z9hG4bK-1",
		`From: "1001" <sip:1001@pbx.local>;tag=abc`,
		"To: <sip:1001@pbx.local>",
		"Call-ID: test-call-id@10.0.0.5",
		"CSeq: 1 REGISTER",
		"User-Agent: friendly-scanner",
		"Max-Forwards: 70",
		"Content-Length: 0",
		"", "",
	}, "\r\n")
}

// serverChallenge sends an unauthenticated REGISTER and reads the realm and
// nonce back out of the 401 the decoy issues.
func serverChallenge(t *testing.T, h *servicetest.PacketHarness) (realm, nonce string) {
	t.Helper()
	h.Send([]byte(registerNoAuth()))
	reply, ok := h.Reply()
	if !ok {
		t.Fatal("no 401 challenge from the decoy")
	}
	if !strings.HasPrefix(string(reply), "SIP/2.0 401") {
		t.Fatalf("expected a 401, got: %q", firstLine(reply))
	}
	for _, line := range strings.Split(strings.ReplaceAll(string(reply), "\r\n", "\n"), "\n") {
		if v, ok := strings.CutPrefix(line, "WWW-Authenticate:"); ok {
			d := parseDigest(v)
			return d["realm"], d["nonce"]
		}
	}
	t.Fatal("401 carried no WWW-Authenticate challenge")
	return "", ""
}

func firstLine(b []byte) string {
	if i := strings.IndexByte(string(b), '\r'); i >= 0 {
		return string(b[:i])
	}
	return string(b)
}

func TestDigestCaptured(t *testing.T) {
	runDigestCase(t, "", "", "") // no qop
}

func TestDigestCapturedWithQOP(t *testing.T) {
	runDigestCase(t, "auth", "00000001", "0a4f113b") // qop=auth
}

func runDigestCase(t *testing.T, qop, nc, cnonce string) {
	h := start(t)
	realm, nonce := serverChallenge(t, h)
	if realm != "asterisk" || nonce == "" {
		t.Fatalf("challenge realm=%q nonce=%q", realm, nonce)
	}

	const (
		user     = "1001"
		password = "s3cr3tVoIP"
		uri      = "sip:pbx.local"
		method   = "REGISTER"
	)
	resp := digestResponse(user, realm, password, method, uri, nonce, qop, nc, cnonce)

	auth := fmt.Sprintf(`Digest username="%s", realm="%s", nonce="%s", uri="%s", response="%s", algorithm=MD5`,
		user, realm, nonce, uri, resp)
	if qop != "" {
		auth += fmt.Sprintf(`, qop=%s, nc=%s, cnonce="%s"`, qop, nc, cnonce)
	}

	msg := strings.Join([]string{
		"REGISTER sip:pbx.local SIP/2.0",
		"Via: SIP/2.0/UDP 10.0.0.5:5060;branch=z9hG4bK-2",
		`From: "1001" <sip:1001@pbx.local>;tag=abc`,
		"To: <sip:1001@pbx.local>",
		"Call-ID: test-call-id@10.0.0.5",
		"CSeq: 2 REGISTER",
		"User-Agent: friendly-scanner",
		"Authorization: " + auth,
		"Content-Length: 0",
		"", "",
	}, "\r\n")

	h.Send([]byte(msg))
	if reply, ok := h.Reply(); !ok || !strings.HasPrefix(string(reply), "SIP/2.0 403") {
		t.Fatalf("expected 403 after auth, got ok=%v line=%q", ok, firstLine(reply))
	}

	ev := h.WaitFor(t, "auth_attempt")
	if ev.Data["username"] != user {
		t.Errorf("username = %v, want %s", ev.Data["username"], user)
	}
	if ev.Data["realm"] != realm {
		t.Errorf("realm = %v, want %s", ev.Data["realm"], realm)
	}
	if ev.Data["hashcat_mode"] != 11400 {
		t.Errorf("hashcat_mode = %v, want 11400", ev.Data["hashcat_mode"])
	}
	assertCrackable(t, ev.Data, password)
}

// assertCrackable proves two things: the captured components re-derive the
// response from the known password (so a wordlist cracks them), and the
// assembled hashcat line reconstructs the same digest URI (so hashcat's HA2
// matches the client's).
func assertCrackable(t *testing.T, data map[string]any, password string) {
	t.Helper()
	get := func(k string) string { s, _ := data[k].(string); return s }

	want := digestResponse(get("username"), get("realm"), password,
		get("method"), get("uri"), get("nonce"), get("qop"), get("nc"), get("cnonce"))
	if want != get("response") {
		t.Fatalf("recorded response does not verify against the password:\n got %s\nwant %s",
			get("response"), want)
	}

	line := get("sip_hash")
	rest, ok := strings.CutPrefix(line, "$sip$*")
	if !ok {
		t.Fatalf("sip_hash = %q, missing $sip$* prefix", line)
	}
	f := strings.Split(rest, "*")
	if len(f) != 14 {
		t.Fatalf("sip_hash has %d fields, want 14: %q", len(f), line)
	}
	prefix, resource, suffix := f[5], f[6], f[7]
	if got := prefix + ":" + resource + suffix; got != get("uri") {
		t.Fatalf("hash URI split %q does not reconstruct %q", got, get("uri"))
	}
	if f[12] != "MD5" {
		t.Errorf("hash directive = %q, want MD5", f[12])
	}
	if f[13] != get("response") {
		t.Errorf("hash response = %q, want %q", f[13], get("response"))
	}
}

func TestOptionsLooksAlive(t *testing.T) {
	h := start(t)
	msg := strings.Join([]string{
		"OPTIONS sip:pbx.local SIP/2.0",
		"Via: SIP/2.0/UDP 10.0.0.9:5060;branch=z9hG4bK-x",
		"From: <sip:svmap@10.0.0.9>;tag=root",
		"To: <sip:pbx.local>",
		"Call-ID: opt-1",
		"CSeq: 1 OPTIONS",
		"User-Agent: friendly-scanner",
		"Content-Length: 0",
		"", "",
	}, "\r\n")

	h.Send([]byte(msg))
	reply, ok := h.Reply()
	if !ok || !strings.HasPrefix(string(reply), "SIP/2.0 200") {
		t.Fatalf("OPTIONS should get 200 OK, got ok=%v line=%q", ok, firstLine(reply))
	}

	ev := h.WaitFor(t, "probe")
	if ev.Data["method"] != "OPTIONS" {
		t.Errorf("method = %v, want OPTIONS", ev.Data["method"])
	}
	if ev.Data["user_agent"] != "friendly-scanner" {
		t.Errorf("user_agent = %v, want friendly-scanner", ev.Data["user_agent"])
	}
}

func TestNonSIPDatagramIgnored(t *testing.T) {
	h := start(t)
	h.Send([]byte("this is not a SIP message\r\n\r\n"))
	if _, ok := h.Reply(); ok {
		t.Fatal("decoy answered a non-SIP datagram; it must not be an amplifier")
	}
	h.Quiet(t, "probe")
	h.Quiet(t, "auth_attempt")
}
