package vncsvc

import (
	"bytes"
	"crypto/des"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net"
	"strings"
	"testing"

	"github.com/willysnow/wisp/internal/service"
	"github.com/willysnow/wisp/internal/service/servicetest"
)

func start(t *testing.T) *servicetest.StreamHarness {
	return servicetest.StartStream(t, func(addr string) service.StreamService {
		return New(addr, "3.8")
	})
}

// vncResponse computes a VNC Authentication response the way a real client does:
// DES-ECB over each 8-byte half of the challenge, keyed by the password with
// each key byte's bits reversed — the quirk that makes VNC auth its own thing.
func vncResponse(password string, challenge []byte) []byte {
	key := make([]byte, 8)
	copy(key, password)
	for i := range key {
		key[i] = reverseBits(key[i])
	}
	block, err := des.NewCipher(key)
	if err != nil {
		panic(err)
	}
	out := make([]byte, challengeSize)
	block.Encrypt(out[0:8], challenge[0:8])
	block.Encrypt(out[8:16], challenge[8:16])
	return out
}

func reverseBits(b byte) byte {
	var r byte
	for i := 0; i < 8; i++ {
		r = (r << 1) | (b & 1)
		b >>= 1
	}
	return r
}

// readBanner reads and sanity-checks the server's ProtocolVersion.
func readBanner(t *testing.T, conn net.Conn) string {
	t.Helper()
	var b [12]byte
	if _, err := io.ReadFull(conn, b[:]); err != nil {
		t.Fatalf("read banner: %v", err)
	}
	if !strings.HasPrefix(string(b[:]), "RFB 003.") {
		t.Fatalf("banner = %q, want an RFB 3.x version", b[:])
	}
	return string(b[:])
}

func TestVNCAuthCaptured(t *testing.T) {
	h := start(t)
	conn := h.Dial()

	readBanner(t, conn)
	if _, err := conn.Write([]byte("RFB 003.008\n")); err != nil {
		t.Fatalf("write version: %v", err)
	}

	// Security types: exactly one, VNC Authentication — never None.
	var count [1]byte
	if _, err := io.ReadFull(conn, count[:]); err != nil {
		t.Fatalf("read type count: %v", err)
	}
	types := make([]byte, count[0])
	if _, err := io.ReadFull(conn, types); err != nil {
		t.Fatalf("read types: %v", err)
	}
	if !bytes.Equal(types, []byte{secVNCAuth}) {
		t.Fatalf("offered types = %v, want only VNC Authentication (2)", types)
	}
	if _, err := conn.Write([]byte{secVNCAuth}); err != nil {
		t.Fatalf("select type: %v", err)
	}

	var challenge [challengeSize]byte
	if _, err := io.ReadFull(conn, challenge[:]); err != nil {
		t.Fatalf("read challenge: %v", err)
	}

	const password = "hunter2"
	if _, err := conn.Write(vncResponse(password, challenge[:])); err != nil {
		t.Fatalf("write response: %v", err)
	}

	// The result is always a failure, never OK.
	var result [4]byte
	if _, err := io.ReadFull(conn, result[:]); err != nil {
		t.Fatalf("read result: %v", err)
	}
	if got := binary.BigEndian.Uint32(result[:]); got != securityResultFailed {
		t.Fatalf("security result = %d, want %d (failed)", got, securityResultFailed)
	}

	ev := h.WaitFor(t, "auth_attempt")
	if ev.Data["client_version"] != "RFB 003.008" {
		t.Errorf("client_version = %v, want RFB 003.008", ev.Data["client_version"])
	}
	if ev.Data["challenge"] != hex.EncodeToString(challenge[:]) {
		t.Errorf("challenge = %v, want %x", ev.Data["challenge"], challenge)
	}
	if ev.Data["john_format"] != "vnc" {
		t.Errorf("john_format = %v, want vnc", ev.Data["john_format"])
	}
	assertCrackable(t, ev.Data["vnc_hash"].(string), password)
}

// assertCrackable proves the captured line is a genuine artifact: re-deriving
// the response from the known password and the recorded challenge must reproduce
// exactly what was logged, which is what a wordlist attack does.
func assertCrackable(t *testing.T, line, password string) {
	t.Helper()
	rest, ok := strings.CutPrefix(line, "$vnc$*")
	if !ok {
		t.Fatalf("vnc_hash = %q, missing $vnc$* prefix", line)
	}
	chalHex, respHex, ok := strings.Cut(rest, "*")
	if !ok {
		t.Fatalf("vnc_hash = %q, missing challenge*response separator", line)
	}
	challenge, err := hex.DecodeString(chalHex)
	if err != nil || len(challenge) != challengeSize {
		t.Fatalf("challenge not %d hex bytes: %q", challengeSize, chalHex)
	}
	want, err := hex.DecodeString(respHex)
	if err != nil {
		t.Fatalf("response not hex: %q", respHex)
	}
	if got := vncResponse(password, challenge); !bytes.Equal(got, want) {
		t.Fatalf("recorded response does not verify against the password:\n got %x\nwant %x", want, got)
	}
}

func TestRFB33DirectSecurityType(t *testing.T) {
	h := start(t)
	conn := h.Dial()

	readBanner(t, conn)
	// An RFB 3.3 client: the server dictates a single 4-byte security type with
	// no negotiation.
	if _, err := conn.Write([]byte("RFB 003.003\n")); err != nil {
		t.Fatalf("write version: %v", err)
	}

	var st [4]byte
	if _, err := io.ReadFull(conn, st[:]); err != nil {
		t.Fatalf("read security type: %v", err)
	}
	if got := binary.BigEndian.Uint32(st[:]); got != secVNCAuth {
		t.Fatalf("security type = %d, want VNC Authentication (2)", got)
	}

	var challenge [challengeSize]byte
	if _, err := io.ReadFull(conn, challenge[:]); err != nil {
		t.Fatalf("read challenge: %v", err)
	}
	const password = "letmein"
	if _, err := conn.Write(vncResponse(password, challenge[:])); err != nil {
		t.Fatalf("write response: %v", err)
	}
	// RFB 3.3 gets a bare 4-byte failure with no reason string.
	var result [4]byte
	if _, err := io.ReadFull(conn, result[:]); err != nil {
		t.Fatalf("read result: %v", err)
	}
	if got := binary.BigEndian.Uint32(result[:]); got != securityResultFailed {
		t.Fatalf("security result = %d, want failed", got)
	}

	ev := h.WaitFor(t, "auth_attempt")
	assertCrackable(t, ev.Data["vnc_hash"].(string), password)
}

func TestProbeOnVersionOnly(t *testing.T) {
	h := start(t)
	conn := h.Dial()

	readBanner(t, conn)
	if _, err := conn.Write([]byte("RFB 003.008\n")); err != nil {
		t.Fatalf("write version: %v", err)
	}
	// Read the offered types but leave without selecting one — the nmap
	// vnc-info shape, which should yield a probe and no auth attempt.
	var count [1]byte
	if _, err := io.ReadFull(conn, count[:]); err != nil {
		t.Fatalf("read type count: %v", err)
	}
	types := make([]byte, count[0])
	_, _ = io.ReadFull(conn, types)
	conn.Close()

	ev := h.WaitFor(t, "probe")
	if ev.Data["client_version"] != "RFB 003.008" {
		t.Errorf("client_version = %v, want RFB 003.008", ev.Data["client_version"])
	}
	h.Quiet(t, "auth_attempt")
}

func TestConnectionOnSilence(t *testing.T) {
	h := start(t)
	conn := h.Dial()
	// Read the banner the server volunteers, then leave: a bare port touch.
	readBanner(t, conn)
	conn.Close()

	ev := h.WaitFor(t, "connection")
	if ev.Service != name {
		t.Errorf("service = %q, want %q", ev.Service, name)
	}
	h.Quiet(t, "auth_attempt")
	h.Quiet(t, "probe")
}
