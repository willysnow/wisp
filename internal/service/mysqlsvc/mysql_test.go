package mysqlsvc

import (
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/willysnow/wisp/internal/service"
	"github.com/willysnow/wisp/internal/service/servicetest"
)

func start(t *testing.T) *servicetest.StreamHarness {
	return servicetest.StartStream(t, func(addr string) service.StreamService {
		return New(addr, "8.0.36")
	})
}

// nativeResponse computes a mysql_native_password response the way a real
// client does, so the tests can play a client that actually authenticates.
func nativeResponse(password string, scramble []byte) []byte {
	if password == "" {
		return nil
	}
	h1 := sha1.Sum([]byte(password))
	h2 := sha1.Sum(h1[:])
	h3 := sha1.Sum(append(append([]byte{}, scramble...), h2[:]...))
	out := make([]byte, 20)
	for i := range out {
		out[i] = h1[i] ^ h3[i]
	}
	return out
}

// serverScramble pulls the 20-byte scramble out of an Initial Handshake packet.
func serverScramble(t *testing.T, payload []byte) []byte {
	t.Helper()
	pos := 1 // protocol version
	_, pos = readCString(payload, pos)
	if pos < 0 {
		t.Fatal("handshake: no server version")
	}
	pos += 4 // connection id
	part1, pos := readN(payload, pos, 8)
	if pos < 0 {
		t.Fatal("handshake: truncated before scramble")
	}
	pos += 1 + 2 + 1 + 2 + 2 + 1 + 10 // filler, caps-lo, charset, status, caps-hi, authlen, reserved
	part2, pos := readN(payload, pos, 12)
	if pos < 0 {
		t.Fatal("handshake: truncated part-2 scramble")
	}
	return append(append([]byte{}, part1...), part2...)
}

type response struct {
	caps     uint32
	username string
	authResp []byte
	database string
	plugin   string
	attrs    map[string]string
}

// build encodes a HandshakeResponse41 the way a client would.
func (r response) build() []byte {
	w := &buf{}
	w.u32(r.caps)
	w.u32(0x01000000) // max packet
	w.u8(charsetUTF8MB4)
	w.zeros(23)
	w.cstr(r.username)

	if r.caps&capSecureConnection != 0 {
		w.u8(byte(len(r.authResp)))
		w.raw(r.authResp)
	} else {
		w.raw(r.authResp)
		w.u8(0)
	}
	if r.caps&capConnectWithDB != 0 {
		w.cstr(r.database)
	}
	if r.caps&capPluginAuth != 0 {
		w.cstr(r.plugin)
	}
	if r.caps&capConnectAttrs != 0 {
		var pairs buf
		for k, v := range r.attrs {
			pairs.u8(byte(len(k)))
			pairs.raw([]byte(k))
			pairs.u8(byte(len(v)))
			pairs.raw([]byte(v))
		}
		w.u8(byte(len(pairs.bytes())))
		w.raw(pairs.bytes())
	}
	return w.bytes()
}

const clientCaps = capLongPassword | capProtocol41 | capSecureConnection |
	capPluginAuth | capConnectWithDB | capConnectAttrs

func TestNativeAuthCaptured(t *testing.T) {
	h := start(t)
	conn := h.Dial()

	_, hs, err := readPacket(conn)
	if err != nil {
		t.Fatalf("read handshake: %v", err)
	}
	scramble := serverScramble(t, hs)

	const password = "s3cr3t!"
	resp := response{
		caps:     clientCaps,
		username: "root",
		authResp: nativeResponse(password, scramble),
		database: "app",
		plugin:   nativePassword,
		attrs: map[string]string{
			"_client_name":    "libmysql",
			"_client_version": "8.0.36",
			"program_name":    "mysql",
		},
	}
	if err := writePacket(conn, 1, resp.build()); err != nil {
		t.Fatalf("write response: %v", err)
	}

	// The reply is always an access-denied error, never an OK packet.
	_, reply, err := readPacket(conn)
	if err != nil {
		t.Fatalf("read reply: %v", err)
	}
	if len(reply) == 0 || reply[0] != 0xff {
		t.Fatalf("reply is not an ERR packet: %x", reply)
	}

	ev := h.WaitFor(t, "auth_attempt")
	if ev.Data["username"] != "root" {
		t.Errorf("username = %v, want root", ev.Data["username"])
	}
	if ev.Data["database"] != "app" {
		t.Errorf("database = %v, want app", ev.Data["database"])
	}
	if ev.Data["hashcat_mode"] != 11200 {
		t.Errorf("hashcat_mode = %v, want 11200", ev.Data["hashcat_mode"])
	}
	if ev.Data["client"] != "libmysql 8.0.36" {
		t.Errorf("client = %v, want libmysql 8.0.36", ev.Data["client"])
	}
	if ev.Data["program"] != "mysql" {
		t.Errorf("program = %v, want mysql", ev.Data["program"])
	}

	line, _ := ev.Data["netmysql"].(string)
	assertCrackable(t, line, password)
}

// assertCrackable proves the captured line is a genuine hashcat-11200 artifact:
// re-deriving the response from the known password and the recorded scramble
// must reproduce exactly what was logged. If it does, a cracker with the right
// wordlist recovers the password from this line alone.
func assertCrackable(t *testing.T, line, password string) {
	t.Helper()
	rest, ok := strings.CutPrefix(line, "$mysqlna$")
	if !ok {
		t.Fatalf("netmysql = %q, missing $mysqlna$ prefix", line)
	}
	saltHex, respHex, ok := strings.Cut(rest, "*")
	if !ok {
		t.Fatalf("netmysql = %q, missing scramble*response separator", line)
	}
	salt, err := hex.DecodeString(saltHex)
	if err != nil || len(salt) != 20 {
		t.Fatalf("scramble not 20 hex bytes: %q", saltHex)
	}
	want, err := hex.DecodeString(respHex)
	if err != nil {
		t.Fatalf("response not hex: %q", respHex)
	}
	if got := nativeResponse(password, salt); !bytes.Equal(got, want) {
		t.Fatalf("recorded response does not verify against the password:\n got %x\nwant %x", want, got)
	}
}

func TestAuthSwitchToNative(t *testing.T) {
	h := start(t)
	conn := h.Dial()

	if _, _, err := readPacket(conn); err != nil {
		t.Fatalf("read handshake: %v", err)
	}

	// A client that offers caching_sha2_password instead of native: its response
	// is not a crackable native value, so the decoy must switch it.
	resp := response{
		caps:     clientCaps &^ capConnectAttrs,
		username: "admin",
		authResp: bytes.Repeat([]byte{0x11}, 32),
		database: "",
		plugin:   "caching_sha2_password",
	}
	if err := writePacket(conn, 1, resp.build()); err != nil {
		t.Fatalf("write response: %v", err)
	}

	_, sw, err := readPacket(conn)
	if err != nil {
		t.Fatalf("read auth switch: %v", err)
	}
	if len(sw) == 0 || sw[0] != 0xfe {
		t.Fatalf("expected an auth-switch request, got %x", sw)
	}
	plugin, pos := readCString(sw, 1)
	if plugin != nativePassword {
		t.Fatalf("switch plugin = %q, want %q", plugin, nativePassword)
	}
	newScramble, _ := readN(sw, pos, 20)
	if newScramble == nil {
		t.Fatal("auth switch carried no scramble")
	}

	const password = "hunter2"
	if err := writePacket(conn, 3, nativeResponse(password, newScramble)); err != nil {
		t.Fatalf("write switch response: %v", err)
	}
	if _, reply, err := readPacket(conn); err != nil || len(reply) == 0 || reply[0] != 0xff {
		t.Fatalf("expected ERR after switch, got %x (err %v)", reply, err)
	}

	ev := h.WaitFor(t, "auth_attempt")
	if ev.Data["username"] != "admin" {
		t.Errorf("username = %v, want admin", ev.Data["username"])
	}
	if ev.Data["hashcat_mode"] != 11200 {
		t.Errorf("hashcat_mode = %v, want 11200", ev.Data["hashcat_mode"])
	}
	assertCrackable(t, ev.Data["netmysql"].(string), password)
}

func TestConnectionOnSilence(t *testing.T) {
	h := start(t)
	conn := h.Dial()
	// Read the handshake the server volunteers, then leave without answering:
	// a bare port touch, which should produce exactly one connection event and
	// no auth attempt.
	_, _, _ = readPacket(conn)
	conn.Close()

	ev := h.WaitFor(t, "connection")
	if ev.Service != name {
		t.Errorf("service = %q, want %q", ev.Service, name)
	}
	h.Quiet(t, "auth_attempt")
}

func TestNeverEmitsAuthOnSilence(t *testing.T) {
	h := start(t)
	conn := h.Dial()
	_ = conn
	// Do not even read the handshake — just let the connection sit and close.
	conn.Close()
	h.Quiet(t, "auth_attempt")
}
