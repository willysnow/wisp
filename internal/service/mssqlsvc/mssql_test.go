package mssqlsvc

import (
	"testing"
	"unicode/utf16"

	"github.com/willysnow/wisp/internal/service"
	"github.com/willysnow/wisp/internal/service/servicetest"
)

func start(t *testing.T) *servicetest.StreamHarness {
	return servicetest.StartStream(t, func(addr string) service.StreamService {
		return New(addr, "16.0.1000", "SQLPROD01")
	})
}

// buildPrelogin encodes a client PRELOGIN carrying an encryption preference and
// an optional instance name.
func buildPrelogin(enc byte, instance string) []byte {
	opts := []struct {
		token byte
		data  []byte
	}{
		{preloginVersion, []byte{0, 0, 0, 0, 0, 0}},
		{preloginEncryption, []byte{enc}},
		{preloginInstOpt, append([]byte(instance), 0)},
	}
	headerLen := len(opts)*5 + 1
	var table, data buf
	off := headerLen
	for _, o := range opts {
		table.u8(o.token)
		table.u16be(uint16(off))
		table.u16be(uint16(len(o.data)))
		off += len(o.data)
		data.raw(o.data)
	}
	table.u8(preloginTerminator)
	return append(table.bytes(), data.bytes()...)
}

// encodePassword applies SQL Server's LOGIN7 obfuscation the way a client does,
// so the decoy's decoder has something real to reverse.
func encodePassword(s string) []byte {
	units := utf16.Encode([]rune(s))
	raw := make([]byte, len(units)*2)
	for i, u := range units {
		le.PutUint16(raw[i*2:], u)
	}
	out := make([]byte, len(raw))
	for i, b := range raw {
		x := b ^ 0xA5
		out[i] = (x >> 4) | (x << 4)
	}
	return out
}

type login7 struct {
	hostname, username, password string
	appName, library, database   string
	sspi                         []byte // non-nil => integrated auth
}

// build encodes a LOGIN7 record with the offset/length descriptor block.
func (c login7) build() []byte {
	const fixed = 36
	const ol = 58
	dataStart := fixed + ol

	var data buf
	var desc [ol]byte

	putStr := func(descPos int, s string) {
		units := utf16.Encode([]rune(s))
		le.PutUint16(desc[descPos:], uint16(dataStart+len(data.bytes())))
		le.PutUint16(desc[descPos+2:], uint16(len(units)))
		for _, u := range units {
			data.u16(u)
		}
	}

	putStr(0, c.hostname)
	putStr(4, c.username)
	// Password: descriptor at +8, obfuscated bytes.
	{
		enc := encodePassword(c.password)
		le.PutUint16(desc[8:], uint16(dataStart+len(data.bytes())))
		le.PutUint16(desc[10:], uint16(len(enc)/2))
		data.raw(enc)
	}
	putStr(12, c.appName)
	putStr(16, "") // server name
	putStr(24, c.library)
	putStr(32, c.database)

	if c.sspi != nil {
		le.PutUint16(desc[42:], uint16(dataStart+len(data.bytes())))
		le.PutUint16(desc[44:], uint16(len(c.sspi)))
		data.raw(c.sspi)
	}

	var w buf
	w.u32(0)          // Length placeholder
	w.u32(0x74000004) // TDSVersion 7.4
	w.u32(4096)       // PacketSize
	w.u32(0)          // ClientProgVer
	w.u32(0)          // ClientPID
	w.u32(0)          // ConnectionID
	w.u8(0)           // OptionFlags1
	w.u8(0)           // OptionFlags2
	w.u8(0)           // TypeFlags
	w.u8(0)           // OptionFlags3
	w.u32(0)          // ClientTimeZone
	w.u32(0)          // ClientLCID
	w.raw(desc[:])
	w.raw(data.bytes())

	out := w.bytes()
	le.PutUint32(out[0:4], uint32(len(out)))
	return out
}

func TestSQLAuthPasswordCaptured(t *testing.T) {
	h := start(t)
	conn := h.Dial()

	if err := writeMessage(conn, pktPrelogin, buildPrelogin(encryptOff, "MSSQLSERVER")); err != nil {
		t.Fatalf("write prelogin: %v", err)
	}
	mt, resp, err := readMessage(conn)
	if err != nil || mt != pktReply {
		t.Fatalf("read prelogin reply: type=%#x err=%v", mt, err)
	}
	// The server must decline encryption, or the password would never travel in
	// the clear.
	if pl := parsePrelogin(resp); pl.encryption != encryptNotSup {
		t.Fatalf("server encryption = %#x, want NOT_SUP", pl.encryption)
	}

	// The probe event records the PRELOGIN before any login.
	probe := h.WaitFor(t, "probe")
	if probe.Data["instance"] != "MSSQLSERVER" {
		t.Errorf("instance = %v, want MSSQLSERVER", probe.Data["instance"])
	}
	if probe.Data["encryption"] != "off" {
		t.Errorf("encryption = %v, want off", probe.Data["encryption"])
	}

	login := login7{
		hostname: "ATTACKER-PC",
		username: "sa",
		password: "Summer2024!",
		appName:  "sqlcmd",
		library:  "go-mssqldb",
		database: "master",
	}
	if err := writeMessage(conn, pktLogin7, login.build()); err != nil {
		t.Fatalf("write login: %v", err)
	}

	mt, reply, err := readMessage(conn)
	if err != nil || mt != pktReply {
		t.Fatalf("read login reply: type=%#x err=%v", mt, err)
	}
	// Always an ERROR token 0xAA carrying 18456 — never a successful login.
	if len(reply) < 7 || reply[0] != 0xAA {
		t.Fatalf("reply is not an ERROR token: %x", reply)
	}
	if n := le.Uint32(reply[3:7]); n != 18456 {
		t.Errorf("error number = %d, want 18456", n)
	}

	ev := h.WaitFor(t, "login_password")
	if ev.Data["username"] != "sa" {
		t.Errorf("username = %v, want sa", ev.Data["username"])
	}
	if ev.Data["password"] != "Summer2024!" {
		t.Errorf("password = %v, want Summer2024!", ev.Data["password"])
	}
	if ev.Data["application"] != "sqlcmd" {
		t.Errorf("application = %v, want sqlcmd", ev.Data["application"])
	}
	if ev.Data["database"] != "master" {
		t.Errorf("database = %v, want master", ev.Data["database"])
	}
	if ev.Data["hostname"] != "ATTACKER-PC" {
		t.Errorf("hostname = %v, want ATTACKER-PC", ev.Data["hostname"])
	}
}

func TestIntegratedAuthRecorded(t *testing.T) {
	h := start(t)
	conn := h.Dial()

	if err := writeMessage(conn, pktPrelogin, buildPrelogin(encryptOff, "")); err != nil {
		t.Fatalf("write prelogin: %v", err)
	}
	if _, _, err := readMessage(conn); err != nil {
		t.Fatalf("read prelogin reply: %v", err)
	}

	// A LOGIN7 carrying an SSPI blob instead of a password: Windows/integrated
	// auth. No cleartext comes out, but the attempt is still worth recording.
	login := login7{
		hostname: "DC01",
		appName:  "Microsoft SQL Server Management Studio",
		sspi:     []byte("NTLMSSP\x00\x01\x00\x00\x00"),
	}
	if err := writeMessage(conn, pktLogin7, login.build()); err != nil {
		t.Fatalf("write login: %v", err)
	}
	if _, _, err := readMessage(conn); err != nil {
		t.Fatalf("read login reply: %v", err)
	}

	ev := h.WaitFor(t, "auth_attempt")
	if ev.Data["auth"] != "integrated" {
		t.Errorf("auth = %v, want integrated", ev.Data["auth"])
	}
	if _, ok := ev.Data["password"]; ok {
		t.Errorf("integrated auth must not log a password, got %v", ev.Data["password"])
	}
	if ev.Data["application"] != "Microsoft SQL Server Management Studio" {
		t.Errorf("application = %v", ev.Data["application"])
	}
}

func TestConnectionOnSilence(t *testing.T) {
	h := start(t)
	conn := h.Dial()
	conn.Close()

	ev := h.WaitFor(t, "connection")
	if ev.Service != name {
		t.Errorf("service = %q, want %q", ev.Service, name)
	}
	h.Quiet(t, "login_password")
	h.Quiet(t, "auth_attempt")
}

func TestNonTDSFirstPacketClosed(t *testing.T) {
	h := start(t)
	conn := h.Dial()

	// A SQLBatch as the first message — not a PRELOGIN — gets no answer, the way
	// a real server treats a client that skips the handshake.
	if err := writeMessage(conn, pktSQLBatch, []byte("SELECT 1")); err != nil {
		t.Fatalf("write: %v", err)
	}
	h.Quiet(t, "probe")
	h.Quiet(t, "login_password")
}
