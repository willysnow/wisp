package mongosvc

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/willysnow/wisp/internal/event"
)

func start(t *testing.T) (conn net.Conn, events func() []event.Event) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	var mu sync.Mutex
	var seen []event.Event
	emit := event.EmitterFunc(func(e event.Event) {
		mu.Lock()
		defer mu.Unlock()
		seen = append(seen, e)
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = New(ln.Addr().String(), "7.0.14").Serve(ctx, ln, emit)
	}()

	conn, err = net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))

	t.Cleanup(func() {
		conn.Close()
		cancel()
		<-done
	})

	return conn, func() []event.Event {
		mu.Lock()
		defer mu.Unlock()
		return append([]event.Event(nil), seen...)
	}
}

// command sends one OP_MSG and returns the server's reply document.
func command(t *testing.T, conn net.Conn, body *docBuilder) doc {
	t.Helper()

	payload := body.build()

	msg := make([]byte, 0, headerSize+5+len(payload))
	msg = binary.LittleEndian.AppendUint32(msg, uint32(headerSize+5+len(payload)))
	msg = binary.LittleEndian.AppendUint32(msg, 7) // request id
	msg = binary.LittleEndian.AppendUint32(msg, 0) // response to
	msg = binary.LittleEndian.AppendUint32(msg, uint32(opMsg))
	msg = binary.LittleEndian.AppendUint32(msg, 0) // flag bits
	msg = append(msg, 0)                           // section kind 0
	msg = append(msg, payload...)

	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}

	var header [headerSize]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		t.Fatalf("read header: %v", err)
	}
	length := int(binary.LittleEndian.Uint32(header[:4]))
	if length < headerSize || length > maxMessage {
		t.Fatalf("reply length %d out of range", length)
	}

	rest := make([]byte, length-headerSize)
	if _, err := io.ReadFull(conn, rest); err != nil {
		t.Fatalf("read body: %v", err)
	}

	// Skip the flag bits and the section kind byte.
	reply, err := parseDocument(rest[5:])
	if err != nil {
		t.Fatalf("parse reply: %v", err)
	}
	return reply
}

func find(t *testing.T, events func() []event.Event, kind string) event.Event {
	t.Helper()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		for _, e := range events() {
			if e.Kind == kind {
				return e
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("no %s event was emitted", kind)
	return event.Event{}
}

// TestSCRAMCapturesCredential is what this module exists for.
//
// The username arrives in the clear, and the client's proof — with the salt,
// the iteration count, and the assembled authentication message — is crackable
// offline, the way a captured NetNTLMv2 response is. Without the SCRAM
// exchange this would be a connection log.
func TestSCRAMCapturesCredential(t *testing.T) {
	conn, events := start(t)

	command(t, conn, newDoc().
		addInt32("hello", 1).
		addString("$db", "admin").
		addStringArray("saslSupportedMechs", []string{"admin.backup_svc"}))

	const clientFirstBare = "n=backup_svc,r=rOprNGfwEbeRWgbNEkqO"
	reply := command(t, conn, newDoc().
		addInt32("saslStart", 1).
		addString("mechanism", "SCRAM-SHA-256").
		addBinary("payload", 0, []byte("n,,"+clientFirstBare)).
		addString("db", "admin").
		addString("$db", "admin"))

	// The username lands as soon as the first message arrives, whether or not
	// the client ever finishes.
	first := find(t, events, "auth_attempt")
	if first.Data["username"] != "backup_svc" {
		t.Fatalf("username = %v, want backup_svc", first.Data["username"])
	}
	if first.Data["mechanism"] != "SCRAM-SHA-256" {
		t.Errorf("mechanism = %v, want SCRAM-SHA-256", first.Data["mechanism"])
	}

	serverFirst, ok := reply.binary("payload")
	if !ok || !strings.HasPrefix(string(serverFirst), "r=rOprNGfwEbeRWgbNEkqO") {
		t.Fatalf("server-first = %q, want it to extend the client nonce", serverFirst)
	}

	// The client signs the exchange and sends its proof.
	clientFinalNoProof := "c=biws,r=" + strings.SplitN(strings.TrimPrefix(string(serverFirst), "r="), ",", 2)[0]
	const proof = "dHNoZWxsb3dvcmxkcHJvb2ZiYXNlNjQ="
	final := command(t, conn, newDoc().
		addInt32("saslContinue", 1).
		addInt32("conversationId", 1).
		addBinary("payload", 0, []byte(clientFinalNoProof+",p="+proof)).
		addString("$db", "admin"))

	var captured event.Event
	for _, e := range events() {
		if e.Kind == "auth_attempt" && e.Data["proof"] != nil {
			captured = e
		}
	}
	if captured.Kind == "" {
		t.Fatal("the client's proof was never captured — nothing here is crackable")
	}
	if captured.Data["proof"] != proof {
		t.Errorf("proof = %v, want %s", captured.Data["proof"], proof)
	}
	if captured.Data["iterations"] != scramIterations {
		t.Errorf("iterations = %v, want %d", captured.Data["iterations"], scramIterations)
	}
	if captured.Data["salt"] == nil || captured.Data["salt"] == "" {
		t.Error("no salt recorded — the proof cannot be attacked without it")
	}

	// The authentication message must be the three SCRAM parts in order, or a
	// cracker cannot reproduce the signature.
	authMessage, _ := captured.Data["auth_message"].(string)
	parts := strings.Split(authMessage, ",")
	if !strings.HasPrefix(authMessage, clientFirstBare) ||
		!strings.HasSuffix(authMessage, clientFinalNoProof) ||
		len(parts) < 6 {
		t.Errorf("auth_message = %q, want client-first,server-first,client-final", authMessage)
	}

	// And the login is refused, always.
	if got := final.values["ok"]; got != float64(0) {
		t.Errorf("ok = %v, want 0 — a decoy must never accept a credential", got)
	}
	if final.str("codeName") != "AuthenticationFailed" {
		t.Errorf("codeName = %q, want AuthenticationFailed", final.str("codeName"))
	}
}

// TestSpeculativeAuthenticateCaptured: drivers bundle the first SCRAM message
// into the handshake to save a round trip, which hands over the username before
// authentication formally starts. Ignoring it would lose the credential of
// every well-behaved modern client.
func TestSpeculativeAuthenticateCaptured(t *testing.T) {
	conn, events := start(t)

	command(t, conn, newDoc().
		addInt32("hello", 1).
		addDoc("speculativeAuthenticate", newDoc().
			addInt32("saslStart", 1).
			addString("mechanism", "SCRAM-SHA-256").
			addBinary("payload", 0, []byte("n,,n=app_user,r=abcdefghijkl")).
			addString("db", "admin")).
		addString("$db", "admin"))

	ev := find(t, events, "auth_attempt")
	if ev.Data["username"] != "app_user" {
		t.Errorf("username = %v, want app_user", ev.Data["username"])
	}
}

// TestHandshakeIdentifiesTheClient — the driver, platform, and application name
// a MongoDB client volunteers are a far stronger fingerprint than an address.
func TestHandshakeIdentifiesTheClient(t *testing.T) {
	conn, events := start(t)

	reply := command(t, conn, newDoc().
		addInt32("hello", 1).
		addDoc("client", newDoc().
			addDoc("driver", newDoc().
				addString("name", "mongo-go-driver").
				addString("version", "1.17.1")).
			addDoc("application", newDoc().addString("name", "loot.py")).
			addDoc("os", newDoc().addString("type", "Linux")).
			addString("platform", "go1.25")).
		addString("$db", "admin"))

	if reply.values["ok"] != float64(1) {
		t.Fatalf("the handshake was refused: %v", reply.values)
	}
	if reply.values["maxWireVersion"] == nil {
		t.Error("the handshake reply is missing maxWireVersion; drivers will give up")
	}

	ev := find(t, events, "probe")
	if got, _ := ev.Data["driver"].(string); !strings.Contains(got, "mongo-go-driver") {
		t.Errorf("driver = %q, want the client's own driver string", got)
	}
	if ev.Data["application"] != "loot.py" {
		t.Errorf("application = %v, want loot.py — the name they chose for their tool",
			ev.Data["application"])
	}
}

// TestUnauthenticatedCommandsAreRefused: the decoy claims authentication is
// required rather than pretending to be wide open. A locked door invites a key,
// and the key is what is worth capturing.
func TestUnauthenticatedCommandsAreRefused(t *testing.T) {
	conn, events := start(t)

	for _, cmd := range []string{"listDatabases", "find", "dropDatabase"} {
		reply := command(t, conn, newDoc().addInt32(cmd, 1).addString("$db", "admin"))

		if reply.values["ok"] != float64(0) {
			t.Errorf("%s returned ok=%v, want 0", cmd, reply.values["ok"])
		}
		if reply.str("codeName") != "Unauthorized" {
			t.Errorf("%s codeName = %q, want Unauthorized", cmd, reply.str("codeName"))
		}
		if !strings.Contains(reply.str("errmsg"), "requires authentication") {
			t.Errorf("%s errmsg = %q, want the wording a secured server uses",
				cmd, reply.str("errmsg"))
		}
	}

	// The attempt itself is intent: dropDatabase is a ransom note, not a typo.
	ev := find(t, events, "command")
	if ev.Data["command"] == nil {
		t.Error("the command name was not recorded")
	}
}

// TestLegacyHandshake — scanners still open with OP_QUERY, and a server that
// ignores them looks like nothing at all.
func TestLegacyHandshake(t *testing.T) {
	conn, _ := start(t)

	query := newDoc().addInt32("isMaster", 1).build()

	body := make([]byte, 0, 64)
	body = binary.LittleEndian.AppendUint32(body, 0) // flags
	body = append(body, "admin.$cmd\x00"...)
	body = binary.LittleEndian.AppendUint32(body, 0) // skip
	body = binary.LittleEndian.AppendUint32(body, 1) // return
	body = append(body, query...)

	msg := make([]byte, 0, headerSize+len(body))
	msg = binary.LittleEndian.AppendUint32(msg, uint32(headerSize+len(body)))
	msg = binary.LittleEndian.AppendUint32(msg, 1)
	msg = binary.LittleEndian.AppendUint32(msg, 0)
	msg = binary.LittleEndian.AppendUint32(msg, uint32(opQuery))
	msg = append(msg, body...)

	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}

	var header [headerSize]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		t.Fatalf("read: %v", err)
	}
	if op := binary.LittleEndian.Uint32(header[12:16]); op != opReply {
		t.Fatalf("opcode = %d, want OP_REPLY (%d)", op, opReply)
	}

	rest := make([]byte, int(binary.LittleEndian.Uint32(header[:4]))-headerSize)
	if _, err := io.ReadFull(conn, rest); err != nil {
		t.Fatalf("read body: %v", err)
	}
	reply, err := parseDocument(rest[20:]) // past the OP_REPLY prefix
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if reply.values["ok"] != float64(1) {
		t.Errorf("legacy handshake returned %v, want ok=1", reply.values["ok"])
	}
}

// TestMalformedInputIsRejected: this parser's input comes from whoever
// connected to the honeypot. None of these may panic or run away.
func TestMalformedInputIsRejected(t *testing.T) {
	valid := newDoc().addString("a", "b").build()

	cases := map[string][]byte{
		"empty":             {},
		"header only":       {5, 0, 0, 0},
		"length too small":  {1, 0, 0, 0, 0},
		"length beyond buf": {0xff, 0xff, 0, 0, 0},
		"truncated":         valid[:len(valid)-2],
		"unterminated key":  {12, 0, 0, 0, typeString, 'k', 'e', 'y', 1, 0, 0, 0},
		"unknown type":      {8, 0, 0, 0, 0x7f, 'k', 0, 0},
		"negative string":   {16, 0, 0, 0, typeString, 'k', 0, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0},
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			// The assertion is that this returns at all.
			_, _ = parseDocument(input)
		})
	}

	// Deep nesting must hit the depth limit rather than the stack.
	deep := newDoc().addString("x", "y")
	for i := 0; i < maxDepth*3; i++ {
		next := newDoc()
		next.addDoc("d", deep)
		deep = next
	}
	if _, err := parseDocument(deep.build()); err == nil {
		t.Error("a document nested past the limit was accepted")
	}
}

// TestRoundTrip checks the writer against the reader, since a reply the client
// cannot parse ends the conversation.
func TestRoundTrip(t *testing.T) {
	built := newDoc().
		addDouble("ok", 1).
		addString("errmsg", "nope").
		addInt32("code", 13).
		addInt64("counter", 1<<40).
		addBool("readOnly", false).
		addBinary("payload", 0, []byte("r=abc,s=def,i=15000")).
		addDoc("nested", newDoc().addString("inner", "value")).
		addStringArray("mechs", []string{"SCRAM-SHA-256", "SCRAM-SHA-1"}).
		build()

	got, err := parseDocument(built)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if got.first() != "ok" {
		t.Errorf("first field = %q, want ok — field order carries the command name", got.first())
	}
	if got.values["ok"] != float64(1) || got.str("errmsg") != "nope" ||
		got.values["code"] != int32(13) || got.values["counter"] != int64(1<<40) ||
		got.values["readOnly"] != false {
		t.Errorf("round trip lost a value: %#v", got.values)
	}
	if payload, ok := got.binary("payload"); !ok || string(payload) != "r=abc,s=def,i=15000" {
		t.Errorf("binary round trip failed: %q", payload)
	}
	if nested, ok := got.sub("nested"); !ok || nested.str("inner") != "value" {
		t.Error("nested document round trip failed")
	}
	if mechs, ok := got.sub("mechs"); !ok || mechs.str("0") != "SCRAM-SHA-256" {
		t.Error("array round trip failed")
	}
}

// TestSilentConnectionIsRecorded — a socket that opens and says nothing is a
// scan, and the only case where a bare connection is worth an event. A client
// that speaks must not also produce one, or a single driver's connection pool
// fills the page with duplicates.
func TestSilentConnectionIsRecorded(t *testing.T) {
	conn, events := start(t)
	conn.Close()

	find(t, events, "connection")

	talkative, talkEvents := start(t)
	command(t, talkative, newDoc().addInt32("hello", 1).addString("$db", "admin"))
	talkative.Close()

	time.Sleep(100 * time.Millisecond)
	for _, e := range talkEvents() {
		if e.Kind == "connection" {
			t.Error("a connection that spoke also produced a bare connection event")
		}
	}
}

// TestClientFirstParsing covers the SCRAM escaping rules — a username with a
// comma in it is legal, and getting it wrong means logging the wrong account.
func TestClientFirstParsing(t *testing.T) {
	for _, tc := range []struct{ payload, user, nonce string }{
		{"n,,n=admin,r=abc123", "admin", "abc123"},
		{"n,a=other,n=svc,r=xyz", "svc", "xyz"},
		{"n=bare,r=nonce", "bare", "nonce"},
		{"n,,n=with=2Ccomma,r=n1", "with,comma", "n1"},
		{"n,,n=with=3Dequals,r=n2", "with=equals", "n2"},
		{"", "", ""},
	} {
		user, nonce, _ := parseClientFirst(tc.payload)
		if user != tc.user || nonce != tc.nonce {
			t.Errorf("parseClientFirst(%q) = (%q, %q), want (%q, %q)",
				tc.payload, user, nonce, tc.user, tc.nonce)
		}
	}
}
