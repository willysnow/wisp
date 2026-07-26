// Package mongosvc emulates a MongoDB server with authentication enabled.
//
// An exposed MongoDB is one of the most-scanned things on the internet, and the
// tooling that finds one goes straight to dumping or ransoming it. A banner
// catcher on 27017 records that someone knocked; this records who they claimed
// to be and what they tried to open.
//
// The decoy answers "this command requires authentication" rather than
// pretending to be wide open, for the same reason the Kubernetes decoy answers
// 403 instead of 401: a door that is merely locked invites a key, and the key
// is what is worth having. Modern drivers then run SCRAM, which hands over the
// username immediately and — once the client sends its proof — a value that can
// be cracked offline, the way a captured NetNTLMv2 response can. Nothing is
// ever accepted; every conversation ends in AuthenticationFailed.
package mongosvc

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/willysnow/wisp/internal/event"
	"github.com/willysnow/wisp/internal/service"
)

const name = "mongodb"

// Wire protocol opcodes. OP_MSG is what every driver since 3.6 speaks; OP_QUERY
// survives because scanners and old tools still open with it.
const (
	opReply = 1
	opQuery = 2004
	opMsg   = 2013
)

// maxMessage caps one wire message. A real server allows 48 MB; nothing a decoy
// needs to understand comes close, and the difference is memory an attacker
// would otherwise get to allocate.
const maxMessage = 1 << 20

// headerSize is the fixed part of every wire message: length, request id,
// response-to, opcode.
const headerSize = 16

// scramIterations is what we claim the password was hashed with. 15000 is the
// server's own default for SCRAM-SHA-256, and a number that does not match a
// real server's would be a tell.
const scramIterations = 15000

// logLimit bounds any single captured field.
const logLimit = 1024

type Service struct {
	addr    string
	version string

	// processID identifies this "server" in topologyVersion. Generated once
	// and kept for the process, because a value that changes per connection is
	// not what a real replica set member looks like.
	processID []byte
}

func New(addr, version string) *Service {
	id := make([]byte, 12)
	_, _ = rand.Read(id)
	return &Service{addr: addr, version: version, processID: id}
}

func (s *Service) Name() string { return name }
func (s *Service) Addr() string { return s.addr }

func (s *Service) Serve(ctx context.Context, ln net.Listener, emit event.Emitter) error {
	return service.Accept(ctx, ln, func(c net.Conn) { s.handle(c, emit) })
}

// session is the per-connection state SCRAM needs. The exchange spans two
// messages, and the pieces of the authentication message an offline cracker
// needs are spread across both.
type session struct {
	username       string
	mechanism      string
	clientFirstBar string // "n=user,r=clientnonce"
	serverFirst    string // "r=combinednonce,s=salt,i=iterations"
	salt           string
	conn           net.Conn
	emit           event.Emitter
	connectionID   int32
}

func (s *Service) handle(conn net.Conn, emit event.Emitter) {
	sess := &session{conn: conn, emit: emit, connectionID: connectionCounter()}

	// A bare connection is only reported when nothing was said on it — that is
	// a port scan, and worth an event. Drivers open several connections per
	// client and every one of them speaks, so reporting each would turn one
	// visitor into a page of identical lines.
	spoke := false
	defer func() {
		if !spoke {
			emit.Emit(event.New(name, "connection", conn.RemoteAddr(), conn.LocalAddr()))
		}
	}()

	for {
		header, body, err := readMessage(conn)
		if err != nil {
			return
		}

		switch header.opCode {
		case opMsg:
			spoke = true
			s.handleOpMsg(sess, header, body)
		case opQuery:
			spoke = true
			s.handleOpQuery(sess, header, body)
		default:
			// Nothing else is worth emulating; a real server closes on an
			// opcode it does not know, and so do we.
			return
		}
	}
}

type msgHeader struct {
	length     int32
	requestID  int32
	responseTo int32
	opCode     int32
}

func readMessage(r io.Reader) (msgHeader, []byte, error) {
	var raw [headerSize]byte
	if _, err := io.ReadFull(r, raw[:]); err != nil {
		return msgHeader{}, nil, err
	}

	h := msgHeader{
		length:     int32(binary.LittleEndian.Uint32(raw[0:4])),
		requestID:  int32(binary.LittleEndian.Uint32(raw[4:8])),
		responseTo: int32(binary.LittleEndian.Uint32(raw[8:12])),
		opCode:     int32(binary.LittleEndian.Uint32(raw[12:16])),
	}
	if h.length < headerSize || h.length > maxMessage {
		return h, nil, fmt.Errorf("message length %d out of range", h.length)
	}

	body := make([]byte, int(h.length)-headerSize)
	if _, err := io.ReadFull(r, body); err != nil {
		return h, nil, err
	}
	return h, body, nil
}

// handleOpMsg processes the modern command format.
func (s *Service) handleOpMsg(sess *session, header msgHeader, body []byte) {
	if len(body) < 5 {
		return
	}

	flags := binary.LittleEndian.Uint32(body[:4])
	sections := body[4:]

	// Bit 0 means the last four bytes are a CRC over the message. Nothing here
	// verifies it, but it must not be parsed as a section.
	if flags&1 != 0 && len(sections) >= 4 {
		sections = sections[:len(sections)-4]
	}

	command, ok := firstBodySection(sections)
	if !ok {
		return
	}

	reply := s.dispatch(sess, command)
	_ = writeOpMsg(sess.conn, header.requestID, reply)
}

// firstBodySection finds the kind-0 section, which carries the command. Kind-1
// sections hold bulk write payloads and are skipped: a decoy that never
// executes a write has no use for them.
func firstBodySection(sections []byte) (doc, bool) {
	for len(sections) > 0 {
		kind := sections[0]
		rest := sections[1:]

		switch kind {
		case 0:
			d, err := parseDocument(rest)
			if err != nil {
				return doc{}, false
			}
			return d, true

		case 1:
			if len(rest) < 4 {
				return doc{}, false
			}
			size := int(int32(binary.LittleEndian.Uint32(rest)))
			if size < 4 || size > len(rest) {
				return doc{}, false
			}
			sections = rest[size:]

		default:
			return doc{}, false
		}
	}
	return doc{}, false
}

// handleOpQuery processes the legacy format, which in practice only ever
// carries the handshake.
func (s *Service) handleOpQuery(sess *session, header msgHeader, body []byte) {
	if len(body) < 4 {
		return
	}
	_, rest, err := readCString(body[4:]) // skip flags, then the collection name
	if err != nil {
		return
	}
	if len(rest) < 8 {
		return
	}
	query, err := parseDocument(rest[8:]) // skip numberToSkip and numberToReturn
	if err != nil {
		return
	}

	reply := s.dispatch(sess, query)
	_ = writeOpReply(sess.conn, header.requestID, reply)
}

// dispatch handles one command and returns the document to answer with.
func (s *Service) dispatch(sess *session, command doc) *docBuilder {
	switch strings.ToLower(command.first()) {
	case "hello", "ismaster", "is_master":
		return s.hello(sess, command)
	case "saslstart":
		return s.saslStart(sess, command)
	case "saslcontinue":
		return s.saslContinue(sess, command)
	case "ping":
		// Genuinely pre-authentication on a real server, so answering keeps
		// the disguise consistent.
		s.emitCommand(sess, command, "probe")
		return newDoc().addDouble("ok", 1)
	}

	// Everything else: the answer a secured server gives. Attackers read this
	// as "there is data here, I just need credentials" — which is the point.
	s.emitCommand(sess, command, "command")
	return unauthorized(command.first())
}

// hello answers the handshake and records who connected.
//
// The client document is the most identifying thing a MongoDB client sends: the
// driver and its version, the platform, and often the application name the
// developer set — a much stronger fingerprint than an address.
func (s *Service) hello(sess *session, command doc) *docBuilder {
	ev := event.New(name, "probe", sess.conn.RemoteAddr(), sess.conn.LocalAddr())
	ev.Data["command"] = command.first()

	if client, ok := command.sub("client"); ok {
		if driver, ok := client.sub("driver"); ok {
			ev.Data["driver"] = truncate(driver.str("name") + " " + driver.str("version"))
		}
		if app, ok := client.sub("application"); ok && app.str("name") != "" {
			ev.Data["application"] = truncate(app.str("name"))
		}
		if os, ok := client.sub("os"); ok && os.str("type") != "" {
			ev.Data["client_os"] = truncate(os.str("type"))
		}
		if p := client.str("platform"); p != "" {
			ev.Data["platform"] = truncate(p)
		}
	}
	sess.emit.Emit(ev)

	// Drivers often bundle the first SCRAM message into the handshake to save a
	// round trip. That hands over the username before authentication formally
	// begins, and it would be careless to ignore it.
	if spec, ok := command.sub("speculativeAuthenticate"); ok {
		s.recordSASLStart(sess, spec)
	}

	reply := newDoc().
		addBool("helloOk", true).
		addBool("ismaster", true).
		addDoc("topologyVersion", newDoc().
			addObjectID("processId", s.processID).
			addInt64("counter", 0)).
		addInt32("maxBsonObjectSize", 16*1024*1024).
		addInt32("maxMessageSizeBytes", 48000000).
		addInt32("maxWriteBatchSize", 100000).
		addDateTime("localTime", time.Now()).
		addInt32("logicalSessionTimeoutMinutes", 30).
		addInt32("connectionId", sess.connectionID).
		addInt32("minWireVersion", 0).
		addInt32("maxWireVersion", 21)

	// Advertising the mechanisms is how a driver learns to run SCRAM, and only
	// a server with users configured answers this — so it also says, quietly,
	// that there are accounts here worth guessing.
	if _, asked := command.lookup("saslSupportedMechs"); asked {
		reply.addStringArray("saslSupportedMechs",
			[]string{"SCRAM-SHA-256", "SCRAM-SHA-1"})
	}

	return reply.addBool("readOnly", false).addDouble("ok", 1)
}

// saslStart takes the client's first SCRAM message and answers with a
// server-first message the client will sign.
func (s *Service) saslStart(sess *session, command doc) *docBuilder {
	s.recordSASLStart(sess, command)

	if sess.serverFirst == "" {
		return unauthorized("saslStart")
	}

	return newDoc().
		addInt32("conversationId", 1).
		addBool("done", false).
		addBinary("payload", 0, []byte(sess.serverFirst)).
		addDouble("ok", 1)
}

// recordSASLStart parses a client-first message, emits the username, and
// prepares the challenge. It is shared between saslStart and the speculative
// copy inside hello.
func (s *Service) recordSASLStart(sess *session, command doc) {
	mechanism := command.str("mechanism")
	payload, ok := command.binary("payload")
	if !ok {
		return
	}

	username, clientNonce, bare := parseClientFirst(string(payload))
	if username == "" {
		return
	}

	sess.username = username
	sess.mechanism = mechanism
	sess.clientFirstBar = bare

	// The salt is ours to choose and is part of what makes the client's proof
	// crackable offline later, so it is recorded with the attempt.
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return
	}
	serverNonce := make([]byte, 18)
	if _, err := rand.Read(serverNonce); err != nil {
		return
	}

	sess.salt = base64.StdEncoding.EncodeToString(salt)
	sess.serverFirst = fmt.Sprintf("r=%s%s,s=%s,i=%d",
		clientNonce, base64.RawStdEncoding.EncodeToString(serverNonce),
		sess.salt, scramIterations)

	ev := event.New(name, "auth_attempt", sess.conn.RemoteAddr(), sess.conn.LocalAddr())
	ev.Data["username"] = truncate(username)
	ev.Data["mechanism"] = truncate(mechanism)
	if db := command.str("db"); db != "" {
		ev.Data["database"] = truncate(db)
	}
	sess.emit.Emit(ev)
}

// saslContinue captures the client's proof and refuses the login.
//
// The proof is an HMAC over the exchange, keyed by a value derived from the
// password. With the salt, the iteration count, and the full authentication
// message — all recorded here — it can be attacked offline exactly like a
// captured NetNTLMv2 response. That is the strongest artifact this module
// produces, and the reason it implements SCRAM rather than closing the
// connection after the username.
func (s *Service) saslContinue(sess *session, command doc) *docBuilder {
	payload, ok := command.binary("payload")
	if !ok || sess.serverFirst == "" {
		return unauthorized("saslContinue")
	}

	final := string(payload)
	proof, withoutProof := splitProof(final)

	ev := event.New(name, "auth_attempt", sess.conn.RemoteAddr(), sess.conn.LocalAddr())
	ev.Data["username"] = truncate(sess.username)
	ev.Data["mechanism"] = truncate(sess.mechanism)
	if proof != "" {
		ev.Data["proof"] = truncate(proof)
		ev.Data["salt"] = sess.salt
		ev.Data["iterations"] = scramIterations
		// Everything a cracker needs, in the order SCRAM defines, so the value
		// can be used without reassembling it from separate fields.
		ev.Data["auth_message"] = truncate(strings.Join(
			[]string{sess.clientFirstBar, sess.serverFirst, withoutProof}, ","))
	}
	sess.emit.Emit(ev)

	// Always the same refusal. Never "no such user": that would let an
	// attacker enumerate accounts, and this server has none to find.
	return newDoc().
		addDouble("ok", 0).
		addString("errmsg", "Authentication failed.").
		addInt32("code", 18).
		addString("codeName", "AuthenticationFailed")
}

// emitCommand records a command the client had no right to run. The command
// name and its first argument are the intent: listDatabases is a survey,
// dropDatabase is a ransom note.
func (s *Service) emitCommand(sess *session, command doc, kind string) {
	ev := event.New(name, kind, sess.conn.RemoteAddr(), sess.conn.LocalAddr())
	ev.Data["command"] = truncate(command.first())

	if v, ok := command.lookup(command.first()); ok {
		if s, ok := v.(string); ok && s != "" {
			ev.Data["argument"] = truncate(s)
		}
	}
	if db := command.str("$db"); db != "" {
		ev.Data["database"] = truncate(db)
	}
	sess.emit.Emit(ev)
}

func unauthorized(command string) *docBuilder {
	return newDoc().
		addDouble("ok", 0).
		addString("errmsg", fmt.Sprintf("command %s requires authentication",
			sanitise(command))).
		addInt32("code", 13).
		addString("codeName", "Unauthorized")
}

// parseClientFirst pulls the username and nonce out of a SCRAM client-first
// message, which looks like "n,,n=admin,r=rOprNGfwEbeRWgbNEkqO".
func parseClientFirst(payload string) (username, nonce, bare string) {
	// Strip the GS2 header: everything up to and including the second comma.
	if i := strings.Index(payload, ",,"); i >= 0 {
		bare = payload[i+2:]
	} else {
		bare = payload
	}

	for _, field := range strings.Split(bare, ",") {
		switch {
		case strings.HasPrefix(field, "n="):
			// SCRAM escapes commas and equals signs in usernames.
			username = strings.NewReplacer("=2C", ",", "=3D", "=").
				Replace(strings.TrimPrefix(field, "n="))
		case strings.HasPrefix(field, "r="):
			nonce = strings.TrimPrefix(field, "r=")
		}
	}
	return username, nonce, bare
}

// splitProof separates a client-final message into its proof and the part that
// is signed. Both halves are needed to crack it.
func splitProof(final string) (proof, withoutProof string) {
	if i := strings.LastIndex(final, ",p="); i >= 0 {
		return final[i+3:], final[:i]
	}
	return "", final
}

// writeOpMsg frames a reply in the modern format.
func writeOpMsg(w io.Writer, responseTo int32, body *docBuilder) error {
	payload := body.build()

	out := make([]byte, 0, headerSize+5+len(payload))
	out = binary.LittleEndian.AppendUint32(out, uint32(headerSize+5+len(payload)))
	out = binary.LittleEndian.AppendUint32(out, uint32(nextRequestID()))
	out = binary.LittleEndian.AppendUint32(out, uint32(responseTo))
	out = binary.LittleEndian.AppendUint32(out, uint32(opMsg))
	out = binary.LittleEndian.AppendUint32(out, 0) // flag bits
	out = append(out, 0)                           // section kind 0: body
	out = append(out, payload...)

	_, err := w.Write(out)
	return err
}

// writeOpReply frames a reply in the legacy format, for clients that opened
// with OP_QUERY.
func writeOpReply(w io.Writer, responseTo int32, body *docBuilder) error {
	payload := body.build()

	const replyPrefix = 20 // flags, cursor id, starting from, number returned
	out := make([]byte, 0, headerSize+replyPrefix+len(payload))
	out = binary.LittleEndian.AppendUint32(out, uint32(headerSize+replyPrefix+len(payload)))
	out = binary.LittleEndian.AppendUint32(out, uint32(nextRequestID()))
	out = binary.LittleEndian.AppendUint32(out, uint32(responseTo))
	out = binary.LittleEndian.AppendUint32(out, uint32(opReply))
	out = binary.LittleEndian.AppendUint32(out, 0) // response flags
	out = binary.LittleEndian.AppendUint64(out, 0) // cursor id
	out = binary.LittleEndian.AppendUint32(out, 0) // starting from
	out = binary.LittleEndian.AppendUint32(out, 1) // number returned
	out = append(out, payload...)

	_, err := w.Write(out)
	return err
}

// Counters for the two identifiers a real server hands out. Both start
// somewhere arbitrary rather than at zero: a server reporting connectionId 1 to
// everyone who connects has obviously just been started for their benefit.
var (
	connections = atomic.Int32{}
	requestIDs  = atomic.Int32{}
)

func init() {
	connections.Store(randomStart(4000) + 100)
	requestIDs.Store(randomStart(100000))
}

// randomStart picks a starting point for a counter.
func randomStart(bound int32) int32 {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 1
	}
	return int32(binary.LittleEndian.Uint32(b[:])&0x7fffffff) % bound
}

func connectionCounter() int32 { return connections.Add(1) }
func nextRequestID() int32     { return requestIDs.Add(1) }

func truncate(s string) string {
	if len(s) <= logLimit {
		return s
	}
	return s[:logLimit] + "..."
}

// sanitise keeps attacker-controlled text from carrying control characters back
// out in our own error message.
func sanitise(s string) string {
	s = truncate(s)
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
}
