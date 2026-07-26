package sink

import (
	"crypto/sha1" //nolint:gosec // matching the protocol under test
	"encoding/binary"
	"encoding/json"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/willysnow/wisp/internal/event"
)

// broker is a minimal hpfeeds server: enough of one to prove the client speaks
// the protocol, and nothing more. Writing the other half is the only way to
// test framing — a client tested against its own encoder passes with the length
// field wrong in both directions.
type broker struct {
	Addr   string
	nonce  []byte
	secret string

	mu        sync.Mutex
	published []publication
	authed    []authentication
}

type publication struct {
	Ident   string
	Channel string
	Payload []byte
}

type authentication struct {
	Ident  string
	Digest []byte
}

func startBroker(t *testing.T, secret string) *broker {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	b := &broker{
		Addr:   ln.Addr().String(),
		nonce:  []byte{0x9d, 0x2e, 0x7f, 0x31},
		secret: secret,
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go b.serve(conn)
		}
	}()
	return b
}

func (b *broker) serve(conn net.Conn) {
	defer conn.Close()

	// INFO: a length-prefixed broker name, then the nonce.
	const name = "wisp-test-broker"
	payload := append([]byte{byte(len(name))}, name...)
	payload = append(payload, b.nonce...)
	msg, err := frame(opInfo, payload)
	if err != nil {
		return
	}
	if _, err := conn.Write(msg); err != nil {
		return
	}

	for {
		opcode, payload, err := readMessage(conn)
		if err != nil {
			return
		}

		switch opcode {
		case opAuth:
			if len(payload) < 1 {
				return
			}
			identLen := int(payload[0])
			if len(payload) < 1+identLen {
				return
			}
			b.mu.Lock()
			b.authed = append(b.authed, authentication{
				Ident:  string(payload[1 : 1+identLen]),
				Digest: append([]byte(nil), payload[1+identLen:]...),
			})
			b.mu.Unlock()

		case opPublish:
			if len(payload) < 1 {
				return
			}
			identLen := int(payload[0])
			if len(payload) < 2+identLen {
				return
			}
			rest := payload[1+identLen:]
			chanLen := int(rest[0])
			if len(rest) < 1+chanLen {
				return
			}
			b.mu.Lock()
			b.published = append(b.published, publication{
				Ident:   string(payload[1 : 1+identLen]),
				Channel: string(rest[1 : 1+chanLen]),
				Payload: append([]byte(nil), rest[1+chanLen:]...),
			})
			b.mu.Unlock()
		}
	}
}

func (b *broker) waitForPublications(t *testing.T, n int) []publication {
	t.Helper()

	deadline := time.Now().Add(3 * time.Second)
	for {
		b.mu.Lock()
		got := append([]publication(nil), b.published...)
		b.mu.Unlock()

		if len(got) >= n {
			return got
		}
		if time.Now().After(deadline) {
			t.Fatalf("wanted %d publications, got %d", n, len(got))
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func (b *broker) waitForAuth(t *testing.T) authentication {
	t.Helper()

	deadline := time.Now().Add(3 * time.Second)
	for {
		b.mu.Lock()
		got := append([]authentication(nil), b.authed...)
		b.mu.Unlock()

		if len(got) > 0 {
			return got[0]
		}
		if time.Now().After(deadline) {
			t.Fatal("the client never authenticated")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestSecretIsNeverSent. It is the one security property the protocol has: the
// broker announces a nonce, the client proves it knows the secret by hashing
// the two together, and the secret itself never crosses the wire.
func TestSecretIsNeverSent(t *testing.T) {
	const secret = "S3cret-hpfeeds-key"
	b := startBroker(t, secret)

	h := NewHPFeeds(HPFeedsOptions{
		Addr: b.Addr, Ident: "wisp-01", Secret: secret, Channel: "wisp.events",
	})
	defer h.Close()

	auth := b.waitForAuth(t)
	if auth.Ident != "wisp-01" {
		t.Errorf("ident = %q, want wisp-01", auth.Ident)
	}

	want := sha1.Sum(append(append([]byte(nil), b.nonce...), secret...)) //nolint:gosec // protocol
	if string(auth.Digest) != string(want[:]) {
		t.Errorf("digest = %x, want sha1(nonce + secret) = %x", auth.Digest, want)
	}
	if string(auth.Digest) == secret {
		t.Fatal("the secret was sent in the clear")
	}
}

// TestEventsArePublishedAsJSON on the configured channel. The payload has to be
// the same object events.jsonl holds, because a collector pointed at both
// should not need two parsers.
func TestEventsArePublishedAsJSON(t *testing.T) {
	b := startBroker(t, "secret")

	h := NewHPFeeds(HPFeedsOptions{
		Addr: b.Addr, Ident: "wisp-01", Secret: "secret", Channel: "wisp.events",
	})
	defer h.Close()

	ev := event.NewRaw("gitlab", "auth_attempt", "10.0.0.9", 41234, 8929)
	ev.Node = "sensor-1"
	ev.Data["private_token"] = "glpat-EXAMPLE.only.in.tests"
	h.Emit(ev)

	got := b.waitForPublications(t, 1)[0]
	if got.Ident != "wisp-01" {
		t.Errorf("ident = %q, want wisp-01", got.Ident)
	}
	if got.Channel != "wisp.events" {
		t.Errorf("channel = %q, want wisp.events", got.Channel)
	}

	var decoded event.Event
	if err := json.Unmarshal(got.Payload, &decoded); err != nil {
		t.Fatalf("payload is not the event JSON: %v\n%s", err, got.Payload)
	}
	if decoded.Service != "gitlab" || decoded.Kind != "auth_attempt" || decoded.Node != "sensor-1" {
		t.Errorf("decoded = %+v, want the emitted event", decoded)
	}
	if decoded.Data["private_token"] != "glpat-EXAMPLE.only.in.tests" {
		t.Errorf("the captured credential did not survive: %v", decoded.Data)
	}
}

// TestFrameLengthCountsItsOwnHeader. This is the detail every hpfeeds
// implementation gets wrong the first time, and getting it wrong desynchronises
// the stream rather than failing cleanly — the broker reads the next message
// starting five bytes into this one.
func TestFrameLengthCountsItsOwnHeader(t *testing.T) {
	msg, err := publishMessage("id", "chan", []byte("payload"))
	if err != nil {
		t.Fatalf("frame: %v", err)
	}

	declared := binary.BigEndian.Uint32(msg[0:4])
	if int(declared) != len(msg) {
		t.Errorf("declared length %d, actual message %d bytes", declared, len(msg))
	}
	if msg[4] != opPublish {
		t.Errorf("opcode = %d, want %d", msg[4], opPublish)
	}
}

// TestOversizedMessagesAreRefusedNotAllocated. A length prefix taken on trust
// is how a hostile or broken peer turns a client into an allocation primitive,
// and this client connects to a broker somebody else runs.
func TestOversizedMessagesAreRefusedNotAllocated(t *testing.T) {
	var header [hpfeedsHeader]byte
	binary.BigEndian.PutUint32(header[0:4], 0xFFFFFFFF)
	header[4] = opInfo

	_, _, err := readMessage(&sliceReader{data: header[:]})
	if err == nil {
		t.Fatal("a 4 GiB message was accepted")
	}

	// And a length shorter than the header itself, which would otherwise
	// underflow the payload size.
	binary.BigEndian.PutUint32(header[0:4], 2)
	if _, _, err := readMessage(&sliceReader{data: header[:]}); err == nil {
		t.Fatal("a message shorter than its own header was accepted")
	}
}

// TestEmitNeverBlocksWhenTheBrokerIsGone.
//
// This is the contract every sink in wisp shares. A service goroutine held up
// because a collector is slow is a service that answers the network late, and a
// hung service is a detectable tell — worse than the lost telemetry.
func TestEmitNeverBlocksWhenTheBrokerIsGone(t *testing.T) {
	// Nothing is listening here.
	h := NewHPFeeds(HPFeedsOptions{
		Addr: "127.0.0.1:1", Ident: "wisp-01", Secret: "secret", Channel: "wisp.events",
	})
	defer h.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < queueSize*2; i++ {
			h.Emit(event.NewRaw("ssh", "login_password", "10.0.0.9", 41234, 2222))
		}
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Emit blocked while the broker was unreachable")
	}

	if h.Dropped() == 0 {
		t.Error("events were silently absorbed; a full queue has to be counted")
	}
}

// TestReconnectsAfterTheBrokerDropsTheConnection. Collectors restart, and a
// sensor that gave up on the first disconnection would go quiet for the rest of
// its uptime without anybody noticing.
func TestReconnectsAfterTheBrokerDropsTheConnection(t *testing.T) {
	b := startBroker(t, "secret")

	h := NewHPFeeds(HPFeedsOptions{
		Addr: b.Addr, Ident: "wisp-01", Secret: "secret", Channel: "wisp.events",
	})
	defer h.Close()

	h.Emit(event.NewRaw("redis", "command", "10.0.0.9", 41234, 6379))
	b.waitForPublications(t, 1)

	// The broker's handler returns — and closes the connection — as soon as it
	// reads a message it does not understand.
	b.mu.Lock()
	b.published = nil
	b.mu.Unlock()

	// Give the client time to notice, back off, and come back.
	deadline := time.Now().Add(5 * time.Second)
	for {
		h.Emit(event.NewRaw("redis", "command", "10.0.0.9", 41234, 6379))

		b.mu.Lock()
		n := len(b.published)
		b.mu.Unlock()
		if n > 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("the client never published again")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// sliceReader hands out a fixed buffer and then EOF, so readMessage can be
// tested without a socket.
type sliceReader struct {
	data []byte
	pos  int
}

func (s *sliceReader) Read(p []byte) (int, error) {
	if s.pos >= len(s.data) {
		return 0, net.ErrClosed
	}
	n := copy(p, s.data[s.pos:])
	s.pos += n
	return n, nil
}
