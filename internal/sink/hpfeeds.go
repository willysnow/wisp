package sink

import (
	"crypto/sha1" //nolint:gosec // the protocol specifies SHA-1; see authDigest
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/willysnow/wisp/internal/event"
)

// HPFeeds publishes events to an hpfeeds broker.
//
// hpfeeds is the pub/sub bus honeypot operators share data over — the transport
// behind the Honeynet Project's collections, and what OpenCanary, Cowrie,
// Dionaea and the rest speak when they feed a shared collector. Supporting it
// is what lets a wisp sensor sit in an existing fleet rather than beside one.
//
// The protocol is small and unencrypted by design, with a nonce-and-shared-
// secret handshake instead of TLS: the broker announces a random nonce, the
// client proves it knows the secret by hashing the two together, and neither
// side ever sends the secret. That protects the credential and nothing else,
// which is why Broker.TLS exists — an event here carries captured passwords,
// and those should not cross a network in the clear.
//
// Delivery is best-effort, on the same contract as the console sink: Emit never
// blocks and never fails, a full queue drops events and counts them, and a
// broker that goes away is reconnected to in the background. A honeypot service
// goroutine must never be held up — or worse, hung — because a collector is
// slow, since a hung service is a detectable tell.
type HPFeeds struct {
	opts HPFeedsOptions

	queue chan event.Event
	done  chan struct{}
	wg    sync.WaitGroup

	mu      sync.Mutex
	dropped int64
}

// HPFeedsOptions configures the broker connection.
type HPFeedsOptions struct {
	// Addr is host:port. The conventional port is 10000.
	Addr string

	// Ident is the account name the broker knows this sensor by, and Secret is
	// the shared secret it was issued with. The secret is never sent.
	Ident  string
	Secret string

	// Channel is what to publish on. Brokers authorise per channel, so this has
	// to be one the ident is allowed to write.
	Channel string

	// TLS, when set, wraps the connection. hpfeeds has no transport security of
	// its own and these messages carry captured credentials, so this should be
	// set for anything crossing a network you do not own.
	TLS *tls.Config
}

// hpfeeds wire opcodes.
const (
	opError   = 0
	opInfo    = 1
	opAuth    = 2
	opPublish = 3
)

const (
	// hpfeedsHeader is the fixed part of every message: a 4-byte big-endian
	// total length followed by a 1-byte opcode. The length counts itself.
	hpfeedsHeader = 5

	// hpfeedsMaxMessage bounds what will be read from the broker. Nothing it
	// legitimately sends is large, and a length prefix taken on trust is how a
	// hostile or broken peer turns a client into an allocation primitive.
	hpfeedsMaxMessage = 1 << 20

	// hpfeedsReconnectMin and Max bound the backoff between connection
	// attempts. A collector that is down for a day must not be reconnected to
	// once a second for a day.
	hpfeedsReconnectMin = time.Second
	hpfeedsReconnectMax = time.Minute

	hpfeedsDialTimeout  = 15 * time.Second
	hpfeedsWriteTimeout = 15 * time.Second
)

// NewHPFeeds starts the publisher. Call Close to stop it.
func NewHPFeeds(opts HPFeedsOptions) *HPFeeds {
	h := &HPFeeds{
		opts:  opts,
		queue: make(chan event.Event, queueSize),
		done:  make(chan struct{}),
	}
	h.wg.Add(1)
	go h.run()
	return h
}

func (h *HPFeeds) Emit(e event.Event) {
	select {
	case h.queue <- e:
	default:
		h.mu.Lock()
		h.dropped++
		h.mu.Unlock()
	}
}

// Dropped reports how many events were discarded because the queue was full.
// Non-zero means the broker has been unreachable or too slow.
func (h *HPFeeds) Dropped() int64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.dropped
}

// Close stops publishing.
func (h *HPFeeds) Close() {
	close(h.done)
	h.wg.Wait()
}

// run keeps a connection up and drains the queue into it.
func (h *HPFeeds) run() {
	defer h.wg.Done()

	backoff := hpfeedsReconnectMin
	for {
		select {
		case <-h.done:
			return
		default:
		}

		conn, err := h.connect()
		if err != nil {
			// Nothing is logged here: a sensor that printed a line every time a
			// collector was unreachable would fill its own console during the
			// outage. The drop counter is the durable record.
			select {
			case <-time.After(backoff):
			case <-h.done:
				return
			}
			if backoff *= 2; backoff > hpfeedsReconnectMax {
				backoff = hpfeedsReconnectMax
			}
			continue
		}
		backoff = hpfeedsReconnectMin

		h.publish(conn)
		_ = conn.Close()
	}
}

// publish writes queued events until the connection fails or we are closing.
//
// An event that fails to send is not requeued. Retrying it would mean holding
// it while reconnecting, and the queue behind it would back up behind one
// stubborn message — the same unbounded growth the drop counter exists to
// prevent.
func (h *HPFeeds) publish(conn net.Conn) {
	for {
		select {
		case <-h.done:
			return

		case e := <-h.queue:
			body, err := json.Marshal(e)
			if err != nil {
				continue
			}
			msg, err := publishMessage(h.opts.Ident, h.opts.Channel, body)
			if err != nil {
				// Too large to frame. Counting it is the honest outcome.
				h.mu.Lock()
				h.dropped++
				h.mu.Unlock()
				continue
			}

			_ = conn.SetWriteDeadline(time.Now().Add(hpfeedsWriteTimeout))
			if _, err := conn.Write(msg); err != nil {
				h.mu.Lock()
				h.dropped++
				h.mu.Unlock()
				return // reconnect
			}
		}
	}
}

// connect dials the broker and completes the handshake.
func (h *HPFeeds) connect() (net.Conn, error) {
	dialer := &net.Dialer{Timeout: hpfeedsDialTimeout}

	var conn net.Conn
	var err error
	if h.opts.TLS != nil {
		conn, err = tls.DialWithDialer(dialer, "tcp", h.opts.Addr, h.opts.TLS)
	} else {
		conn, err = dialer.Dial("tcp", h.opts.Addr)
	}
	if err != nil {
		return nil, err
	}

	if err := h.handshake(conn); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

// handshake performs the INFO/AUTH exchange.
//
// The broker speaks first with its name and a random nonce; the client answers
// with its ident and sha1(nonce + secret). The secret itself never crosses the
// wire, which is the one security property the protocol has.
func (h *HPFeeds) handshake(conn net.Conn) error {
	_ = conn.SetReadDeadline(time.Now().Add(hpfeedsDialTimeout))

	opcode, payload, err := readMessage(conn)
	if err != nil {
		return err
	}
	if opcode == opError {
		return fmt.Errorf("hpfeeds broker refused the connection: %s", payload)
	}
	if opcode != opInfo {
		return fmt.Errorf("hpfeeds: expected INFO, got opcode %d", opcode)
	}

	// INFO payload: a length-prefixed broker name, then the nonce.
	if len(payload) < 1 {
		return fmt.Errorf("hpfeeds: truncated INFO")
	}
	nameLen := int(payload[0])
	if len(payload) < 1+nameLen {
		return fmt.Errorf("hpfeeds: INFO names %d bytes it did not send", nameLen)
	}
	nonce := payload[1+nameLen:]

	auth, err := authMessage(h.opts.Ident, h.opts.Secret, nonce)
	if err != nil {
		return err
	}
	_ = conn.SetWriteDeadline(time.Now().Add(hpfeedsWriteTimeout))
	if _, err := conn.Write(auth); err != nil {
		return err
	}

	// A broker that rejects the credential answers with ERROR and closes. It
	// says nothing at all when the credential is good, so there is nothing to
	// wait for here — the read deadline is cleared and the next failure will
	// surface on the first publish.
	_ = conn.SetReadDeadline(time.Time{})
	return nil
}

// authDigest is sha1(nonce + secret), which is what the protocol specifies.
//
// SHA-1 is not a defensible choice in 2026 and it is not ours to make: every
// broker and every other client computes this, and a sensor that used something
// stronger would simply fail to authenticate. It is a challenge-response over a
// shared secret rather than a signature, so the collision weaknesses that
// killed SHA-1 elsewhere do not apply — but the preimage margin is the only
// thing protecting the secret, which is the other reason to run this over TLS.
func authDigest(secret string, nonce []byte) []byte {
	sum := sha1.New() //nolint:gosec // protocol-mandated; see above
	sum.Write(nonce)
	sum.Write([]byte(secret))
	return sum.Sum(nil)
}

func authMessage(ident, secret string, nonce []byte) ([]byte, error) {
	if len(ident) > 255 {
		return nil, fmt.Errorf("hpfeeds: ident is longer than the protocol's 255 bytes")
	}

	payload := make([]byte, 0, 1+len(ident)+sha1.Size)
	payload = append(payload, byte(len(ident)))
	payload = append(payload, ident...)
	payload = append(payload, authDigest(secret, nonce)...)
	return frame(opAuth, payload)
}

func publishMessage(ident, channel string, body []byte) ([]byte, error) {
	if len(ident) > 255 {
		return nil, fmt.Errorf("hpfeeds: ident is longer than the protocol's 255 bytes")
	}
	if len(channel) > 255 {
		return nil, fmt.Errorf("hpfeeds: channel is longer than the protocol's 255 bytes")
	}

	payload := make([]byte, 0, 2+len(ident)+len(channel)+len(body))
	payload = append(payload, byte(len(ident)))
	payload = append(payload, ident...)
	payload = append(payload, byte(len(channel)))
	payload = append(payload, channel...)
	payload = append(payload, body...)
	return frame(opPublish, payload)
}

// frame prefixes a payload with the protocol's length and opcode. The length
// counts the header, which is the detail every hpfeeds implementation gets
// wrong the first time.
func frame(opcode byte, payload []byte) ([]byte, error) {
	total := hpfeedsHeader + len(payload)
	if total > hpfeedsMaxMessage {
		return nil, fmt.Errorf("hpfeeds: message is %d bytes, over the %d limit",
			total, hpfeedsMaxMessage)
	}

	out := make([]byte, hpfeedsHeader, total)
	binary.BigEndian.PutUint32(out[0:4], uint32(total))
	out[4] = opcode
	return append(out, payload...), nil
}

// readMessage reads one framed message.
func readMessage(r io.Reader) (byte, []byte, error) {
	var header [hpfeedsHeader]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return 0, nil, err
	}

	total := binary.BigEndian.Uint32(header[0:4])
	if total < hpfeedsHeader {
		return 0, nil, fmt.Errorf("hpfeeds: message claims %d bytes, less than a header", total)
	}
	if total > hpfeedsMaxMessage {
		// Refused rather than allocated. A length prefix taken on trust is how
		// a hostile or broken peer turns a client into an allocation primitive.
		return 0, nil, fmt.Errorf("hpfeeds: message claims %d bytes, over the %d limit",
			total, hpfeedsMaxMessage)
	}

	payload := make([]byte, total-hpfeedsHeader)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, err
	}
	return header[4], payload, nil
}
