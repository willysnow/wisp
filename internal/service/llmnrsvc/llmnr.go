// Package llmnrsvc detects LLMNR poisoning.
//
// This module is the odd one out: it is not a decoy. Every other service here
// waits to be touched, but LLMNR poisoning leaves nothing to wait for — the
// attacker is answering *other* machines' name lookups, and a passive listener
// would only see the ordinary broadcast chatter every Windows host makes.
//
// So it asks a question nobody can honestly answer. It multicasts an LLMNR
// query for a hostname that does not exist and never will; a correct network
// answers with silence. Responder, Inveigh, and every other credential-relay
// tool answer everything, because answering everything is how they work. One
// reply is proof of an active attacker on the segment, from a source address
// that names the machine they are running on.
//
// **It never answers an LLMNR query.** Replying would be poisoning our own
// network — precisely the attack this module exists to catch — and a detector
// that performs the attack it detects is not a detector. The refusal is
// enforced by a test, like the NTP module's refusal to answer monlist.
package llmnrsvc

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math/big"
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/willysnow/wisp/internal/event"
	"github.com/willysnow/wisp/internal/service"
)

const name = "llmnr"

// LLMNR's assigned multicast group and port (RFC 4795). The IPv6 group is
// ff02::1:3; a query to either reaches the same tools, and IPv4 is the one
// present on every network that still has LLMNR enabled at all.
const (
	multicastAddr = "224.0.0.252:5355"
	llmnrPort     = 5355
)

// Defaults for the probe schedule. Five minutes is often enough to catch a
// poisoner within one working session, and rare enough that the sensor is not
// itself a source of traffic anyone notices.
const (
	DefaultInterval = 5 * time.Minute
	DefaultSplay    = time.Minute
)

// outstandingTTL is how long a probe stays answerable. Anything arriving later
// is not a reply to us.
const outstandingTTL = 30 * time.Second

// firstProbeDelay is how long after start the first query goes out — long
// enough for the network to be up, short enough that a freshly deployed sensor
// is useful immediately.
const firstProbeDelay = 15 * time.Second

type Service struct {
	addr     string
	hostname string
	interval time.Duration
	splay    time.Duration

	mu          sync.Mutex
	outstanding map[uint16]probe
}

type probe struct {
	hostname string
	sentAt   time.Time
}

// New builds the detector. An empty hostname means a fresh random one per
// probe, which is the better default: a fixed name is one an attacker who has
// seen it before can teach their tool to ignore.
func New(addr, hostname string, interval, splay time.Duration) *Service {
	if interval <= 0 {
		interval = DefaultInterval
	}
	if splay < 0 {
		splay = DefaultSplay
	}
	return &Service{
		addr:        addr,
		hostname:    hostname,
		interval:    interval,
		splay:       splay,
		outstanding: map[uint16]probe{},
	}
}

func (s *Service) Name() string { return name }
func (s *Service) Addr() string { return s.addr }

func (s *Service) ServePacket(ctx context.Context, pc net.PacketConn, emit event.Emitter) error {
	go s.probeLoop(ctx, pc, emit)

	return service.AcceptPackets(ctx, pc, func(_ net.PacketConn, from net.Addr, payload []byte) {
		s.handle(from, payload, emit)
	})
}

// probeLoop sends a query, waits, and sends another, until the sensor stops.
func (s *Service) probeLoop(ctx context.Context, pc net.PacketConn, emit event.Emitter) {
	dst, err := net.ResolveUDPAddr("udp4", multicastAddr)
	if err != nil {
		return
	}

	// The first probe comes soon after start rather than a full interval
	// later: a sensor that has just been deployed onto a segment someone is
	// already poisoning should not stay quiet for five minutes.
	wait := firstProbeDelay + jitter(s.splay)

	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}

		// Jittered from here on, so the probe does not become a clock an
		// observer can set their watch by — a query arriving exactly every 300
		// seconds is a tell that something automated is asking.
		wait = s.interval + jitter(s.splay)

		if err := s.sendProbe(pc, dst); err != nil {
			// A send failure is not worth an alert — the network may simply
			// have no route for multicast. The next probe will try again.
			continue
		}
		s.expire()
	}
}

func (s *Service) sendProbe(pc net.PacketConn, dst net.Addr) error {
	host := s.hostname
	if host == "" {
		host = randomHostname()
	}

	id, err := randomID()
	if err != nil {
		return err
	}

	msg, err := buildQuery(id, host)
	if err != nil {
		return err
	}

	s.mu.Lock()
	s.outstanding[id] = probe{hostname: host, sentAt: time.Now()}
	s.mu.Unlock()

	_, err = pc.WriteTo(msg, dst)
	return err
}

// handle inspects one datagram. Queries from other machines are ignored, and
// never answered.
func (s *Service) handle(from net.Addr, payload []byte, emit event.Emitter) {
	var p dnsmessage.Parser

	// The parser is x/net's rather than a hand-rolled one on purpose. This is
	// attacker-controlled DNS wire format, complete with compression pointers
	// that can be made to loop, and a vetted parser is worth more here than
	// one fewer import.
	header, err := p.Start(payload)
	if err != nil {
		return
	}
	if !header.Response {
		// A query from someone else on the network. Recorded nowhere and
		// answered never: every Windows host on the segment sends these, so
		// they are noise — and answering one is the attack.
		return
	}

	s.mu.Lock()
	pr, ours := s.outstanding[header.ID]
	if ours {
		delete(s.outstanding, header.ID)
	}
	s.mu.Unlock()

	if !ours || time.Since(pr.sentAt) > outstandingTTL {
		return
	}

	srcIP, srcPort := event.SplitHostPortString(from.String())
	ev := event.NewRaw(name, "llmnr_poisoned", srcIP, srcPort, llmnrPort)
	ev.Data["queried"] = pr.hostname
	ev.Data["responder"] = srcIP

	// What they claimed the name resolves to — usually the attacker's own
	// address, which is where the relayed authentication would have gone.
	if addr := answerAddress(&p); addr != "" {
		ev.Data["claimed_address"] = addr
	}

	emit.Emit(ev)
}

// answerAddress returns the first address in the answer section, if any. A
// reply with no answer is still proof of a poisoner, so a failure here is not
// a reason to drop the event.
func answerAddress(p *dnsmessage.Parser) string {
	if err := p.SkipAllQuestions(); err != nil {
		return ""
	}

	for {
		h, err := p.AnswerHeader()
		if err != nil {
			return ""
		}
		switch h.Type {
		case dnsmessage.TypeA:
			r, err := p.AResource()
			if err != nil {
				return ""
			}
			return net.IP(r.A[:]).String()
		case dnsmessage.TypeAAAA:
			r, err := p.AAAAResource()
			if err != nil {
				return ""
			}
			return net.IP(r.AAAA[:]).String()
		default:
			if err := p.SkipAnswer(); err != nil {
				return ""
			}
		}
	}
}

// buildQuery assembles an LLMNR query, which is a DNS query with the recursion
// and authority flags clear.
func buildQuery(id uint16, hostname string) ([]byte, error) {
	n, err := dnsmessage.NewName(hostname + ".")
	if err != nil {
		return nil, fmt.Errorf("hostname %q: %w", hostname, err)
	}

	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: id})
	b.EnableCompression()
	if err := b.StartQuestions(); err != nil {
		return nil, err
	}
	if err := b.Question(dnsmessage.Question{
		Name:  n,
		Type:  dnsmessage.TypeA,
		Class: dnsmessage.ClassINET,
	}); err != nil {
		return nil, err
	}
	return b.Finish()
}

// expire drops probes nobody answered, so an unanswered query — the normal
// case, on a healthy network — does not accumulate.
func (s *Service) expire() {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	for id, p := range s.outstanding {
		if now.Sub(p.sentAt) > outstandingTTL {
			delete(s.outstanding, id)
		}
	}
}

// randomHostname produces a name that looks like something an internal network
// would plausibly have.
//
// Plausibility is the point: an operator watching a poisoner's log should see
// a name that fits in, not an obvious canary. It is random per probe because a
// fixed name is one an attacker who has seen it before can teach their tool to
// stay silent for.
func randomHostname() string {
	const digits = "0123456789"
	roles := []string{"srv", "fs", "nas", "backup", "print", "app", "dc", "vault"}

	var b strings.Builder
	b.WriteString(roles[randInt(len(roles))])
	b.WriteByte('-')
	for i := 0; i < 2; i++ {
		b.WriteByte(digits[randInt(len(digits))])
	}
	return b.String()
}

// randInt is crypto/rand rather than math/rand: the probe name should not be
// predictable from a previous one by anyone watching the wire.
func randInt(n int) int {
	v, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		return 0
	}
	return int(v.Int64())
}

func randomID() (uint16, error) {
	var buf [2]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(buf[:]), nil
}

// jitter returns a random duration in [0, span).
func jitter(span time.Duration) time.Duration {
	if span <= 0 {
		return 0
	}
	return time.Duration(randInt(int(span)))
}
