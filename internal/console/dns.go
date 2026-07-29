package console

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/willysnow/wisp/internal/console/notify"
	"github.com/willysnow/wisp/internal/console/store"
	"github.com/willysnow/wisp/internal/event"
)

// A DNS token is the one that reaches the console from a network HTTP cannot
// leave. The lure is a hostname under a zone delegated to this server; resolving
// it — from anywhere, through any recursive resolver — walks the query out to
// us, and the query itself is the callback. It is the same path data
// exfiltration takes, so a segment locked down enough to stop the HTTP tokens is
// usually still wide open to this one.
//
// The server answers, but it is not an amplifier: a single A record is the size
// of the question, and it never recurses. It exists to log, and to hand back an
// address so the resolver that asked is satisfied and the lookup that carried
// the id completes.

// dnsAnswerTTL is the TTL on the A record handed back. Short, because the answer
// is not meant to be cached — every fresh resolution is another sighting worth
// recording.
const dnsAnswerTTL = 30

// dnsUDPTimeout bounds how long a read blocks before the loop rechecks ctx, and
// how long recording one query may take.
const dnsUDPTimeout = 5 * time.Second

// DNSConfig configures the authoritative token server. Disabled by default: it
// is the one part of the console that wants a privileged port and a delegated
// domain, so it only runs when an operator has set both up.
type DNSConfig struct {
	Enabled bool
	// Zone is the domain delegated to this server, e.g. tokens.example.com.
	Zone string
	// Addr is the listen address. Empty means :53.
	Addr string
	// Answer is the address returned for A queries under the zone. Nil means
	// 127.0.0.1 — deliberately a black hole, since the answer only has to
	// satisfy the resolver, not lead anywhere.
	Answer net.IP
}

// Active reports whether the DNS server should run: enabled, and with the zone
// it needs to know what it is authoritative for.
func (c DNSConfig) Active() bool { return c.Enabled && c.Zone != "" }

// DNSServer is the authoritative server for token callbacks over DNS.
type DNSServer struct {
	zone     string // normalized: lowercase, no leading/trailing dot
	addr     string
	answer   net.IP
	store    *store.Store
	dispatch *notify.Dispatcher
	logger   *log.Logger
}

// NewDNSServer builds the server. It does not open any socket until Run.
func NewDNSServer(cfg DNSConfig, st *store.Store, dispatch *notify.Dispatcher, logger *log.Logger) *DNSServer {
	addr := cfg.Addr
	if addr == "" {
		addr = ":53"
	}
	answer := cfg.Answer
	if answer == nil {
		answer = net.IPv4(127, 0, 0, 1)
	}
	return &DNSServer{
		zone:     strings.ToLower(strings.Trim(strings.TrimSpace(cfg.Zone), ".")),
		addr:     addr,
		answer:   answer,
		store:    st,
		dispatch: dispatch,
		logger:   logger,
	}
}

// Run serves UDP and TCP until ctx is cancelled. DNS uses UDP first and falls
// back to TCP on truncation or by policy, so both are answered — the reply here
// is tiny either way.
func (s *DNSServer) Run(ctx context.Context) error {
	if s.zone == "" {
		return errors.New("dns: no zone configured")
	}

	pc, err := net.ListenPacket("udp", s.addr)
	if err != nil {
		return err
	}
	defer pc.Close()

	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return err
	}
	defer ln.Close()

	go func() {
		<-ctx.Done()
		pc.Close()
		ln.Close()
	}()

	go s.serveTCP(ctx, ln)
	s.serveUDP(ctx, pc)
	return nil
}

func (s *DNSServer) serveUDP(ctx context.Context, pc net.PacketConn) {
	buf := make([]byte, 512)
	for {
		if ctx.Err() != nil {
			return
		}
		_ = pc.SetReadDeadline(time.Now().Add(dnsUDPTimeout))
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return // listener closed
		}

		srcIP, _ := event.SplitHostPortString(addr.String())
		reply, ok := s.respond(ctx, buf[:n], srcIP)
		if !ok {
			continue
		}
		_ = pc.SetWriteDeadline(time.Now().Add(dnsUDPTimeout))
		_, _ = pc.WriteTo(reply, addr)
	}
}

func (s *DNSServer) serveTCP(ctx context.Context, ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return // listener closed
		}
		go s.handleTCPConn(ctx, conn)
	}
}

func (s *DNSServer) handleTCPConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(dnsUDPTimeout))

	// A DNS-over-TCP message is a 2-byte big-endian length followed by the
	// message itself.
	var lenBuf [2]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return
	}
	msgLen := int(lenBuf[0])<<8 | int(lenBuf[1])
	if msgLen == 0 {
		return
	}
	msg := make([]byte, msgLen)
	if _, err := io.ReadFull(conn, msg); err != nil {
		return
	}

	srcIP, _ := event.SplitHostPortString(conn.RemoteAddr().String())
	reply, ok := s.respond(ctx, msg, srcIP)
	if !ok {
		return
	}
	out := make([]byte, 2+len(reply))
	out[0] = byte(len(reply) >> 8)
	out[1] = byte(len(reply))
	copy(out[2:], reply)
	_, _ = conn.Write(out)
}

// respond parses a query, records a firing if it names a live token under the
// zone, and builds the reply. The bool reports whether there is a reply to send
// — a packet we cannot parse is dropped, the way a real server ignores garbage.
//
// It is the whole of the DNS logic, factored out so it can be tested without a
// socket.
func (s *DNSServer) respond(ctx context.Context, query []byte, srcIP string) ([]byte, bool) {
	var p dnsmessage.Parser
	hdr, err := p.Start(query)
	if err != nil || hdr.Response {
		return nil, false
	}
	q, err := p.Question()
	if err != nil {
		return nil, false
	}

	name := strings.ToLower(strings.TrimSuffix(q.Name.String(), "."))
	rcode := dnsmessage.RCodeSuccess
	authoritative := true

	tokenID, under := s.match(name)
	switch {
	case !under:
		// Not our zone. Say so honestly rather than pretending — a resolver that
		// delegated to us expects authority only for the zone.
		rcode = dnsmessage.RCodeRefused
		authoritative = false
	case tokenID != "":
		s.record(ctx, tokenID, name, q.Type, srcIP)
	}

	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{
		ID:               hdr.ID,
		Response:         true,
		OpCode:           hdr.OpCode,
		Authoritative:    authoritative,
		RecursionDesired: hdr.RecursionDesired,
		RCode:            rcode,
	})
	b.EnableCompression()
	if err := b.StartQuestions(); err != nil {
		return nil, false
	}
	if err := b.Question(q); err != nil {
		return nil, false
	}

	// Answer A queries inside the zone with the black-hole address so the lookup
	// completes; every other type gets an authoritative empty answer.
	if under && rcode == dnsmessage.RCodeSuccess && q.Type == dnsmessage.TypeA {
		var a [4]byte
		copy(a[:], s.answer.To4())
		if err := b.StartAnswers(); err == nil {
			_ = b.AResource(dnsmessage.ResourceHeader{
				Name:  q.Name,
				Type:  dnsmessage.TypeA,
				Class: dnsmessage.ClassINET,
				TTL:   dnsAnswerTTL,
			}, dnsmessage.AResource{A: a})
		}
	}

	msg, err := b.Finish()
	if err != nil {
		return nil, false
	}
	return msg, true
}

// match reports whether name falls under the zone and, if so, which token id it
// carries. The id is the label immediately to the left of the zone, so both the
// bare token name and a cache-busted <random>.<id>.<zone> — which some clients
// produce — resolve to the same token.
func (s *DNSServer) match(name string) (tokenID string, under bool) {
	if name == s.zone {
		return "", true // the bare zone, no token
	}
	suffix := "." + s.zone
	if !strings.HasSuffix(name, suffix) {
		return "", false
	}
	prefix := strings.TrimSuffix(name, suffix)
	labels := strings.Split(prefix, ".")
	return labels[len(labels)-1], true
}

func (s *DNSServer) record(ctx context.Context, id, qname string, qtype dnsmessage.Type, srcIP string) {
	ev := event.Event{
		Time:    time.Now().UTC(),
		Node:    TokenNode,
		Service: TokenService,
		Kind:    KindTokenTriggered,
		SrcIP:   srcIP,
		Data: map[string]any{
			"via":        "dns",
			"qname":      qname,
			"query_type": dnsType(qtype),
		},
	}

	rctx, cancel := context.WithTimeout(ctx, dnsUDPTimeout)
	defer cancel()

	_, ok, err := s.store.RecordTokenTrigger(rctx, id, ev)
	if err != nil {
		s.logf("dns token record failed: %v", err)
		return
	}
	if ok && s.dispatch != nil {
		s.dispatch.Handle([]event.Event{ev})
	}
}

func (s *DNSServer) logf(format string, args ...any) {
	if s.logger != nil {
		s.logger.Printf(format, args...)
	}
}

// dnsType renders the common query types by name and falls back to the numeric
// form, so the recorded event reads "A" or "AAAA" rather than "16".
func dnsType(t dnsmessage.Type) string {
	switch t {
	case dnsmessage.TypeA:
		return "A"
	case dnsmessage.TypeAAAA:
		return "AAAA"
	case dnsmessage.TypeTXT:
		return "TXT"
	case dnsmessage.TypeCNAME:
		return "CNAME"
	case dnsmessage.TypeNS:
		return "NS"
	case dnsmessage.TypeMX:
		return "MX"
	case dnsmessage.TypeSRV:
		return "SRV"
	case dnsmessage.TypeSOA:
		return "SOA"
	}
	return t.String()
}
