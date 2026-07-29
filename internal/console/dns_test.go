package console

import (
	"context"
	"net"
	"path/filepath"
	"testing"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/willysnow/wisp/internal/console/store"
)

const testZone = "tokens.example.com"

func newTestDNS(t *testing.T, answer net.IP) (*DNSServer, *store.Store) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "dns.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	srv := NewDNSServer(DNSConfig{Enabled: true, Zone: testZone, Answer: answer}, st, nil, nil)
	return srv, st
}

func dnsQuery(t *testing.T, name string, qtype dnsmessage.Type) []byte {
	t.Helper()
	n, err := dnsmessage.NewName(name + ".")
	if err != nil {
		t.Fatalf("NewName(%q): %v", name, err)
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 4242, RecursionDesired: true})
	if err := b.StartQuestions(); err != nil {
		t.Fatalf("StartQuestions: %v", err)
	}
	if err := b.Question(dnsmessage.Question{Name: n, Type: qtype, Class: dnsmessage.ClassINET}); err != nil {
		t.Fatalf("Question: %v", err)
	}
	msg, err := b.Finish()
	if err != nil {
		t.Fatalf("Finish: %v", err)
	}
	return msg
}

// parseReply returns the RCODE and the A answers in a reply.
func parseReply(t *testing.T, msg []byte) (dnsmessage.RCode, []net.IP) {
	t.Helper()
	var p dnsmessage.Parser
	hdr, err := p.Start(msg)
	if err != nil {
		t.Fatalf("parse reply: %v", err)
	}
	if !hdr.Response {
		t.Fatal("reply is not marked as a response")
	}
	if err := p.SkipAllQuestions(); err != nil {
		t.Fatalf("skip questions: %v", err)
	}

	var ips []net.IP
	for {
		ah, err := p.AnswerHeader()
		if err == dnsmessage.ErrSectionDone {
			break
		}
		if err != nil {
			t.Fatalf("answer header: %v", err)
		}
		if ah.Type == dnsmessage.TypeA {
			a, err := p.AResource()
			if err != nil {
				t.Fatalf("A resource: %v", err)
			}
			ips = append(ips, net.IPv4(a.A[0], a.A[1], a.A[2], a.A[3]))
		} else {
			if err := p.SkipAnswer(); err != nil {
				t.Fatalf("skip answer: %v", err)
			}
		}
	}
	return hdr.RCode, ips
}

// TestDNSTokenRecordsAndAnswers is the DNS half of the core property: resolving
// a live token's name records the firing and hands back the black-hole address
// so the lookup completes.
func TestDNSTokenRecordsAndAnswers(t *testing.T) {
	srv, st := newTestDNS(t, nil) // default answer 127.0.0.1
	ctx := context.Background()

	tok, _ := st.CreateToken(ctx, "dns", "wiki page", "")

	reply, ok := srv.respond(ctx, dnsQuery(t, tok.ID+"."+testZone, dnsmessage.TypeA), "198.51.100.9")
	if !ok {
		t.Fatal("respond returned no reply for a valid query")
	}
	rcode, ips := parseReply(t, reply)
	if rcode != dnsmessage.RCodeSuccess {
		t.Errorf("RCODE = %v, want success", rcode)
	}
	if len(ips) != 1 || !ips[0].Equal(net.IPv4(127, 0, 0, 1)) {
		t.Errorf("A answers = %v, want [127.0.0.1]", ips)
	}

	events, _ := st.List(ctx, store.Filter{})
	if len(events) != 1 {
		t.Fatalf("recorded %d events, want 1", len(events))
	}
	if events[0].Data["via"] != "dns" || events[0].Data["query_type"] != "A" {
		t.Errorf("event data = %v, want via=dns query_type=A", events[0].Data)
	}
	if events[0].SrcIP != "198.51.100.9" {
		t.Errorf("SrcIP = %q, want the resolver address", events[0].SrcIP)
	}
}

func TestDNSCustomAnswer(t *testing.T) {
	srv, st := newTestDNS(t, net.IPv4(10, 1, 2, 3))
	tok, _ := st.CreateToken(context.Background(), "dns", "", "")

	reply, _ := srv.respond(context.Background(), dnsQuery(t, tok.ID+"."+testZone, dnsmessage.TypeA), "198.51.100.9")
	_, ips := parseReply(t, reply)
	if len(ips) != 1 || !ips[0].Equal(net.IPv4(10, 1, 2, 3)) {
		t.Errorf("A answers = %v, want [10.1.2.3]", ips)
	}
}

// TestDNSOutsideZoneRefused checks the server is honest about its authority: a
// name it was not delegated is refused, not answered.
func TestDNSOutsideZoneRefused(t *testing.T) {
	srv, st := newTestDNS(t, nil)

	reply, ok := srv.respond(context.Background(), dnsQuery(t, "evil.example.net", dnsmessage.TypeA), "198.51.100.9")
	if !ok {
		t.Fatal("respond dropped a well-formed out-of-zone query")
	}
	rcode, _ := parseReply(t, reply)
	if rcode != dnsmessage.RCodeRefused {
		t.Errorf("RCODE = %v, want refused", rcode)
	}
	if events, _ := st.List(context.Background(), store.Filter{}); len(events) != 0 {
		t.Errorf("an out-of-zone query recorded %d events", len(events))
	}
}

// TestDNSUnknownTokenAnswersWithoutRecording keeps the DNS side from being an
// oracle for which ids are live: an unknown name under the zone still gets a
// normal answer, but nothing is recorded.
func TestDNSUnknownTokenAnswersWithoutRecording(t *testing.T) {
	srv, st := newTestDNS(t, nil)

	reply, ok := srv.respond(context.Background(), dnsQuery(t, "nosuchid."+testZone, dnsmessage.TypeA), "198.51.100.9")
	if !ok {
		t.Fatal("respond dropped a well-formed in-zone query")
	}
	rcode, ips := parseReply(t, reply)
	if rcode != dnsmessage.RCodeSuccess || len(ips) != 1 {
		t.Errorf("unknown in-zone name got RCODE %v / %d answers, want success with an A", rcode, len(ips))
	}
	if events, _ := st.List(context.Background(), store.Filter{}); len(events) != 0 {
		t.Errorf("an unknown token recorded %d events", len(events))
	}
}

// TestDNSCacheBustPrefixExtractsToken covers the shape some clients produce,
// where a random label is prepended to defeat caching: the token id is still
// the label next to the zone.
func TestDNSCacheBustPrefixExtractsToken(t *testing.T) {
	srv, st := newTestDNS(t, nil)
	ctx := context.Background()
	tok, _ := st.CreateToken(ctx, "dns", "", "")

	_, ok := srv.respond(ctx, dnsQuery(t, "s1."+tok.ID+"."+testZone, dnsmessage.TypeA), "198.51.100.9")
	if !ok {
		t.Fatal("respond dropped a cache-busted query")
	}
	if events, _ := st.List(ctx, store.Filter{}); len(events) != 1 {
		t.Errorf("cache-busted name recorded %d events, want 1", len(events))
	}
}

// TestDNSAAAARecordsButHasNoAnswer checks a non-A lookup still counts as a
// firing — resolving the name at all is the signal — while the server returns no
// address of a type it does not serve.
func TestDNSAAAARecordsButHasNoAnswer(t *testing.T) {
	srv, st := newTestDNS(t, nil)
	ctx := context.Background()
	tok, _ := st.CreateToken(ctx, "dns", "", "")

	reply, _ := srv.respond(ctx, dnsQuery(t, tok.ID+"."+testZone, dnsmessage.TypeAAAA), "198.51.100.9")
	rcode, ips := parseReply(t, reply)
	if rcode != dnsmessage.RCodeSuccess {
		t.Errorf("AAAA RCODE = %v, want success", rcode)
	}
	if len(ips) != 0 {
		t.Errorf("AAAA query got A answers %v, want none", ips)
	}
	if events, _ := st.List(ctx, store.Filter{}); len(events) != 1 {
		t.Errorf("AAAA lookup recorded %d events, want 1", len(events))
	}
}

func TestDNSDisabledTokenNotRecorded(t *testing.T) {
	srv, st := newTestDNS(t, nil)
	ctx := context.Background()
	tok, _ := st.CreateToken(ctx, "dns", "", "")
	if _, err := st.DisableToken(ctx, tok.ID); err != nil {
		t.Fatalf("DisableToken: %v", err)
	}

	reply, ok := srv.respond(ctx, dnsQuery(t, tok.ID+"."+testZone, dnsmessage.TypeA), "198.51.100.9")
	if !ok {
		t.Fatal("respond dropped a query for a disabled token")
	}
	// Still answers — no oracle — but records nothing.
	if _, ips := parseReply(t, reply); len(ips) != 1 {
		t.Errorf("disabled-token query got %d answers, want 1 (no oracle)", len(ips))
	}
	if events, _ := st.List(ctx, store.Filter{}); len(events) != 0 {
		t.Errorf("a disabled token recorded %d events", len(events))
	}
}

// TestDNSDropsGarbage checks a packet that is not a DNS query produces no reply,
// the way a real server ignores noise rather than answering it.
func TestDNSDropsGarbage(t *testing.T) {
	srv, _ := newTestDNS(t, nil)
	if _, ok := srv.respond(context.Background(), []byte("not a dns packet"), "198.51.100.9"); ok {
		t.Error("respond answered a malformed packet")
	}
}
