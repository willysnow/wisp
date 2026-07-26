package llmnrsvc

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/willysnow/wisp/internal/event"
)

const readTimeout = 500 * time.Millisecond

// start brings the detector up on a loopback socket and returns a client
// socket plus an accessor for the events it emitted.
func start(t *testing.T, svc *Service) (client net.PacketConn, server net.Addr, events func() []event.Event) {
	t.Helper()

	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
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
		_ = svc.ServePacket(ctx, pc, emit)
	}()

	client, err = net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("client listen: %v", err)
	}

	t.Cleanup(func() {
		client.Close()
		cancel()
		<-done
	})

	return client, pc.LocalAddr(), func() []event.Event {
		mu.Lock()
		defer mu.Unlock()
		return append([]event.Event(nil), seen...)
	}
}

func query(t *testing.T, id uint16, hostname string) []byte {
	t.Helper()

	msg, err := buildQuery(id, hostname)
	if err != nil {
		t.Fatalf("build query: %v", err)
	}
	return msg
}

// TestNeverAnswersQueries is this module's version of the NTP rule.
//
// Answering an LLMNR query for a name we do not own *is* LLMNR poisoning — the
// exact attack this module exists to detect. A detector that performs the
// attack it detects is not a detector, and on a real network it would be
// stealing authentication attempts from the machines around it.
func TestNeverAnswersQueries(t *testing.T) {
	client, server, events := start(t, New("127.0.0.1:0", "", time.Hour, 0))

	// Ask for a name, the way any Windows host on the segment would.
	if _, err := client.WriteTo(query(t, 0x1234, "fileserver"), server); err != nil {
		t.Fatalf("write: %v", err)
	}

	_ = client.SetReadDeadline(time.Now().Add(readTimeout))
	buf := make([]byte, 512)
	n, _, err := client.ReadFrom(buf)
	if err == nil {
		t.Fatalf("the detector answered an LLMNR query with %d bytes — that is poisoning", n)
	}

	for _, e := range events() {
		if e.Kind == "llmnr_poisoned" {
			t.Error("a query from another host was recorded as poisoning")
		}
	}
}

// TestPoisonedResponseIsRecorded is the detection itself: a reply to a name
// that does not exist can only have come from something answering everything.
func TestPoisonedResponseIsRecorded(t *testing.T) {
	svc := New("127.0.0.1:0", "decoy-host", time.Hour, 0)
	client, server, events := start(t, svc)

	// Stand in for the probe the service would send on its own timer.
	const id = 0xbeef
	svc.mu.Lock()
	svc.outstanding[id] = probe{hostname: "decoy-host", sentAt: time.Now()}
	svc.mu.Unlock()

	if _, err := client.WriteTo(poisonedReply(t, id, "decoy-host", "10.0.0.66"), server); err != nil {
		t.Fatalf("write: %v", err)
	}

	ev := waitForKind(t, events, "llmnr_poisoned")
	if ev.Data["queried"] != "decoy-host" {
		t.Errorf("queried = %v, want decoy-host", ev.Data["queried"])
	}
	if ev.Data["claimed_address"] != "10.0.0.66" {
		t.Errorf("claimed_address = %v, want 10.0.0.66 — the attacker's own address is the lead",
			ev.Data["claimed_address"])
	}
	if ev.SrcIP != "127.0.0.1" {
		t.Errorf("SrcIP = %q, want the responder's address", ev.SrcIP)
	}
}

// TestUnsolicitedResponseIgnored: only replies to our own probe count. Anything
// else is another machine's conversation, and reporting it would turn ordinary
// name resolution into a stream of false alarms.
func TestUnsolicitedResponseIgnored(t *testing.T) {
	client, server, events := start(t, New("127.0.0.1:0", "", time.Hour, 0))

	if _, err := client.WriteTo(poisonedReply(t, 0x0001, "someone-else", "10.0.0.5"), server); err != nil {
		t.Fatalf("write: %v", err)
	}

	time.Sleep(100 * time.Millisecond)
	for _, e := range events() {
		if e.Kind == "llmnr_poisoned" {
			t.Fatal("a reply to a query we never sent was reported as poisoning")
		}
	}
}

// TestStaleResponseIgnored covers the same property in time rather than in
// identity.
func TestStaleResponseIgnored(t *testing.T) {
	svc := New("127.0.0.1:0", "decoy-host", time.Hour, 0)
	client, server, events := start(t, svc)

	const id = 0x00ff
	svc.mu.Lock()
	svc.outstanding[id] = probe{
		hostname: "decoy-host",
		sentAt:   time.Now().Add(-2 * outstandingTTL),
	}
	svc.mu.Unlock()

	if _, err := client.WriteTo(poisonedReply(t, id, "decoy-host", "10.0.0.7"), server); err != nil {
		t.Fatalf("write: %v", err)
	}

	time.Sleep(100 * time.Millisecond)
	for _, e := range events() {
		if e.Kind == "llmnr_poisoned" {
			t.Fatal("a reply long after the probe expired was still accepted")
		}
	}
}

// TestRandomHostnamesDiffer: the probe name is random per query so that an
// attacker who has seen one cannot teach their tool to stay silent for it.
func TestRandomHostnamesDiffer(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		seen[randomHostname()] = true
	}
	if len(seen) < 10 {
		t.Errorf("only %d distinct hostnames in 50 probes — too predictable", len(seen))
	}

	// It also has to be a name that can go on the wire at all.
	if _, err := buildQuery(1, randomHostname()); err != nil {
		t.Errorf("generated hostname is not encodable: %v", err)
	}
}

// poisonedReply builds what Responder sends: an answer claiming the name
// resolves to the attacker's address.
func poisonedReply(t *testing.T, id uint16, hostname, addr string) []byte {
	t.Helper()

	n, err := dnsmessage.NewName(hostname + ".")
	if err != nil {
		t.Fatalf("name: %v", err)
	}

	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: id, Response: true})
	if err := b.StartQuestions(); err != nil {
		t.Fatalf("questions: %v", err)
	}
	q := dnsmessage.Question{Name: n, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}
	if err := b.Question(q); err != nil {
		t.Fatalf("question: %v", err)
	}
	if err := b.StartAnswers(); err != nil {
		t.Fatalf("answers: %v", err)
	}

	ip := net.ParseIP(addr).To4()
	if ip == nil {
		t.Fatalf("bad test address %q", addr)
	}
	var a [4]byte
	copy(a[:], ip)

	if err := b.AResource(dnsmessage.ResourceHeader{
		Name:  n,
		Type:  dnsmessage.TypeA,
		Class: dnsmessage.ClassINET,
		TTL:   30,
	}, dnsmessage.AResource{A: a}); err != nil {
		t.Fatalf("resource: %v", err)
	}

	msg, err := b.Finish()
	if err != nil {
		t.Fatalf("finish: %v", err)
	}
	return msg
}

func waitForKind(t *testing.T, events func() []event.Event, kind string) event.Event {
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
