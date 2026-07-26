package httpdecoy

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/willysnow/wisp/internal/event"
)

func recorder(t *testing.T) *Recorder {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	return NewRecorder("test", ln, event.EmitterFunc(func(event.Event) {}))
}

func request(t *testing.T, header, value string) *http.Request {
	t.Helper()

	r := httptest.NewRequest(http.MethodGet, "/whatever", nil)
	r.RemoteAddr = "10.0.0.9:41234"
	if header != "" {
		r.Header.Set(header, value)
	}
	return r
}

// TestBearerTokenPromotesAnOrdinaryProbe. A scan that carries a stolen token is
// not a scan, and an operator filtering on auth_attempt has to see it.
func TestBearerTokenPromotesAnOrdinaryProbe(t *testing.T) {
	rec := recorder(t)

	ev := rec.Event(request(t, "Authorization", "Bearer eyJhbGciOiJSUzI1NiJ9.stolen"), "probe")

	if ev.Kind != "auth_attempt" {
		t.Errorf("kind = %q, want auth_attempt", ev.Kind)
	}
	if ev.Data["auth_scheme"] != "Bearer" {
		t.Errorf("auth_scheme = %v, want Bearer", ev.Data["auth_scheme"])
	}
	if tok, _ := ev.Data["token"].(string); !strings.HasPrefix(tok, "eyJhbGciOiJSUzI1NiJ9") {
		t.Errorf("token = %q, want the presented credential", tok)
	}
}

// TestCredentialDoesNotOverwriteAStatedIntent is the other half of that rule.
//
// A request that carried a search query, a Groovy script, or a container spec
// has already told us what the intruder wanted. Relabelling it "auth_attempt"
// because it also carried a password would file the most specific event under
// the most generic name.
func TestCredentialDoesNotOverwriteAStatedIntent(t *testing.T) {
	rec := recorder(t)

	r := request(t, "", "")
	r.SetBasicAuth("elastic", "changeme")
	ev := rec.Event(r, "search_query")

	if ev.Kind != "search_query" {
		t.Errorf("kind = %q, want the caller's high-value kind to survive", ev.Kind)
	}
	if ev.Data["username"] != "elastic" || ev.Data["password"] != "changeme" {
		t.Errorf("credential was dropped: %v", ev.Data)
	}
}

// TestBasicAuthIsDecoded rather than logged as an opaque base64 blob. The point
// of capturing a credential is being able to read it.
func TestBasicAuthIsDecoded(t *testing.T) {
	rec := recorder(t)

	r := request(t, "", "")
	r.SetBasicAuth("admin", "hunter2")
	ev := rec.Event(r, "probe")

	if ev.Kind != "login_basic" {
		t.Errorf("kind = %q, want login_basic", ev.Kind)
	}
	if ev.Data["password"] != "hunter2" {
		t.Errorf("password = %v, want the decoded value", ev.Data["password"])
	}
	if _, raw := ev.Data["token"]; raw {
		t.Error("the base64 blob was logged as well as the decoded pair")
	}
}

// TestOversizedFieldsAreTruncated. One request must not be able to decide how
// much every downstream sink writes.
func TestOversizedFieldsAreTruncated(t *testing.T) {
	rec := recorder(t)

	ev := rec.Event(request(t, "Authorization", "Bearer "+strings.Repeat("A", 8000)), "probe")

	tok, _ := ev.Data["token"].(string)
	if len(tok) > TokenLimit+32 {
		t.Errorf("token is %d bytes, want it bounded at %d", len(tok), TokenLimit)
	}
	if !strings.HasSuffix(tok, "[truncated]") {
		t.Error("a clipped token must say it was clipped, or it reads as the whole credential")
	}
}

// TestBodyIsBounded: a decoy that reads whatever it is sent is a memory
// exhaustion primitive pointed at itself.
func TestBodyIsBounded(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(strings.Repeat("x", MaxBody*2)))
	w := httptest.NewRecorder()

	if n := len(Body(w, r)); n > MaxBody {
		t.Errorf("read %d bytes, want no more than %d", n, MaxBody)
	}
}

// TestStableIDIsStable. Pod UIDs, container IDs and cluster UUIDs that change
// on every restart identify the box as a honeypot to anyone who looks twice.
func TestStableIDIsStable(t *testing.T) {
	if StableID("customers", 22) != StableID("customers", 22) {
		t.Fatal("the same seed produced two different identifiers")
	}
	if StableID("customers", 22) == StableID("orders", 22) {
		t.Error("two different seeds produced the same identifier")
	}
	if got := len(StableID("x", 64)); got != 64 {
		t.Errorf("length = %d, want 64", got)
	}
}

// TestStableIDsDoNotShareAPrefix.
//
// This is the bug the avalanche step in StableID exists to prevent: emitting
// the top nibble of an FNV state gave every identifier the sensor produced the
// same two leading characters, so an intruder comparing any two of them saw
// that they came from the same generator.
func TestStableIDsDoNotShareAPrefix(t *testing.T) {
	seeds := []string{
		"customers", "orders-2026.07", "payments-audit", "app-logs-2026.07.26",
		".kibana_1", "postgres-0", "payments-api", "daemon", "bridge", "alpine:3.19",
	}

	firstChars := map[byte]int{}
	for _, seed := range seeds {
		id := StableID(seed, 22)
		firstChars[id[0]]++

		for _, other := range seeds {
			if other == seed {
				continue
			}
			if id[:3] == StableID(other, 22)[:3] {
				t.Errorf("%q and %q share the prefix %q", seed, other, id[:3])
			}
		}
	}

	// Ten identifiers landing on one or two starting characters is the failure;
	// a handful of collisions across sixteen is ordinary.
	if len(firstChars) < 5 {
		t.Errorf("%d seeds produced only %d distinct first characters: %v",
			len(seeds), len(firstChars), firstChars)
	}
}

// TestPromoteLeavesUnknownKindsAlone. Promote is the only path that rewrites a
// kind, and it must not invent one for a service that has not asked.
func TestPromoteLeavesUnknownKindsAlone(t *testing.T) {
	ev := event.NewRaw("test", "command", "10.0.0.1", 1, 2)
	Promote(&ev, "auth_attempt")
	if ev.Kind != "command" {
		t.Errorf("kind = %q, want command", ev.Kind)
	}

	ev = event.NewRaw("test", "probe", "10.0.0.1", 1, 2)
	Promote(&ev, "auth_attempt")
	if ev.Kind != "auth_attempt" {
		t.Errorf("kind = %q, want auth_attempt", ev.Kind)
	}
}
