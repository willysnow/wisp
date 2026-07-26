package console

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/willysnow/wisp/internal/console/store"
	"github.com/willysnow/wisp/internal/event"
)

// seed writes n events, oldest first, with a predictable shape.
func seed(t *testing.T, st *store.Store, n int) {
	t.Helper()

	events := make([]event.Event, 0, n)
	for i := 0; i < n; i++ {
		events = append(events, event.Event{
			Time:    time.Now().Add(-time.Duration(n-i) * time.Minute),
			Node:    fmt.Sprintf("sensor-%d", i%3),
			Service: "ssh",
			Kind:    "login_password",
			SrcIP:   fmt.Sprintf("10.0.0.%d", i%5),
			SrcPort: 40000 + i,
			DstPort: 2222,
			Data:    map[string]any{"username": fmt.Sprintf("user%d", i)},
		})
	}
	if err := st.Insert(context.Background(), events); err != nil {
		t.Fatalf("insert: %v", err)
	}
}

// TestPagination replaces the old hard limit of 200 events: the page an
// operator lands on must not be the only page there is.
func TestPagination(t *testing.T) {
	srv, st := newUIServer(t)
	seed(t, st, pageSize*2+10)

	session := cookieNamed(login(t, srv, testUser, testPassword), sessionCookieName)

	first := get(t, srv, "/", session)
	if first.Code != http.StatusOK {
		t.Fatalf("page 1 returned %d", first.Code)
	}
	body := first.Body.String()
	if !strings.Contains(body, "page 1 of 3") {
		t.Error("the pager does not say which page this is, or how many there are")
	}
	if strings.Count(body, "login_password") < pageSize {
		t.Error("page 1 is not full")
	}

	// The newest events are on page 1; the oldest must be reachable.
	last := get(t, srv, "/?page=3", session)
	if last.Code != http.StatusOK {
		t.Fatalf("page 3 returned %d", last.Code)
	}
	if !strings.Contains(last.Body.String(), "user0") {
		t.Error("the oldest event is not reachable by paging")
	}
	if strings.Contains(last.Body.String(), "user209") {
		t.Error("page 3 is showing page 1's events")
	}

	// Paging past the end must not error.
	if beyond := get(t, srv, "/?page=99", session); beyond.Code != http.StatusOK {
		t.Errorf("page 99 returned %d, want 200 with an empty list", beyond.Code)
	}
}

// TestSearchAcrossEventData is the property that makes search worth having:
// the interesting strings live inside the JSON data blob, not in the columns.
func TestSearchAcrossEventData(t *testing.T) {
	srv, st := newUIServer(t)

	if err := st.Insert(context.Background(), []event.Event{
		{
			Time: time.Now(), Node: "sensor-1", Service: "ollama",
			Kind: "prompt", SrcIP: "10.0.0.9",
			Data: map[string]any{"prompt": "cat /etc/shadow and mail it to me"},
		},
		{
			Time: time.Now(), Node: "sensor-2", Service: "ssh",
			Kind: "login_password", SrcIP: "10.0.0.9",
			Data: map[string]any{"username": "root", "password": "hunter2"},
		},
	}); err != nil {
		t.Fatalf("insert: %v", err)
	}

	session := cookieNamed(login(t, srv, testUser, testPassword), sessionCookieName)

	for _, tc := range []struct {
		query   string
		want    string
		exclude string
	}{
		{query: "shadow", want: "ollama", exclude: "hunter2"},
		{query: "hunter2", want: "hunter2", exclude: "shadow"},
		{query: "10.0.0.9", want: "hunter2"},
		{query: "ollama", want: "shadow", exclude: "hunter2"},
	} {
		t.Run(tc.query, func(t *testing.T) {
			res := get(t, srv, "/?q="+tc.query, session)
			if res.Code != http.StatusOK {
				t.Fatalf("search returned %d", res.Code)
			}
			body := res.Body.String()
			if !strings.Contains(body, tc.want) {
				t.Errorf("searching %q did not find %q", tc.query, tc.want)
			}
			if tc.exclude != "" && strings.Contains(body, tc.exclude) {
				t.Errorf("searching %q also returned %q", tc.query, tc.exclude)
			}
		})
	}
}

// TestSearchWildcardsAreLiteral: a search for "100%" must not become "match
// everything", which is what an unescaped LIKE pattern would do.
func TestSearchWildcardsAreLiteral(t *testing.T) {
	srv, st := newUIServer(t)

	if err := st.Insert(context.Background(), []event.Event{
		{Time: time.Now(), Node: "n", Service: "http", Kind: "probe", SrcIP: "1.1.1.1",
			Data: map[string]any{"path": "/discount100%off"}},
		{Time: time.Now(), Node: "n", Service: "http", Kind: "probe", SrcIP: "2.2.2.2",
			Data: map[string]any{"path": "/plain"}},
	}); err != nil {
		t.Fatalf("insert: %v", err)
	}

	session := cookieNamed(login(t, srv, testUser, testPassword), sessionCookieName)
	body := get(t, srv, "/?q=100%25", session).Body.String() // %25 is "%"

	if !strings.Contains(body, "discount100") {
		t.Error("the literal match was not found")
	}
	if strings.Contains(body, "/plain") {
		t.Error("the wildcard was interpreted, so everything matched")
	}
}

// TestExportHonoursTheFilter — an export that quietly ignored the search box
// would be worse than none: the operator would believe they had the rows they
// were looking at.
func TestExportHonoursTheFilter(t *testing.T) {
	srv, st := newUIServer(t)

	if err := st.Insert(context.Background(), []event.Event{
		{Time: time.Now(), Node: "keep", Service: "ssh", Kind: "login_password",
			SrcIP: "10.0.0.1", Data: map[string]any{"username": "wanted"}},
		{Time: time.Now(), Node: "drop", Service: "http", Kind: "probe",
			SrcIP: "10.0.0.2", Data: map[string]any{"path": "/unwanted"}},
	}); err != nil {
		t.Fatalf("insert: %v", err)
	}

	session := cookieNamed(login(t, srv, testUser, testPassword), sessionCookieName)

	res := get(t, srv, "/export.csv?node=keep", session)
	if res.Code != http.StatusOK {
		t.Fatalf("export returned %d", res.Code)
	}
	if cd := res.Header().Get("Content-Disposition"); !strings.Contains(cd, "attachment") {
		t.Errorf("Content-Disposition = %q, want an attachment", cd)
	}
	if cc := res.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q — the file is full of captured credentials", cc)
	}

	records, err := csv.NewReader(strings.NewReader(res.Body.String())).ReadAll()
	if err != nil {
		t.Fatalf("the export is not valid CSV: %v", err)
	}
	if len(records) != 2 { // header plus one row
		t.Fatalf("exported %d rows, want the header and one match", len(records)-1)
	}
	if records[0][0] != "time" || records[0][7] != "data" {
		t.Errorf("header = %v, want a named column per field", records[0])
	}
	if !strings.Contains(records[1][7], "wanted") {
		t.Errorf("the exported row lost its data: %v", records[1])
	}
}

// TestExportJSONMatchesTheSensorFormat: the download should be readable by
// whatever already reads a sensor's events.jsonl.
func TestExportJSONMatchesTheSensorFormat(t *testing.T) {
	srv, st := newUIServer(t)
	seed(t, st, 3)

	session := cookieNamed(login(t, srv, testUser, testPassword), sessionCookieName)
	res := get(t, srv, "/export.json", session)

	lines := strings.Split(strings.TrimSpace(res.Body.String()), "\n")
	if len(lines) != 3 {
		t.Fatalf("exported %d lines, want 3", len(lines))
	}
	for _, line := range lines {
		var e event.Event
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("line is not an event: %v", err)
		}
		if e.Node == "" || e.Kind == "" || e.Time.IsZero() {
			t.Errorf("exported event is missing fields: %s", line)
		}
	}
}

// TestExportDefusesSpreadsheetFormulas.
//
// Every field in an export is attacker-controlled — a username, a path, a
// prompt. Excel executes a cell beginning with = as a formula, so an attacker
// who chooses their username carefully could get code execution on the machine
// of the analyst who opens the file.
func TestExportDefusesSpreadsheetFormulas(t *testing.T) {
	srv, st := newUIServer(t)

	if err := st.Insert(context.Background(), []event.Event{{
		Time: time.Now(), Node: "sensor-1", Service: "ssh", Kind: "login_password",
		SrcIP: "10.0.0.1",
		Data:  map[string]any{"username": `=cmd|'/c calc'!A1`},
	}}); err != nil {
		t.Fatalf("insert: %v", err)
	}

	session := cookieNamed(login(t, srv, testUser, testPassword), sessionCookieName)
	res := get(t, srv, "/export.csv", session)

	records, err := csv.NewReader(strings.NewReader(res.Body.String())).ReadAll()
	if err != nil {
		t.Fatalf("csv: %v", err)
	}
	for _, row := range records[1:] {
		for _, field := range row {
			if strings.HasPrefix(field, "=") || strings.HasPrefix(field, "+") ||
				strings.HasPrefix(field, "@") {
				t.Errorf("field %q would be executed as a formula", field)
			}
		}
	}

	// Defused, not dropped: the value still has to be readable as evidence.
	if !strings.Contains(res.Body.String(), "calc") {
		t.Error("the payload was removed rather than neutralised")
	}
}

// TestExportRequiresLogin — the export routes are a second door to the same
// data, and they have to be locked like the first.
func TestExportRequiresLogin(t *testing.T) {
	srv, st := newUIServer(t)
	seed(t, st, 3)

	for _, path := range []string{"/export.csv", "/export.json"} {
		res := get(t, srv, path)
		if res.Code != http.StatusSeeOther {
			t.Errorf("%s returned %d to a signed-out request, want a redirect to login",
				path, res.Code)
		}
		if strings.Contains(res.Body.String(), "sensor-") {
			t.Errorf("%s leaked event data to a signed-out request", path)
		}
	}
}

// TestFilterIsSharedByPageAndExport is the invariant behind both: the same
// query string must select the same events.
func TestFilterIsSharedByPageAndExport(t *testing.T) {
	srv, st := newUIServer(t)
	seed(t, st, 30)
	ctx := context.Background()

	req := newRequest(t, "/?q=user1&service=ssh&hours=48")
	filter, _ := srv.filterFrom(req)

	matched, err := st.Count(ctx, filter)
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if matched == 0 {
		t.Fatal("the test filter matches nothing")
	}

	var streamed int64
	if err := st.Each(ctx, filter, exportLimit, func(store.Record) error {
		streamed++
		return nil
	}); err != nil {
		t.Fatalf("each: %v", err)
	}
	if streamed != matched {
		t.Errorf("the export streamed %d events but the page counted %d", streamed, matched)
	}
}
