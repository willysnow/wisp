package console

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/willysnow/wisp/internal/console/store"
)

// exportLimit caps one download. The retention policy already bounds the
// database, but an export is assembled by a browser on someone's laptop and a
// million rows helps nobody.
const exportLimit = 100000

// handleExport streams the current filter as CSV or JSON.
//
// It takes the same query parameters as the page it is linked from, so what
// lands in the file is exactly what the operator was looking at — an export
// that quietly ignores the search box would be worse than none.
func (s *Server) handleExport(w http.ResponseWriter, r *http.Request, _ string) {
	format := strings.TrimPrefix(r.URL.Path, "/export.")
	filter, _ := s.filterFrom(r)
	filter.Offset = 0

	stamp := time.Now().UTC().Format("20060102-150405")
	w.Header().Set("Content-Disposition",
		fmt.Sprintf(`attachment; filename="wisp-events-%s.%s"`, stamp, format))
	// The file is full of captured credentials. It should not sit in a proxy
	// cache on the way to the operator's browser.
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")

	switch format {
	case "csv":
		s.exportCSV(w, r, filter)
	case "json":
		s.exportJSON(w, r, filter)
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) exportCSV(w http.ResponseWriter, r *http.Request, filter store.Filter) {
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")

	out := csv.NewWriter(w)
	defer out.Flush()

	_ = out.Write([]string{"time", "node", "service", "kind",
		"src_ip", "src_port", "dst_port", "data"})

	err := s.store.Each(r.Context(), filter, exportLimit, func(rec store.Record) error {
		data, err := json.Marshal(rec.Data)
		if err != nil {
			data = []byte("{}")
		}
		return out.Write([]string{
			rec.Time.UTC().Format(time.RFC3339Nano),
			csvSafe(rec.Node),
			csvSafe(rec.Service),
			csvSafe(rec.Kind),
			csvSafe(rec.SrcIP),
			fmt.Sprint(rec.SrcPort),
			fmt.Sprint(rec.DstPort),
			csvSafe(string(data)),
		})
	})
	if err != nil {
		// Headers are long gone by now; the truncated file and the log line
		// are all that is left to say so.
		return
	}
}

// exportJSON writes newline-delimited JSON — the same shape the sensor's own
// events.jsonl has, so anything already pointed at that will read this too.
func (s *Server) exportJSON(w http.ResponseWriter, r *http.Request, filter store.Filter) {
	w.Header().Set("Content-Type", "application/x-ndjson; charset=utf-8")

	enc := json.NewEncoder(w)
	_ = s.store.Each(r.Context(), filter, exportLimit, func(rec store.Record) error {
		return enc.Encode(rec.Event)
	})
}

// csvSafe defuses spreadsheet formula injection.
//
// Every field in an export is attacker-controlled: a username, a probed path,
// a prompt. A value beginning with =, +, -, @, or a control character is
// executed as a formula by Excel and LibreOffice when the file is opened —
// which would turn "the analyst opened the export" into code execution on the
// analyst's machine. Prefixing with an apostrophe is the standard defusing,
// and it survives a round trip through a spreadsheet as text.
func csvSafe(s string) string {
	if s == "" {
		return s
	}
	switch s[0] {
	case '=', '+', '-', '@', '\t', '\r':
		return "'" + s
	}
	return s
}
