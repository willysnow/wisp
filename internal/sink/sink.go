// Package sink writes events out. Sinks are the seam where the open-source
// agent will later hand off to a hosted console: adding a gRPC/HTTPS sink here
// requires no change to any service.
package sink

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"

	"github.com/willysnow/wisp/internal/event"
)

// Multi fans one event out to several sinks.
type Multi []event.Emitter

func (m Multi) Emit(e event.Event) {
	for _, s := range m {
		s.Emit(e)
	}
}

// JSONL writes one JSON object per line. This is the machine-readable format —
// point Filebeat/Vector/Promtail at it, or tail it into a SIEM.
type JSONL struct {
	mu sync.Mutex
	w  io.Writer
}

func NewJSONL(w io.Writer) *JSONL { return &JSONL{w: w} }

// NewJSONLFile opens path in append mode, rotating it by size. The caller owns
// closing the returned file.
func NewJSONLFile(path string, rotate RotateConfig) (*JSONL, *RotatingFile, error) {
	f, err := OpenRotating(path, rotate)
	if err != nil {
		return nil, nil, err
	}
	return NewJSONL(f), f, nil
}

func (j *JSONL) Emit(e event.Event) {
	b, err := json.Marshal(e)
	if err != nil {
		return
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	_, _ = j.w.Write(append(b, '\n'))
}

// Console writes a short human-readable line. For operators watching a terminal
// during setup, not for machines.
type Console struct {
	mu sync.Mutex
	w  io.Writer
}

func NewConsole(w io.Writer) *Console { return &Console{w: w} }

func (c *Console) Emit(e event.Event) {
	var b strings.Builder
	fmt.Fprintf(&b, "%s  %-7s %-14s %s:%d -> :%d",
		e.Time.Format("15:04:05"), e.Service, e.Kind, e.SrcIP, e.SrcPort, e.DstPort)

	// Sort keys so repeated events read identically run to run.
	keys := make([]string, 0, len(e.Data))
	for k := range e.Data {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(&b, "  %s=%s", k, truncate(fmt.Sprint(e.Data[k]), 120))
	}
	b.WriteByte('\n')

	c.mu.Lock()
	defer c.mu.Unlock()
	_, _ = io.WriteString(c.w, b.String())
}

// truncate shortens a value for the console line. The marker is ASCII on
// purpose: the Windows console's default code page renders U+2026 and friends
// as mojibake, which makes the whole tool look broken on a platform it
// otherwise supports.
func truncate(s string, n int) string {
	s = strings.ReplaceAll(s, "\n", "\\n")
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
