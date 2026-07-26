package sink

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/willysnow/wisp/internal/event"
)

func logPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "events.jsonl")
}

func read(t *testing.T, path string) string {
	t.Helper()

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", filepath.Base(path), err)
	}
	return string(b)
}

// TestRotationNeverSplitsALine is the property the whole design turns on.
//
// The size check happens before the write rather than after, so a record lands
// in exactly one file. Rotating afterwards would leave the tail of a JSON
// object in one file and nothing in the next, and a half-written object is a
// parse error in whatever the operator pointed at the log.
func TestRotationNeverSplitsALine(t *testing.T) {
	path := logPath(t)

	// Small enough that almost every event rotates, so the property is
	// exercised dozens of times rather than once.
	f, err := OpenRotating(path, RotateConfig{MaxSize: 400, MaxFiles: 4})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	sink := NewJSONL(f)

	for i := 0; i < 60; i++ {
		ev := event.NewRaw("elasticsearch", "search_query", "10.0.0.9", 41234, 9200)
		ev.Node = "sensor-1"
		ev.Data["query"] = strings.Repeat("q", 40)
		sink.Emit(ev)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// Every line in every generation has to be a complete JSON object.
	lines := 0
	for _, name := range []string{path, path + ".1", path + ".2", path + ".3", path + ".4"} {
		b, err := os.ReadFile(name)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		for _, line := range strings.Split(strings.TrimRight(string(b), "\n"), "\n") {
			if line == "" {
				continue
			}
			lines++
			var ev event.Event
			if err := json.Unmarshal([]byte(line), &ev); err != nil {
				t.Fatalf("%s: truncated record: %v\n%q", filepath.Base(name), err, line)
			}
			if ev.Service != "elasticsearch" || ev.Kind != "search_query" {
				t.Fatalf("%s: record lost fields: %+v", filepath.Base(name), ev)
			}
		}
	}
	if lines == 0 {
		t.Fatal("nothing was written")
	}
}

// TestOldGenerationsAreDiscarded. The point of rotating is a bound on disk, and
// a bound nobody enforces is a comment.
func TestOldGenerationsAreDiscarded(t *testing.T) {
	path := logPath(t)

	f, err := OpenRotating(path, RotateConfig{MaxSize: 100, MaxFiles: 2})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	for i := 0; i < 40; i++ {
		if _, err := f.Write([]byte(strings.Repeat("x", 60) + "\n")); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	if _, err := os.Stat(path + ".3"); !os.IsNotExist(err) {
		t.Error("a third generation survived a max_files of 2")
	}
	for _, name := range []string{path, path + ".1", path + ".2"} {
		if _, err := os.Stat(name); err != nil {
			t.Errorf("%s is missing: %v", filepath.Base(name), err)
		}
	}
}

// TestNewestDataIsInTheLiveFile. Generations shift away from the live file, so
// events.jsonl is always the one to tail. Getting the direction backwards would
// be invisible until someone needed the log.
func TestNewestDataIsInTheLiveFile(t *testing.T) {
	path := logPath(t)

	f, err := OpenRotating(path, RotateConfig{MaxSize: 60, MaxFiles: 3})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	for _, marker := range []string{"oldest", "middle", "newest"} {
		if _, err := f.Write([]byte(marker + strings.Repeat("-", 60) + "\n")); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	if got := read(t, path); !strings.HasPrefix(got, "newest") {
		t.Errorf("live file starts %.10q, want the newest record", got)
	}
	if got := read(t, path+".1"); !strings.HasPrefix(got, "middle") {
		t.Errorf("generation 1 starts %.10q, want the previous record", got)
	}
	if got := read(t, path+".2"); !strings.HasPrefix(got, "oldest") {
		t.Errorf("generation 2 starts %.10q, want the oldest record", got)
	}
}

// TestSizeSurvivesARestart. A sensor that restarts often would otherwise never
// rotate: each start would begin counting from zero against a file that is
// already at the threshold.
func TestSizeSurvivesARestart(t *testing.T) {
	path := logPath(t)
	cfg := RotateConfig{MaxSize: 200, MaxFiles: 2}

	first, err := OpenRotating(path, cfg)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := first.Write([]byte(strings.Repeat("a", 190) + "\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	second, err := OpenRotating(path, cfg)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if _, err := second.Write([]byte("after the restart\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := second.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	if _, err := os.Stat(path + ".1"); err != nil {
		t.Fatalf("the restarted sensor did not rotate: %v", err)
	}
	if got := read(t, path); !strings.HasPrefix(got, "after the restart") {
		t.Errorf("live file = %.20q, want only what was written after the restart", got)
	}
}

// TestRotationCanBeTurnedOff, for a deployment that already points logrotate or
// journald at the file. Two log rotators fighting over one file is worse than
// either alone.
func TestRotationCanBeTurnedOff(t *testing.T) {
	path := logPath(t)

	f, err := OpenRotating(path, RotateConfig{MaxSize: 0})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	for i := 0; i < 50; i++ {
		if _, err := f.Write([]byte(strings.Repeat("x", 100) + "\n")); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	if _, err := os.Stat(path + ".1"); !os.IsNotExist(err) {
		t.Error("rotation happened with MaxSize 0")
	}
	if got := len(read(t, path)); got != 50*101 {
		t.Errorf("wrote %d bytes, want all 5050 kept", got)
	}
}

// TestConcurrentWritersDoNotInterleave. Every service handles its connections
// in its own goroutine, so the sink is written from many at once — and a
// rotation in the middle of that must not lose or corrupt a record.
func TestConcurrentWritersDoNotInterleave(t *testing.T) {
	path := logPath(t)

	f, err := OpenRotating(path, RotateConfig{MaxSize: 512, MaxFiles: 8})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	sink := NewJSONL(f)

	const writers, each = 8, 40
	done := make(chan struct{})
	for w := 0; w < writers; w++ {
		go func(w int) {
			defer func() { done <- struct{}{} }()
			for i := 0; i < each; i++ {
				ev := event.NewRaw("docker", "container_create", "10.0.0.9", 1024+w, 2375)
				ev.Time = time.Now().UTC()
				ev.Data["binds"] = strings.Repeat("/:/host ", 5)
				sink.Emit(ev)
			}
		}(w)
	}
	for w := 0; w < writers; w++ {
		<-done
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	total := 0
	for i := 0; i <= 8; i++ {
		name := path
		if i > 0 {
			name = generation(path, i)
		}
		b, err := os.ReadFile(name)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		for _, line := range strings.Split(strings.TrimRight(string(b), "\n"), "\n") {
			if line == "" {
				continue
			}
			var ev event.Event
			if err := json.Unmarshal([]byte(line), &ev); err != nil {
				t.Fatalf("interleaved write produced invalid JSON: %v\n%q", err, line)
			}
			total++
		}
	}
	// Some generations will have been discarded; what must not happen is a
	// corrupt record, which the loop above would have caught.
	if total == 0 {
		t.Fatal("nothing survived")
	}
}
