package sink

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// RotateConfig bounds how much disk the event log may take.
//
// Without it, the size of events.jsonl is decided by whoever is scanning the
// sensor. The rate limiter already stops a flood from arriving faster than the
// disk can take it, but it does not stop a year of ordinary traffic from
// filling the partition — and a sensor whose disk is full stops recording the
// intrusion that filled it, which is the same failure the console's retention
// policy exists to prevent.
type RotateConfig struct {
	// MaxSize is the threshold in bytes. Zero disables rotation, for a
	// deployment that already points logrotate or journald at the file.
	MaxSize int64

	// MaxFiles is how many rotated generations to keep alongside the live one.
	// Zero keeps none: the file is truncated at the threshold and the old
	// contents are gone.
	MaxFiles int
}

// defaultMaxSize and defaultMaxFiles bound a fresh install at roughly half a
// gigabyte. Big enough that a quiet sensor never rotates, small enough that a
// noisy one cannot fill a small disk before anybody looks.
const (
	defaultMaxSize  = 100 << 20
	defaultMaxFiles = 5
)

// RotatingFile is an append-only file that rotates once it passes a size.
//
// Rotation is by rename, oldest first: events.jsonl.4 is removed, .3 becomes
// .4, and so on down to the live file becoming .1. Numbered generations rather
// than timestamps because the sensor has to be able to find and delete the
// oldest without parsing anything, and because `events.jsonl.1` is unambiguous
// to a human reading a directory listing at three in the morning.
type RotatingFile struct {
	path     string
	maxSize  int64
	maxFiles int

	mu   sync.Mutex
	f    *os.File
	size int64
}

// OpenRotating opens path for appending, rotating it when it outgrows the
// configured size. A zero MaxSize means the caller wants no rotation, and the
// result is an ordinary append-only file.
func OpenRotating(path string, cfg RotateConfig) (*RotatingFile, error) {
	f, err := openAppend(path)
	if err != nil {
		return nil, err
	}

	// Pick up where a previous run left off. Without this a sensor that
	// restarts often would never reach the threshold, because every start would
	// begin counting from zero against a file that is already large.
	var size int64
	if info, err := f.Stat(); err == nil {
		size = info.Size()
	}

	return &RotatingFile{
		path:     path,
		maxSize:  cfg.MaxSize,
		maxFiles: cfg.MaxFiles,
		f:        f,
		size:     size,
	}, nil
}

// Write appends p, rotating first if it would not fit.
//
// The check is before the write, not after, and that ordering is the whole
// reason this is safe for JSONL: the JSONL sink hands over one complete line
// per call, so rotating first means a line always lands in exactly one file.
// Rotating afterwards would put the tail of a record in one file and nothing in
// the next, and a half-written JSON object is a parse error in whatever the
// operator pointed at the log.
func (r *RotatingFile) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.maxSize > 0 && r.size > 0 && r.size+int64(len(p)) > r.maxSize {
		if err := r.rotate(); err != nil {
			// Rotation failed — the disk is full, or something holds the file
			// open. Keep writing to the file we have: an oversized log beats a
			// sensor that stops recording.
			_ = err
		}
	}

	n, err := r.f.Write(p)
	r.size += int64(n)
	return n, err
}

// Close closes the underlying file.
func (r *RotatingFile) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.f == nil {
		return nil
	}
	err := r.f.Close()
	r.f = nil
	return err
}

// Name returns the live file's path.
func (r *RotatingFile) Name() string { return r.path }

// rotate closes the live file, shifts the generations up, and opens a new one.
//
// The file is closed before it is renamed because Windows will not rename a
// file that is still open, and a sensor that rotated correctly on Linux and
// silently stopped rotating on Windows would be worse than one that never
// rotated at all.
func (r *RotatingFile) rotate() error {
	if err := r.f.Close(); err != nil {
		return err
	}
	r.f = nil

	if r.maxFiles <= 0 {
		// Nobody wants the history. Removing the file is the whole rotation.
		_ = os.Remove(r.path)
	} else {
		// Oldest first, so each rename lands on a name that has just been freed.
		_ = os.Remove(generation(r.path, r.maxFiles))
		for i := r.maxFiles - 1; i >= 1; i-- {
			_ = os.Rename(generation(r.path, i), generation(r.path, i+1))
		}
		if err := os.Rename(r.path, generation(r.path, 1)); err != nil && !os.IsNotExist(err) {
			// The live file could not be moved aside. Reopen it and carry on
			// appending rather than losing the sink entirely.
			f, openErr := openAppend(r.path)
			if openErr != nil {
				return openErr
			}
			r.f = f
			return err
		}
	}

	f, err := openAppend(r.path)
	if err != nil {
		return err
	}
	r.f = f
	r.size = 0
	return nil
}

func generation(path string, n int) string {
	return fmt.Sprintf("%s.%d", path, n)
}

// openAppend opens the log for appending, creating the directory if the
// operator pointed the config at one that does not exist yet. 0600 because the
// file holds captured credentials.
func openAppend(path string) (*os.File, error) {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		_ = os.MkdirAll(dir, 0o700)
	}
	return os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
}
