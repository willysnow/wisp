// Package build carries the version stamped into the binaries at release time.
//
// It exists so that "which build is on that sensor?" has an answer. A honeypot
// is deployed once and then ignored for months by design; when one finally
// reports something strange, the first question is what is actually running on
// it.
package build

import (
	"fmt"
	"runtime"
	"runtime/debug"
	"strings"
)

// Version is set at link time:
//
//	-ldflags "-X github.com/willysnow/wisp/internal/build.Version=v1.2.3"
//
// A build from a working tree says "dev", which is the truth. Nothing pretends
// to be a release it is not.
var Version = "dev"

// Info returns a one-line description of this binary.
func Info() string {
	var b strings.Builder
	b.WriteString(Version)

	if rev := revision(); rev != "" {
		b.WriteString(" (")
		b.WriteString(rev)
		b.WriteString(")")
	}

	fmt.Fprintf(&b, " %s/%s %s", runtime.GOOS, runtime.GOARCH, runtime.Version())
	return b.String()
}

// revision reports the commit this was built from, which the Go toolchain
// records for any build made inside a repository. It is what identifies an
// unreleased build — "dev" alone says nothing.
func revision() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return ""
	}

	var rev, suffix string
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			rev = s.Value
		case "vcs.modified":
			if s.Value == "true" {
				// Built with uncommitted changes. Worth saying: the commit
				// alone would name a tree that does not match the binary.
				suffix = "-dirty"
			}
		}
	}

	if rev == "" {
		return ""
	}
	if len(rev) > 12 {
		rev = rev[:12]
	}
	return rev + suffix
}
