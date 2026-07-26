package build

import (
	"runtime"
	"strings"
	"testing"
)

// TestInfoNamesTheBuild: this string is what an operator reads off a sensor
// they have not touched in six months, so it has to carry the version, the
// platform, and the toolchain.
func TestInfoNamesTheBuild(t *testing.T) {
	got := Info()

	for _, want := range []string{Version, runtime.GOOS, runtime.GOARCH, runtime.Version()} {
		if !strings.Contains(got, want) {
			t.Errorf("Info() = %q, missing %q", got, want)
		}
	}
}

// TestVersionDefaultsToDev — an unstamped build must not claim to be a
// release.
func TestVersionDefaultsToDev(t *testing.T) {
	if Version != "dev" {
		t.Skip("built with a stamped version; nothing to check here")
	}
	if strings.HasPrefix(Info(), "v") {
		t.Errorf("Info() = %q, which reads like a release", Info())
	}
}
