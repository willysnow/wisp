package main

import (
	"strings"
	"testing"
)

// TestBootstrapCredentialCarriesTheSecret. The whole reason this password is
// framed rather than logged is that it is printed exactly once and nowhere else.
// If a refactor ever drops the username, the password, or the recovery command
// from the block, the first anyone learns of it is a locked-out console — so
// assert all three are present.
func TestBootstrapCredentialCarriesTheSecret(t *testing.T) {
	var buf strings.Builder
	printBootstrapCredential(&buf, "admin", "pSymBGpoDhZdiRZUMVyEeUjt")
	out := buf.String()

	for _, want := range []string{
		"admin",                    // the account name
		"pSymBGpoDhZdiRZUMVyEeUjt", // the one-time password itself
		"user passwd admin",        // how to recover if it is lost
	} {
		if !strings.Contains(out, want) {
			t.Errorf("bootstrap credential block is missing %q\n---\n%s", want, out)
		}
	}

	// It must stand apart from the timestamped log lines around it: a leading
	// blank line and a rule are what make it catch the eye.
	if !strings.HasPrefix(out, "\n") {
		t.Error("block does not start with a blank line, so it runs into the log above it")
	}
	if !strings.Contains(out, "====") {
		t.Error("block has no rule, so nothing separates it from the startup notes")
	}
}
