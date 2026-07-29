package console

import (
	"net"
	"testing"
)

func TestTokenDNSValidation(t *testing.T) {
	// Enabled without a zone is a misconfiguration, not a silent no-op: an
	// operator who turned it on expects it to run.
	if _, err := (&Config{Tokens: TokensConfig{DNS: TokenDNSConfig{Enabled: true}}}).TokenDNS(); err == nil {
		t.Error("enabled DNS with no zone was accepted")
	}

	// A non-IP or IPv6 answer would produce silent empty replies, since only A
	// records are served.
	for _, bad := range []string{"not-an-ip", "2001:db8::1"} {
		cfg := &Config{Tokens: TokensConfig{DNS: TokenDNSConfig{
			Enabled: true, Zone: "tokens.example.com", Answer: bad,
		}}}
		if _, err := cfg.TokenDNS(); err == nil {
			t.Errorf("answer %q was accepted, want a rejection", bad)
		}
	}

	// A good configuration parses, normalises the zone, and is active.
	cfg := &Config{Tokens: TokensConfig{DNS: TokenDNSConfig{
		Enabled: true, Zone: "tokens.example.com.", Answer: "10.0.0.1",
	}}}
	d, err := cfg.TokenDNS()
	if err != nil {
		t.Fatalf("TokenDNS: %v", err)
	}
	if !d.Active() {
		t.Error("a well-formed enabled config is not Active")
	}
	if d.Zone != "tokens.example.com" {
		t.Errorf("zone = %q, want the trailing dot trimmed", d.Zone)
	}
	if !d.Answer.Equal(net.IPv4(10, 0, 0, 1)) {
		t.Errorf("answer = %v, want 10.0.0.1", d.Answer)
	}
}

// TestTokenDNSDisabledSkipsValidation lets an operator leave a half-filled DNS
// block in the file without it stopping the console from starting — the feature
// is simply off.
func TestTokenDNSDisabledSkipsValidation(t *testing.T) {
	cfg := &Config{Tokens: TokensConfig{DNS: TokenDNSConfig{Enabled: false, Zone: ""}}}
	d, err := cfg.TokenDNS()
	if err != nil {
		t.Fatalf("disabled DNS config errored: %v", err)
	}
	if d.Active() {
		t.Error("a disabled DNS config reports Active")
	}
}

func TestTokenArtifactConfigPassesThrough(t *testing.T) {
	cfg := &Config{Tokens: TokensConfig{
		BaseURL: "  https://console.example.com  ",
		DNS:     TokenDNSConfig{Zone: " tokens.example.com "},
	}}
	got := cfg.TokenArtifactConfig()
	if got.BaseURL != "https://console.example.com" {
		t.Errorf("BaseURL = %q, want it trimmed", got.BaseURL)
	}
	if got.DNSZone != "tokens.example.com" {
		t.Errorf("DNSZone = %q, want it trimmed", got.DNSZone)
	}
}
