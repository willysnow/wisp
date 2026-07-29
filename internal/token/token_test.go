package token

import (
	"encoding/json"
	"strings"
	"testing"
)

const testBase = "https://console.example.com"

func TestHTTPURL(t *testing.T) {
	cfg := Config{BaseURL: testBase}
	got, err := HTTPURL(cfg, "abc123")
	if err != nil {
		t.Fatalf("HTTPURL: %v", err)
	}
	if want := testBase + "/t/abc123"; got != want {
		t.Errorf("HTTPURL = %q, want %q", got, want)
	}
}

// TestHTTPURLTrimsTrailingSlash keeps the callback path from ever containing a
// double slash, which some clients normalise away and others do not — a token
// that fires under one and not the other is a token that fails silently.
func TestHTTPURLTrimsTrailingSlash(t *testing.T) {
	got, err := HTTPURL(Config{BaseURL: testBase + "/"}, "id")
	if err != nil {
		t.Fatalf("HTTPURL: %v", err)
	}
	if want := testBase + "/t/id"; got != want {
		t.Errorf("HTTPURL = %q, want %q", got, want)
	}
}

func TestHTTPURLRejectsBadBase(t *testing.T) {
	for _, base := range []string{"", "console.example.com", "ftp://x", "https://"} {
		if _, err := HTTPURL(Config{BaseURL: base}, "id"); err == nil {
			t.Errorf("HTTPURL(%q) = nil error, want a rejection", base)
		}
	}
}

func TestDNSName(t *testing.T) {
	got, err := DNSName(Config{DNSZone: "tokens.example.com"}, "abc123")
	if err != nil {
		t.Fatalf("DNSName: %v", err)
	}
	if want := "abc123.tokens.example.com"; got != want {
		t.Errorf("DNSName = %q, want %q", got, want)
	}

	// A missing zone is an error, not a hostname with a dangling dot.
	if _, err := DNSName(Config{}, "id"); err == nil {
		t.Error("DNSName with no zone = nil error, want a rejection")
	}
}

// TestKubeconfigConnects checks the two properties that make a kubeconfig token
// fire: the apiserver is the callback URL, and verification is skipped so the
// console's own certificate does not stop the connection before it is recorded.
func TestKubeconfigConnects(t *testing.T) {
	y, err := Kubeconfig(Config{BaseURL: testBase}, "abc123")
	if err != nil {
		t.Fatalf("Kubeconfig: %v", err)
	}
	if !strings.Contains(y, "server: "+testBase+"/t/abc123") {
		t.Errorf("kubeconfig server is not the callback URL:\n%s", y)
	}
	if !strings.Contains(y, "insecure-skip-tls-verify: true") {
		t.Errorf("kubeconfig would refuse a self-signed console, so it would never fire:\n%s", y)
	}
}

// TestMCPConfigIsValidJSON checks the MCP artifact parses and points its server
// at the callback — an agent that cannot load the config never connects, and a
// server pointed elsewhere never fires.
func TestMCPConfigIsValidJSON(t *testing.T) {
	j, err := MCPConfig(Config{BaseURL: testBase}, "abc123")
	if err != nil {
		t.Fatalf("MCPConfig: %v", err)
	}

	var doc struct {
		MCPServers map[string]struct {
			URL string `json:"url"`
		} `json:"mcpServers"`
	}
	if err := json.Unmarshal([]byte(j), &doc); err != nil {
		t.Fatalf("MCP config is not valid JSON: %v\n%s", err, j)
	}
	srv, ok := doc.MCPServers["internal-tools"]
	if !ok {
		t.Fatalf("MCP config has no server entry:\n%s", j)
	}
	if !strings.HasPrefix(srv.URL, testBase+"/t/abc123") {
		t.Errorf("MCP server URL = %q, want it under the callback URL", srv.URL)
	}
}

// TestRenderCoversEveryKind is a guard: every advertised kind must render, or
// the CLI offers a kind it cannot produce.
func TestRenderCoversEveryKind(t *testing.T) {
	cfg := Config{BaseURL: testBase, DNSZone: "tokens.example.com"}
	for _, kind := range Kinds() {
		art, err := Render(cfg, kind, "abc123")
		if err != nil {
			t.Errorf("Render(%q) = %v", kind, err)
			continue
		}
		if len(art.Content) == 0 {
			t.Errorf("Render(%q) produced no content", kind)
		}
	}

	if _, err := Render(cfg, "nonsense", "id"); err == nil {
		t.Error("Render(unknown kind) = nil error, want a rejection")
	}
}

func TestValidKind(t *testing.T) {
	for _, kind := range Kinds() {
		if !ValidKind(kind) {
			t.Errorf("ValidKind(%q) = false, want true", kind)
		}
	}
	if ValidKind("nope") {
		t.Error("ValidKind(nope) = true, want false")
	}
}
