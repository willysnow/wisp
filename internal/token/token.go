// Package token renders the artifacts a honeytoken is planted as.
//
// A honeytoken is the mirror image of a decoy. A decoy waits on the network for
// an intruder who is already inside to touch it; a token is planted inside data
// — a document, a kubeconfig, an MCP server entry — and travels with that data,
// firing from wherever it ends up the moment someone opens or uses it. The two
// cover different halves of the same problem, and the console is where both land.
//
// Everything here is pure: given a token id and where the console can be
// reached, it produces the bytes to plant. Minting the token and receiving its
// callback belong to the console; this package only knows how to write the lure.
package token

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

// Kinds of token, by the artifact each is planted as. The string is what the
// store records and the CLI accepts, so it is stable.
const (
	// KindHTTP is a bare URL that fires when fetched — the primitive the
	// document, kubeconfig and MCP kinds all build on.
	KindHTTP = "http"
	// KindDNS is a hostname that fires when resolved. It reaches the console
	// even from a network that blocks outbound HTTP, because a recursive
	// resolver walks the query out for it — which is exactly the path data
	// exfiltration takes, so the same egress that would leak data trips this.
	KindDNS = "dns"
	// KindDocx is a Word document that fetches the URL when opened, via a linked
	// image that Word resolves on load.
	KindDocx = "docx"
	// KindKubeconfig is a kubeconfig whose apiserver is the callback URL: it
	// fires the first time someone points kubectl at it.
	KindKubeconfig = "kubeconfig"
	// KindMCP is an MCP client configuration whose server is the callback URL:
	// it fires when an agent loads the config and connects.
	KindMCP = "mcp"
)

// Kinds returns every supported kind, in the order the CLI lists them.
func Kinds() []string {
	return []string{KindHTTP, KindDNS, KindDocx, KindKubeconfig, KindMCP}
}

// ValidKind reports whether kind is one this package can render.
func ValidKind(kind string) bool {
	switch kind {
	case KindHTTP, KindDNS, KindDocx, KindKubeconfig, KindMCP:
		return true
	}
	return false
}

// Config is what the console publishes about where it can be reached, so a
// planted artifact knows where to call home.
type Config struct {
	// BaseURL is the console's public origin, e.g. https://console.example.com.
	// Every kind but the bare DNS token needs it, because the callback rides an
	// HTTP request.
	BaseURL string
	// DNSZone is the domain delegated to the console's DNS server, e.g.
	// tokens.example.com. Only the DNS kind needs it.
	DNSZone string
}

// Artifact is a rendered token, ready to plant.
type Artifact struct {
	// Filename is a suggested name on disk, for the kinds written to a file.
	Filename string
	// ContentType is the MIME type of Content.
	ContentType string
	// Content is the bytes to plant.
	Content []byte
	// Binary reports whether Content is binary (a document) rather than text a
	// terminal can print (a URL, a YAML/JSON config).
	Binary bool
}

// String returns the text content, for the kinds that have any.
func (a Artifact) String() string { return string(a.Content) }

// Render produces the artifact for a token of the given kind.
func Render(cfg Config, kind, id string) (Artifact, error) {
	if id == "" {
		return Artifact{}, fmt.Errorf("token id is required")
	}

	switch kind {
	case KindHTTP:
		u, err := HTTPURL(cfg, id)
		if err != nil {
			return Artifact{}, err
		}
		return Artifact{ContentType: "text/plain", Content: []byte(u)}, nil

	case KindDNS:
		name, err := DNSName(cfg, id)
		if err != nil {
			return Artifact{}, err
		}
		return Artifact{ContentType: "text/plain", Content: []byte(name)}, nil

	case KindKubeconfig:
		y, err := Kubeconfig(cfg, id)
		if err != nil {
			return Artifact{}, err
		}
		return Artifact{
			Filename:    "kubeconfig",
			ContentType: "application/yaml",
			Content:     []byte(y),
		}, nil

	case KindMCP:
		j, err := MCPConfig(cfg, id)
		if err != nil {
			return Artifact{}, err
		}
		return Artifact{
			Filename:    "mcp.json",
			ContentType: "application/json",
			Content:     []byte(j),
		}, nil

	case KindDocx:
		b, err := Docx(cfg, id)
		if err != nil {
			return Artifact{}, err
		}
		return Artifact{
			Filename:    "document.docx",
			ContentType: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
			Content:     b,
			Binary:      true,
		}, nil
	}

	return Artifact{}, fmt.Errorf("unknown token kind %q", kind)
}

// HTTPURL is the callback URL a token id fires. The console answers any path
// under /t/<id>, so a client that appends its own suffix — kubectl asking for
// /api, an MCP client for /sse — still lands on the same token.
func HTTPURL(cfg Config, id string) (string, error) {
	base, err := normalizeBaseURL(cfg.BaseURL)
	if err != nil {
		return "", err
	}
	return base + "/t/" + id, nil
}

// DNSName is the hostname a DNS token fires. Resolving it — from anywhere, over
// any recursive resolver — carries the id to the console's authoritative server.
func DNSName(cfg Config, id string) (string, error) {
	zone := strings.Trim(strings.TrimSpace(cfg.DNSZone), ".")
	if zone == "" {
		return "", fmt.Errorf("a DNS token needs tokens.dns.zone set on the console")
	}
	return id + "." + zone, nil
}

// Kubeconfig renders a kubeconfig whose apiserver is the token URL.
//
// insecure-skip-tls-verify is deliberately on: the console answers with its own
// certificate, and a kubeconfig that refused to connect over it would never
// fire. The point is not to complete a Kubernetes session — it never does — but
// to record that a stolen cluster credential was used, which the first request
// already proves.
func Kubeconfig(cfg Config, id string) (string, error) {
	u, err := HTTPURL(cfg, id)
	if err != nil {
		return "", err
	}
	// Written by hand rather than through a YAML marshaller so it reads exactly
	// like a kubeconfig a person would recognise on sight — the lure only works
	// if it looks like the real thing.
	var b strings.Builder
	fmt.Fprintf(&b, `apiVersion: v1
kind: Config
current-context: prod
clusters:
- name: prod
  cluster:
    server: %s
    insecure-skip-tls-verify: true
contexts:
- name: prod
  context:
    cluster: prod
    user: prod-admin
    namespace: default
users:
- name: prod-admin
  user:
    token: %s
`, u, id)
	return b.String(), nil
}

// MCPConfig renders an MCP client configuration whose server is the token URL.
//
// The transport is the streamable HTTP/SSE one, so the token fires on the plain
// act of an agent connecting to the "server" — no tool has to be called. The
// name is chosen to be the kind of thing an agent operator would wire up
// without a second look.
func MCPConfig(cfg Config, id string) (string, error) {
	u, err := HTTPURL(cfg, id)
	if err != nil {
		return "", err
	}

	type server struct {
		URL string `json:"url"`
	}
	doc := map[string]any{
		"mcpServers": map[string]server{
			"internal-tools": {URL: u + "/sse"},
		},
	}
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return "", err
	}
	return string(out) + "\n", nil
}

// normalizeBaseURL validates the console origin and trims a trailing slash, so
// URL building never produces a double slash or an unusable link.
func normalizeBaseURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("this token needs tokens.base_url set on the console")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("tokens.base_url is not a URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("tokens.base_url must be http:// or https://, got %q", raw)
	}
	if u.Host == "" {
		return "", fmt.Errorf("tokens.base_url has no host: %q", raw)
	}
	u.Path = strings.TrimRight(u.Path, "/")
	u.RawQuery = ""
	u.Fragment = ""
	return u.String(), nil
}
