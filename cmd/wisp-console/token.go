package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/willysnow/wisp/internal/console"
	"github.com/willysnow/wisp/internal/console/store"
	"github.com/willysnow/wisp/internal/token"
)

// runTokenCommand handles `wisp-console token <add|list|show|disable>`.
// It returns the process exit code.
//
// Tokens are minted here, from the CLI, for the same reason sensors and
// operators are: it keeps the web UI a read-only window onto captured events,
// with no form that mutates state and nothing to protect but the login.
func runTokenCommand(args []string) int {
	fs := flag.NewFlagSet("token", flag.ContinueOnError)
	dbPath := fs.String("db", "wisp-console.db", "path to the SQLite database")
	cfgPath := fs.String("config", "console.yaml", "console config, read for tokens.base_url and tokens.dns.zone")
	kind := fs.String("kind", "", "token kind: "+strings.Join(token.Kinds(), ", "))
	memo := fs.String("memo", "", "a note to yourself: where you are planting it")
	url := fs.String("url", "", "console base URL, e.g. https://console.example.com (overrides the config)")
	domain := fs.String("domain", "", "DNS token zone, e.g. tokens.example.com (overrides the config)")
	out := fs.String("o", "", "write the artifact to this file instead of standard output")

	operands, ok := parseInterspersed(fs, args)
	if !ok {
		return 2
	}
	if len(operands) == 0 {
		tokenUsage()
		return 2
	}
	action, operands := operands[0], operands[1:]

	// The artifact config comes from the console's own file so an operator does
	// not have to repeat the base URL on every mint, with the flags winning when
	// they want a one-off.
	artifactCfg := loadArtifactConfig(*cfgPath, *url, *domain)

	st, err := store.Open(*dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "database: %v\n", err)
		return 1
	}
	defer st.Close()

	ctx := context.Background()

	switch action {
	case "add":
		return tokenAdd(ctx, st, artifactCfg, *kind, *memo, *out)
	case "list":
		return tokenList(ctx, st)
	case "show":
		return tokenShow(ctx, st, artifactCfg, operands, *out)
	case "disable":
		return tokenDisable(ctx, st, operands)
	}

	fmt.Fprintf(os.Stderr, "unknown token command %q\n\n", action)
	tokenUsage()
	return 2
}

func tokenAdd(ctx context.Context, st *store.Store, cfg token.Config, kind, memo, out string) int {
	kind = strings.TrimSpace(kind)
	if kind == "" {
		fmt.Fprintf(os.Stderr, "a -kind is required (one of: %s)\n", strings.Join(token.Kinds(), ", "))
		return 2
	}
	if !token.ValidKind(kind) {
		fmt.Fprintf(os.Stderr, "unknown -kind %q (one of: %s)\n", kind, strings.Join(token.Kinds(), ", "))
		return 2
	}

	// Preflight the render before minting, so a missing base URL fails cleanly
	// rather than leaving a token that cannot be shown.
	if _, err := token.Render(cfg, kind, "preflight"); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", artifactHint(err))
		return 1
	}

	tok, err := st.CreateToken(ctx, kind, memo, "")
	if err != nil {
		fmt.Fprintf(os.Stderr, "create token: %v\n", err)
		return 1
	}

	art, err := token.Render(cfg, kind, tok.ID)
	if err != nil {
		// Should not happen after the preflight, but if it does the token still
		// exists and can be rendered later with `token show`.
		fmt.Fprintf(os.Stderr, "token %s created, but rendering it failed: %v\n", tok.ID, err)
		return 1
	}

	fmt.Printf("Minted %s token %s.\n", kind, tok.ID)
	if memo != "" {
		fmt.Printf("  memo: %s\n", memo)
	}
	fmt.Println()
	if code := emitArtifact(art, out); code != 0 {
		return code
	}
	fmt.Println()
	fmt.Println(plantingHint(kind, art, out))
	fmt.Println("A firing shows up in the console timeline and on the tokens page,")
	fmt.Println("and notifies like a captured credential. Disable it with:")
	fmt.Printf("  wisp-console token disable %s\n", tok.ID)
	return 0
}

func tokenShow(ctx context.Context, st *store.Store, cfg token.Config, operands []string, out string) int {
	if len(operands) < 1 {
		fmt.Fprintln(os.Stderr, "usage: wisp-console token show <id>")
		return 2
	}
	id := operands[0]

	tok, found, err := st.GetToken(ctx, id)
	if err != nil {
		fmt.Fprintf(os.Stderr, "look up %s: %v\n", id, err)
		return 1
	}
	if !found {
		fmt.Fprintf(os.Stderr, "no token %q\n", id)
		return 1
	}

	art, err := token.Render(cfg, tok.Kind, tok.ID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", artifactHint(err))
		return 1
	}

	fmt.Printf("%s token %s", tok.Kind, tok.ID)
	if tok.Disabled {
		fmt.Print(" (disabled)")
	}
	fmt.Println()
	if tok.Memo != "" {
		fmt.Printf("  memo: %s\n", tok.Memo)
	}
	fmt.Println()
	if code := emitArtifact(art, out); code != 0 {
		return code
	}
	fmt.Println()
	fmt.Println(plantingHint(tok.Kind, art, out))
	return 0
}

func tokenList(ctx context.Context, st *store.Store) int {
	tokens, err := st.ListTokens(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "list: %v\n", err)
		return 1
	}
	if len(tokens) == 0 {
		fmt.Println("No tokens minted.")
		fmt.Println("Mint one with: wisp-console token add -kind docx -memo \"finance share\"")
		return 0
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tKIND\tSTATUS\tTRIGGERED\tLAST\tMEMO")
	for _, t := range tokens {
		status := "active"
		if t.Disabled {
			status = "disabled"
		}
		last := "never"
		if t.Triggered() {
			last = t.LastTriggered.Local().Format("2006-01-02 15:04")
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%s\t%s\n",
			t.ID, t.Kind, status, t.TriggerCount, last, t.Memo)
	}
	if err := w.Flush(); err != nil {
		return 1
	}
	return 0
}

func tokenDisable(ctx context.Context, st *store.Store, operands []string) int {
	if len(operands) < 1 {
		fmt.Fprintln(os.Stderr, "usage: wisp-console token disable <id>")
		return 2
	}
	id := operands[0]

	disabled, err := st.DisableToken(ctx, id)
	if err != nil {
		fmt.Fprintf(os.Stderr, "disable %s: %v\n", id, err)
		return 1
	}
	if !disabled {
		fmt.Printf("No active token %q — already disabled, or never minted.\n", id)
		return 1
	}
	fmt.Printf("Disabled %s. Further callbacks are ignored; its past firings stay in the timeline.\n", id)
	return 0
}

// loadArtifactConfig reads the console config for the base URL and DNS zone,
// then lets the flags override them for a one-off mint.
func loadArtifactConfig(cfgPath, url, domain string) token.Config {
	cfg := token.Config{}
	if loaded, _, err := console.LoadConfig(cfgPath); err == nil {
		cfg = loaded.TokenArtifactConfig()
	}
	if url != "" {
		cfg.BaseURL = strings.TrimSpace(url)
	}
	if domain != "" {
		cfg.DNSZone = strings.TrimSpace(domain)
	}
	return cfg
}

// emitArtifact writes the artifact to a file or prints it. A binary artifact
// with no destination is written to its suggested filename rather than dumped
// as bytes onto a terminal.
func emitArtifact(art token.Artifact, out string) int {
	if out == "" && art.Binary {
		out = art.Filename
	}

	if out == "" {
		// A text artifact to the terminal, indented so it reads as a block.
		for _, line := range strings.Split(strings.TrimRight(art.String(), "\n"), "\n") {
			fmt.Printf("  %s\n", line)
		}
		return 0
	}

	if err := os.WriteFile(out, art.Content, 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "write %s: %v\n", out, err)
		return 1
	}
	fmt.Printf("  wrote %s (%d bytes)\n", out, len(art.Content))
	return 0
}

// artifactHint turns a render error into a message that also says how to fix it
// from the CLI, since the underlying error only knows about the console config.
func artifactHint(err error) string {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "base_url"):
		return msg + " — set it in console.yaml, or pass -url https://console.example.com"
	case strings.Contains(msg, "dns.zone"):
		return msg + " — set it in console.yaml, or pass -domain tokens.example.com"
	}
	return msg
}

// plantingHint says, per kind, where the artifact goes and what trips it.
func plantingHint(kind string, art token.Artifact, out string) string {
	where := out
	if where == "" && art.Binary {
		where = art.Filename
	}

	switch kind {
	case token.KindHTTP:
		return "Plant this URL where a curious intruder will fetch it — a bookmarked\n" +
			"admin link, a wiki page, an HTML <img>. It fires on the first request."
	case token.KindDNS:
		return "Plant this hostname where something will resolve it — a config value, an\n" +
			"allowlist, a host entry. It fires on the first lookup, and reaches the\n" +
			"console even from a network that blocks outbound HTTP."
	case token.KindDocx:
		return fmt.Sprintf("Saved to %s. Rename it to something tempting and drop it on a share.\n"+
			"It fires when opened in Word, which fetches its linked image.", where)
	case token.KindKubeconfig:
		return "Plant this kubeconfig where a stolen cluster credential would sit — a\n" +
			"~/.kube/config, a CI secret, a note. It fires the first time kubectl uses it."
	case token.KindMCP:
		return "Plant this in an MCP client config (e.g. claude_desktop_config.json or a\n" +
			"project .mcp.json). It fires when an agent loads it and connects."
	}
	return ""
}

func tokenUsage() {
	fmt.Fprintf(os.Stderr, `Mint and manage honeytokens — lures planted in data that call home when used.

Usage:
  wisp-console token add -kind <kind> -memo "<where>"   mint a token and print its artifact
  wisp-console token list                               show every token and its firings
  wisp-console token show <id>                          re-print a token's artifact
  wisp-console token disable <id>                        stop recording a token's callbacks

Kinds:
  %s

Flags:
  -db <path>       path to the SQLite database (default wisp-console.db)
  -config <path>   console config for tokens.base_url and tokens.dns.zone (default console.yaml)
  -kind <kind>     token kind (add)
  -memo <text>     a note to yourself: where you planted it
  -url <url>       console base URL, overriding the config
  -domain <zone>   DNS token zone, overriding the config
  -o <file>        write the artifact to a file instead of standard output
`, strings.Join(token.Kinds(), ", "))
}
