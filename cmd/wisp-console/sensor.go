package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/willysnow/wisp/internal/console/store"
)

// runSensorCommand handles `wisp-console sensor <add|list|revoke>`.
// It returns the process exit code.
func runSensorCommand(args []string) int {
	fs := flag.NewFlagSet("sensor", flag.ContinueOnError)
	dbPath := fs.String("db", "wisp-console.db", "path to the SQLite database")

	operands, ok := parseInterspersed(fs, args)
	if !ok {
		return 2
	}
	if len(operands) == 0 {
		sensorUsage()
		return 2
	}
	action, operands := operands[0], operands[1:]

	st, err := store.Open(*dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "database: %v\n", err)
		return 1
	}
	defer st.Close()

	ctx := context.Background()

	switch action {
	case "add":
		if len(operands) < 1 {
			fmt.Fprintln(os.Stderr, "usage: wisp-console sensor add <node-name>")
			return 2
		}
		node := operands[0]

		token, err := st.CreateSensorToken(ctx, node)
		if err != nil {
			fmt.Fprintf(os.Stderr, "enroll %s: %v\n", node, err)
			return 1
		}

		fmt.Printf("Enrolled %s.\n\n", node)
		fmt.Printf("  %s\n\n", token)
		fmt.Println("This token is shown once and is not recoverable — only its hash is stored.")
		fmt.Println("Put it in the sensor's wisp.yaml:")
		fmt.Println()
		fmt.Println("  log:")
		fmt.Println("    remote:")
		fmt.Println("      url: \"https://console.example.com\"")
		fmt.Printf("      token: \"%s\"\n", token)
		fmt.Println()
		fmt.Println("Running `sensor add` again for this node issues a new token and invalidates this one.")
		return 0

	case "list":
		tokens, err := st.ListSensorTokens(ctx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "list: %v\n", err)
			return 1
		}
		if len(tokens) == 0 {
			fmt.Println("No sensors enrolled.")
			fmt.Println("Enroll one with: wisp-console sensor add <node-name>")
			return 0
		}

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "NODE\tSTATUS\tENROLLED\tLAST USED")
		for _, t := range tokens {
			status := "active"
			if t.Revoked {
				status = "revoked"
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\n",
				t.Node, status,
				t.CreatedAt.Local().Format("2006-01-02 15:04"),
				formatLastUsed(t.LastUsed))
		}
		if err := w.Flush(); err != nil {
			return 1
		}
		return 0

	case "revoke":
		if len(operands) < 1 {
			fmt.Fprintln(os.Stderr, "usage: wisp-console sensor revoke <node-name>")
			return 2
		}
		node := operands[0]

		revoked, err := st.RevokeSensor(ctx, node)
		if err != nil {
			fmt.Fprintf(os.Stderr, "revoke %s: %v\n", node, err)
			return 1
		}
		if !revoked {
			fmt.Printf("No active token for %s — already revoked, or never enrolled.\n", node)
			return 1
		}
		fmt.Printf("Revoked %s. Its token is rejected from now on.\n", node)
		return 0
	}

	fmt.Fprintf(os.Stderr, "unknown sensor command %q\n\n", action)
	sensorUsage()
	return 2
}

// parseInterspersed parses a subcommand's arguments, allowing flags and
// operands in any order.
//
// flag stops parsing at the first operand, so `sensor add node -db x.db` would
// silently ignore -db and use the default database. Parsing in a loop — take
// one operand, parse again — uses the FlagSet's own knowledge of which flags
// consume a following value.
func parseInterspersed(fs *flag.FlagSet, args []string) (operands []string, ok bool) {
	rest := args
	for {
		if err := fs.Parse(rest); err != nil {
			return nil, false
		}
		rest = fs.Args()
		if len(rest) == 0 {
			return operands, true
		}
		operands = append(operands, rest[0])
		rest = rest[1:]
	}
}

func formatLastUsed(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	return t.Local().Format("2006-01-02 15:04")
}

func sensorUsage() {
	fmt.Fprintln(os.Stderr, `Manage sensor enrollment.

Usage:
  wisp-console sensor add <node-name>     enroll a sensor and print its token
  wisp-console sensor list                show every enrollment
  wisp-console sensor revoke <node-name>  reject a sensor's token from now on

Flags:
  -db <path>   path to the SQLite database (default wisp-console.db)`)
}
