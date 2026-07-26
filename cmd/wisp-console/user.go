package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/willysnow/wisp/internal/console/store"
)

// runUserCommand handles `wisp-console user <add|list|passwd|remove>`.
// It returns the process exit code.
func runUserCommand(args []string) int {
	fs := flag.NewFlagSet("user", flag.ContinueOnError)
	dbPath := fs.String("db", "wisp-console.db", "path to the SQLite database")
	fromStdin := fs.Bool("password-stdin", false, "read the password from standard input instead of generating one")

	operands, ok := parseInterspersed(fs, args)
	if !ok {
		return 2
	}
	if len(operands) == 0 {
		userUsage()
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
			fmt.Fprintln(os.Stderr, "usage: wisp-console user add <username>")
			return 2
		}
		username := operands[0]

		password, generated, err := choosePassword(*fromStdin)
		if err != nil {
			fmt.Fprintf(os.Stderr, "password: %v\n", err)
			return 1
		}
		if err := st.CreateUser(ctx, username, password); err != nil {
			fmt.Fprintf(os.Stderr, "add %s: %v\n", username, err)
			return 1
		}

		fmt.Printf("Created operator %s.\n", username)
		printPassword(password, generated)
		return 0

	case "passwd":
		if len(operands) < 1 {
			fmt.Fprintln(os.Stderr, "usage: wisp-console user passwd <username>")
			return 2
		}
		username := operands[0]

		password, generated, err := choosePassword(*fromStdin)
		if err != nil {
			fmt.Fprintf(os.Stderr, "password: %v\n", err)
			return 1
		}
		if err := st.SetPassword(ctx, username, password); err != nil {
			fmt.Fprintf(os.Stderr, "passwd %s: %v\n", username, err)
			return 1
		}

		fmt.Printf("Password changed for %s. Existing sessions are signed out.\n", username)
		printPassword(password, generated)
		return 0

	case "list":
		users, err := st.ListUsers(ctx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "list: %v\n", err)
			return 1
		}
		if len(users) == 0 {
			fmt.Println("No operators. The console creates one on first start.")
			fmt.Println("Or add one now with: wisp-console user add <username>")
			return 0
		}

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "USERNAME\tCREATED\tLAST LOGIN")
		for _, u := range users {
			fmt.Fprintf(w, "%s\t%s\t%s\n",
				u.Username,
				u.CreatedAt.Local().Format("2006-01-02 15:04"),
				formatLastUsed(u.LastLogin))
		}
		if err := w.Flush(); err != nil {
			return 1
		}
		return 0

	case "remove":
		if len(operands) < 1 {
			fmt.Fprintln(os.Stderr, "usage: wisp-console user remove <username>")
			return 2
		}
		username := operands[0]

		// Removing the last operator would lock everyone out — and the console
		// would bootstrap a fresh account on its next start, which is a
		// confusing way to find out.
		users, err := st.ListUsers(ctx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "remove %s: %v\n", username, err)
			return 1
		}
		if len(users) == 1 && users[0].Username == username {
			fmt.Fprintf(os.Stderr, "%s is the only operator; add another before removing this one.\n", username)
			return 1
		}

		removed, err := st.DeleteUser(ctx, username)
		if err != nil {
			fmt.Fprintf(os.Stderr, "remove %s: %v\n", username, err)
			return 1
		}
		if !removed {
			fmt.Printf("No operator named %s.\n", username)
			return 1
		}
		fmt.Printf("Removed %s. Their sessions are signed out.\n", username)
		return 0
	}

	fmt.Fprintf(os.Stderr, "unknown user command %q\n\n", action)
	userUsage()
	return 2
}

// choosePassword either reads one from stdin or generates one.
//
// There is no interactive prompt on purpose: reading a password without echo
// needs terminal handling that differs per platform, and a generated 144-bit
// password is better than whatever gets typed at a prompt anyway.
func choosePassword(fromStdin bool) (password string, generated bool, err error) {
	if !fromStdin {
		p, err := store.GeneratePassword()
		return p, true, err
	}

	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && err != io.EOF {
		return "", false, err
	}
	password = strings.TrimRight(line, "\r\n")
	if password == "" {
		return "", false, fmt.Errorf("no password on standard input")
	}
	return password, false, store.ValidatePassword(password)
}

func printPassword(password string, generated bool) {
	if !generated {
		return
	}
	fmt.Printf("\n  %s\n\n", password)
	fmt.Println("This password is shown once and is not recoverable — only its hash is stored.")
	fmt.Println("Set your own instead with: wisp-console user passwd <username> -password-stdin")
}

func userUsage() {
	fmt.Fprintln(os.Stderr, `Manage console operators.

Usage:
  wisp-console user add <username>     create an operator and print a password
  wisp-console user list               show every operator
  wisp-console user passwd <username>  change a password and sign out its sessions
  wisp-console user remove <username>  delete an operator

Flags:
  -db <path>         path to the SQLite database (default wisp-console.db)
  -password-stdin    read the password from standard input instead of generating one`)
}
