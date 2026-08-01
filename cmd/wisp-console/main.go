// Command wisp-console aggregates events from a fleet of wisp sensors.
//
// It is the piece a sensor cannot be: one place where every alert lands. Run it
// yourself — it needs nothing but a writable file for its database.
package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/willysnow/wisp/internal/build"
	"github.com/willysnow/wisp/internal/console"
	"github.com/willysnow/wisp/internal/console/notify"
	"github.com/willysnow/wisp/internal/console/store"
	"github.com/willysnow/wisp/internal/token"
)

func main() {
	// Subcommands are checked before flags so `wisp-console sensor add foo`
	// does not have to fight the server's flag set.
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "sensor":
			os.Exit(runSensorCommand(os.Args[2:]))
		case "user":
			os.Exit(runUserCommand(os.Args[2:]))
		case "token":
			os.Exit(runTokenCommand(os.Args[2:]))
		case "healthcheck":
			os.Exit(runHealthcheck(os.Args[2:]))
		}
	}

	var (
		addr     = flag.String("addr", ":8000", "listen address for the UI and ingest API")
		dbPath   = flag.String("db", "wisp-console.db", "path to the SQLite database")
		cfgPath  = flag.String("config", "console.yaml", "path to the console configuration file")
		token    = flag.String("token", "", "ingest token; generated and printed if empty")
		tokenEnv = flag.String("token-env", "WISP_CONSOLE_TOKEN", "environment variable to read the ingest token from")

		showVersion = flag.Bool("version", false, "print the version and exit")
	)
	flag.Parse()

	if *showVersion {
		fmt.Println("wisp-console", build.Info())
		return
	}

	logger := log.New(os.Stderr, "", log.LstdFlags)
	logger.Printf("wisp-console %s", build.Info())

	st, err := store.Open(*dbPath)
	if err != nil {
		logger.Fatalf("database: %v", err)
	}
	defer st.Close()

	// Per-sensor tokens are the supported path. The shared token exists only so
	// an existing deployment keeps working, and is not generated once any
	// sensor has been enrolled.
	enrolled, err := st.HasSensorTokens(context.Background())
	if err != nil {
		logger.Fatalf("database: %v", err)
	}

	ingestToken, generated, err := resolveToken(*token, *tokenEnv, enrolled)
	if err != nil {
		logger.Fatalf("token: %v", err)
	}

	cfg, cfgFound, err := console.LoadConfig(*cfgPath)
	if err != nil {
		logger.Fatalf("config: %v", err)
	}
	notifiers, err := cfg.Notifiers()
	if err != nil {
		logger.Fatalf("config: %v", err)
	}
	window, err := cfg.Window()
	if err != nil {
		logger.Fatalf("config: %v", err)
	}
	opts, err := cfg.ServerOptions()
	if err != nil {
		logger.Fatalf("config: %v", err)
	}
	retention, err := cfg.RetentionPolicy()
	if err != nil {
		logger.Fatalf("config: %v", err)
	}
	tlsSetup, err := cfg.TLSSetup()
	if err != nil {
		logger.Fatalf("config: %v", err)
	}
	silence, err := cfg.SilencePolicy()
	if err != nil {
		logger.Fatalf("config: %v", err)
	}
	tokenArtifact := cfg.TokenArtifactConfig()
	dnsCfg, err := cfg.TokenDNS()
	if err != nil {
		logger.Fatalf("config: %v", err)
	}

	// The UI is never open. If nobody has been enrolled, one account is created
	// here and its password printed once — the same bargain as the sensor
	// token, and the only way a first run can be both usable and closed.
	bootstrapUser, bootstrapPassword, err := ensureOperator(context.Background(), st)
	if err != nil {
		logger.Fatalf("operator account: %v", err)
	}

	dispatch := notify.NewDispatcher(notifiers, window, cfg.Notify.Kinds, logger)
	defer dispatch.Close()

	opts.IngestToken = ingestToken
	opts.Dispatch = dispatch
	opts.TokenConfig = tokenArtifact

	srv, err := console.New(st, opts)
	if err != nil {
		logger.Fatalf("console: %v", err)
	}

	httpSrv := &http.Server{
		Addr:              *addr,
		Handler:           srv.Handler(),
		TLSConfig:         tlsSetup.Config,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      60 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// The optional plain listener never serves the console itself: it redirects
	// to HTTPS, and in acme mode also answers the HTTP-01 challenge.
	var redirectSrv *http.Server
	if tlsSetup.Enabled() && tlsSetup.HTTPAddr != "" {
		redirectSrv = &http.Server{
			Addr:              tlsSetup.HTTPAddr,
			Handler:           tlsSetup.HTTPHandler,
			ReadHeaderTimeout: 10 * time.Second,
		}
		go func() {
			if err := redirectSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				logger.Printf("http redirect listener: %v", err)
			}
		}()
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if redirectSrv != nil {
			_ = redirectSrv.Shutdown(shutdownCtx)
		}
		_ = httpSrv.Shutdown(shutdownCtx)
	}()

	// Housekeeping runs even with no retention policy: expired sessions are
	// cleared either way.
	go console.NewJanitor(st, retention, logger).Run(ctx)

	// Watching for sensors that stop reporting. Nothing else in wisp alerts on
	// the absence of something.
	go console.NewSilenceWatcher(st, silence, dispatch, logger).Run(ctx)

	// The authoritative DNS server for DNS tokens, when one is configured. Its
	// failure is logged, not fatal: the HTTP tokens and the whole console keep
	// working without it, and a console that refused to start because port 53
	// was taken would be worse than one that says so and carries on.
	if dnsCfg.Active() {
		go func() {
			if err := console.NewDNSServer(dnsCfg, st, dispatch, logger).Run(ctx); err != nil && ctx.Err() == nil {
				logger.Printf("dns token server: %v — DNS tokens will not fire", err)
			}
		}()
	}

	scheme := "http"
	if tlsSetup.Enabled() {
		scheme = "https"
	}
	logger.Printf("console listening on %s %s (database %s)", scheme, *addr, *dbPath)

	if cfgFound {
		logger.Printf("loaded config from %s", *cfgPath)
	}
	if names := notifierNames(notifiers); names != "" {
		logger.Printf("notifying via %s (suppression window %s)", names, window)
	} else {
		// Worth saying plainly: a console nobody is alerted by is a dashboard,
		// and dashboards do not get checked at 3am.
		logger.Printf("no notifiers configured — alerts are visible in the UI only")
	}

	switch {
	case enrolled && ingestToken == "":
		logger.Printf("authenticating sensors by per-sensor token")
	case ingestToken != "":
		// A shared token means any holder can claim to be any sensor, because
		// the node name then comes from the payload rather than the credential.
		logger.Printf("WARNING: a shared ingest token is in use. Any holder can forge events")
		logger.Printf("         attributed to any sensor. Run `wisp-console sensor add <name>`")
		logger.Printf("         per sensor, then remove the shared token.")
	}

	if silence.Enabled() {
		logger.Printf("alerting when a sensor is quiet for %s", silence.After)
	} else {
		logger.Printf("NOTE: no sensor silence threshold set. A sensor that is found and")
		logger.Printf("      stopped looks exactly like a quiet network. Set sensors.silence_after in %s.", *cfgPath)
	}

	logTokens(logger, tokenArtifact, dnsCfg, *cfgPath)

	switch {
	case retention.MaxAge > 0 && retention.MaxEvents > 0:
		logger.Printf("retention: %s or %d events, whichever comes first",
			retention.MaxAge, retention.MaxEvents)
	case retention.MaxAge > 0:
		logger.Printf("retention: %s", retention.MaxAge)
	case retention.MaxEvents > 0:
		logger.Printf("retention: newest %d events", retention.MaxEvents)
	default:
		// Worth a warning rather than a note: the size of this database is
		// otherwise decided by whoever is scanning the sensors.
		logger.Printf("WARNING: no retention policy — events are kept forever and the")
		logger.Printf("         database grows without bound. Set retention.events in %s.", *cfgPath)
	}

	if generated {
		// Printed once, on the operator's terminal, because there is nowhere
		// else it can come from on a first run.
		logger.Printf("generated shared ingest token: %s", ingestToken)
	}
	logTLS(logger, tlsSetup, *cfgPath)

	// Last, and framed rather than logged: the operator password is generated on
	// this first start and printed nowhere else, so a line that looks like every
	// other timestamped note is a line that gets lost. Print it where the eye
	// lands, in a block it cannot be mistaken for.
	if bootstrapPassword != "" {
		printBootstrapCredential(os.Stderr, bootstrapUser, bootstrapPassword)
	}

	// The certificate and key come from the TLS config, so both arguments are
	// empty here. In acme mode there is no file at all — the manager answers
	// the handshake.
	serve := func() error { return httpSrv.ListenAndServeTLS("", "") }
	if !tlsSetup.Enabled() {
		serve = httpSrv.ListenAndServe
	}
	if err := serve(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Fatalf("serve: %v", err)
	}
	logger.Print("shutting down")
}

// printBootstrapCredential frames the one-time operator password so it survives
// the startup log. It writes raw, not through the timestamped logger, on
// purpose: this password is generated on the first start and printed nowhere
// else, and a bordered block with blank lines around it is what an operator
// actually catches among the notes and warnings.
func printBootstrapCredential(w io.Writer, username, password string) {
	rule := strings.Repeat("=", 72)
	fmt.Fprintf(w, "\n%s\n", rule)
	fmt.Fprintln(w, "  CONSOLE OPERATOR CREATED — this password is shown once. Save it now.")
	fmt.Fprintf(w, "\n      username:  %s\n", username)
	fmt.Fprintf(w, "      password:  %s\n\n", password)
	fmt.Fprintf(w, "  Change it later with:  wisp-console user passwd %s\n", username)
	fmt.Fprintf(w, "%s\n\n", rule)
}

// logTLS says what the transport is doing, in the terms that matter: what
// crosses the wire in the clear, and what a sensor has to trust.
func logTLS(logger *log.Logger, t *console.TLS, cfgPath string) {
	if t.HTTPAddr != "" {
		logger.Printf("redirecting plain HTTP on %s to HTTPS", t.HTTPAddr)
	}

	switch t.Mode {
	case console.TLSOff:
		logger.Printf("WARNING: TLS is off. Sensors send captured credentials, their bearer")
		logger.Printf("         tokens, and your login password in the clear. Put a reverse proxy")
		logger.Printf("         in front, or set tls.mode in %s.", cfgPath)

	case console.TLSSelfSigned:
		logger.Printf("TLS: self-signed certificate")
		logger.Printf("     SHA-256 %s", t.Fingerprint)
		// A self-signed console only protects anything if the sensors actually
		// check the certificate. Give the operator what they need to do that,
		// so nobody reaches for insecure_skip_verify.
		logger.Printf("     Copy the certificate to each sensor and set log.remote.ca_file,")
		logger.Printf("     or pin this fingerprint with log.remote.fingerprint.")

	case console.TLSFile:
		logger.Printf("TLS: certificate loaded from file")

	case console.TLSACME:
		logger.Printf("TLS: certificates issued automatically (ACME)")
	}
}

// logTokens reports what the token service can do at startup: where HTTP
// callbacks land, and whether the DNS half is answering. A console with no
// tokens.base_url can still receive a callback — the endpoint is always live —
// but it cannot show an operator the URL to plant, so that is worth saying.
func logTokens(logger *log.Logger, artifact token.Config, dnsCfg console.DNSConfig, cfgPath string) {
	switch {
	case artifact.BaseURL == "":
		logger.Printf("NOTE: no tokens.base_url set. The /t/ callback endpoint is live, but set")
		logger.Printf("      tokens.base_url in %s to mint HTTP, document, kubeconfig and MCP tokens.", cfgPath)
	default:
		if _, err := token.HTTPURL(artifact, "probe"); err != nil {
			logger.Printf("WARNING: tokens.base_url is unusable: %v", err)
		} else {
			logger.Printf("token callbacks land at %s/t/", strings.TrimRight(artifact.BaseURL, "/"))
		}
	}

	if dnsCfg.Active() {
		addr := dnsCfg.Addr
		if addr == "" {
			addr = ":53"
		}
		logger.Printf("answering DNS token callbacks for *.%s on %s", dnsCfg.Zone, addr)
	}
}

// bootstrapOperator is the account created on a first run. Named for what it
// is, so nobody wonders whether "wisp" is a service account.
const bootstrapOperator = "admin"

// ensureOperator creates the first operator account if none exists, returning
// the generated password so the caller can print it once.
//
// An empty password means an account already existed and nothing was created.
func ensureOperator(ctx context.Context, st *store.Store) (username, password string, err error) {
	n, err := st.CountUsers(ctx)
	if err != nil || n > 0 {
		return "", "", err
	}

	password, err = store.GeneratePassword()
	if err != nil {
		return "", "", err
	}
	if err := st.CreateUser(ctx, bootstrapOperator, password); err != nil {
		return "", "", err
	}
	return bootstrapOperator, password, nil
}

func notifierNames(notifiers []notify.Notifier) string {
	names := make([]string, 0, len(notifiers))
	for _, n := range notifiers {
		names = append(names, n.Name())
	}
	return strings.Join(names, ", ")
}

// resolveToken picks the legacy shared ingest token from the flag, then the
// environment. The flag is offered for convenience but the environment
// variable is the better place: a token on the command line is visible to every
// other process on the host.
//
// One is generated only when nothing is configured and no sensor has been
// enrolled — that is a first run, and the console needs some way to accept
// events. Once sensors are enrolled, no shared token exists at all.
func resolveToken(flagValue, envName string, enrolled bool) (token string, generated bool, err error) {
	if flagValue != "" {
		return flagValue, false, nil
	}
	if v := os.Getenv(envName); v != "" {
		return v, false, nil
	}
	if enrolled {
		return "", false, nil
	}

	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", false, err
	}
	return base64.RawURLEncoding.EncodeToString(buf), true, nil
}
