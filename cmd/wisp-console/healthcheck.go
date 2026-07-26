package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

// runHealthcheck handles `wisp-console healthcheck`. It returns the process
// exit code: 0 if the console answered, 1 if it did not.
//
// It exists because the container image has no shell and no curl — that is the
// point of a distroless image — so the binary has to be able to probe itself.
func runHealthcheck(args []string) int {
	fs := flag.NewFlagSet("healthcheck", flag.ContinueOnError)
	url := fs.String("url", "http://127.0.0.1:8000/healthz", "health endpoint to probe")
	timeout := fs.Duration("timeout", 5*time.Second, "how long to wait for an answer")
	insecure := fs.Bool("insecure", false,
		"skip certificate verification — for probing a console's own self-signed certificate over loopback")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	client := &http.Client{
		Timeout: *timeout,
		// Do not follow redirects. Every UI path answers a signed-out request
		// with a redirect to the login page, so a followed redirect would
		// report a mistyped URL as healthy — and a health check that passes
		// when pointed at the wrong endpoint is worse than none.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	if *insecure {
		// Loopback only, and the container is probing the process inside it.
		// There is no network here for anyone to be in the middle of.
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // see above
		client.Transport = transport
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, *url, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "healthcheck: %v\n", err)
		return 1
	}

	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "healthcheck: %v\n", err)
		return 1
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "healthcheck: %s returned %s\n", *url, resp.Status)
		return 1
	}
	return 0
}
