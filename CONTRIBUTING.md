# Contributing

Protocol coverage is complete — wisp reimplements all 21 of OpenCanary's modules
and adds nine decoys and a honeytoken service of its own. The most useful
contributions now are the ones that make it battle-tested: real-world hardening,
a new decoy for the 2026 attack surface, or better fidelity in an existing
capture.

Security problems go to [SECURITY.md](SECURITY.md), never to a public issue.

## The constraints everything else follows from

These are not style preferences. They are the reasons this project exists, and
a change that breaks one will be turned down however good it otherwise is.

**One static binary, no cgo.** The pitch is that deploying a honeypot should
not require Python, Twisted, Scapy, and a working Samba install. SQLite is
`modernc.org/sqlite` (pure Go) rather than the cgo driver for exactly this
reason. `CGO_ENABLED=0` must stay viable, and so must cross-compilation to
every target in CI — including 32-bit ARM, which is what most people have lying
around to leave a sensor on.

**Dependencies are a cost.** The whole tree is `gopkg.in/yaml.v3`,
`golang.org/x/crypto`, and `modernc.org/sqlite` (plus what `acme/autocert`
pulls in). Adding one needs a reason that the standard library cannot cover.

**A sensor must never become a weapon.** No decoy grants access, executes
anything, writes a file, or makes an outbound connection an operator did not
configure. The NTP module refuses to answer mode 7 `monlist` because replying
would make it a working DDoS amplifier pointed at a spoofed address — that
property has a test, and so should yours.

**A sensor must not stop answering the network.** Emitting an event never
blocks a service goroutine, delivery is best-effort, and a full queue drops
events rather than applying back-pressure. A hung service is a detectable tell;
lost telemetry is merely bad.

## Adding a protocol module

One package under `internal/service/`, one line in `buildServices`. The
checklist:

1. **`internal/service/<name>svc/<name>.go`** implementing `service.Service`
   plus either `StreamService` (TCP) or `PacketService` (UDP).
2. **Config**: a struct in `internal/config/config.go`, a field on `Services`,
   and defaults in `Default()` — on an unprivileged port, so wisp starts
   without elevation.
3. **Wiring**: one line in `buildServices` in `cmd/wispd/main.go`.
4. **`wisp.example.yaml`**: the new section, with comments explaining the
   choices an operator has to make.
5. **README**: a row in the "What it emulates today" table saying what it
   *captures*.
6. **Tests** for whatever the module must never do.

Three things decide whether a module is any good:

- **What it captures.** "Someone connected to port 3306" is a connection log.
  "This username and this password hash were offered" is an alert. Aim for the
  second; if the protocol makes it genuinely hard, say so in the README rather
  than shipping a banner catcher counted as coverage.
- **Whether it keeps them talking.** Answering plausibly is usually worth more
  than refusing, because the next message is more intelligence. redis returns
  `+OK` so a takeover script runs its whole playbook where you can watch it;
  the Kubernetes decoy answers `403` rather than `401`, because `401` reads as
  "wrong door" and ends the conversation.
- **Whether it gives itself away.** Match a real implementation's banner,
  error text, and timing. Persist anything an attacker could compare across two
  visits — host keys and certificates are generated once and kept, because one
  that changes every restart is a fingerprint.

## Events

Emit `event.Event` and let the console decide what matters — services never
filter. Pick a `Kind` that names what happened (`login_password`, `prompt`,
`write_request`), and reuse an existing one if it fits: the UI colours known
kinds, and the console notifies on `event.HighValueKinds`.

If your kind carries a credential or the attacker's stated intent, add it to
`HighValueKinds`. That one list decides both what wakes an operator at 3am and
what the sensor's rate limiter protects when it has to drop something.

## Tests

Not coverage for its own sake — a test should state a property the project
would be broken without, and say so in its name and comment. The existing ones
are the model:

- `TestNTPNeverAnswersMonlist` — the amplification refusal.
- `TestPerSensorTokenStampsNode` — a sensor's identity comes from its
  credential, not from the body it sends.
- `TestUIRequiresLogin` — an unauthenticated request never sees event data.
- `TestHighValueSurvivesNoiseFlood` — a flood of connections cannot bury the
  password that arrives next.

Anything touching authentication, TLS, rate limiting, or what a decoy is
willing to do needs one.

## Comments

This codebase explains *why*, not *what*. `// increment the counter` is noise;
the reason a constant is 30 rather than 300, or why a lookup is deliberately
not constant-time, is the thing a future reader cannot recover from the code.
If a decision has a trade-off behind it, write the trade-off down.

## Before you open a pull request

```bash
gofmt -l .
go vet ./...
go test ./...
```

CI additionally runs the race detector, `govulncheck`, tests on macOS and
Windows, and a cross-compile of every supported target. Cross-compilation is
not ceremony: an untyped constant larger than a 32-bit `int` once stopped the
whole sensor from building for `linux/arm`, and nothing else would have caught
it.

Almost every test binds a loopback listener. On a Windows machine running
endpoint security software, the first connection to a freshly built test binary
can stall for the ten-second header timeout and then fail with `EOF` — a
different test each run, usually a TLS one. That is the scanner touching each new
binary's first socket, not a race in the code; `go test ./... -p 1` makes it
rarer, and re-running clears it. The suite is green on all three platforms in CI.

Commits: imperative subject line, and a body explaining why when the change is
not obvious. Small, reviewable pull requests over large ones.

## Releasing

Tagging is the whole procedure — the release workflow does the rest:

```bash
git tag v0.1.0 && git push origin v0.1.0
```

That re-runs the tests (a tag can be pushed at a commit CI never saw), builds
both binaries for seven platforms, publishes a GitHub release with checksums and
a build-provenance attestation, and pushes multi-architecture container images to
`ghcr.io`. A tag with a hyphen (`v0.1.0-rc1`) is marked as a pre-release.

Every binary is stamped: `wispd -version` reports the release, the commit, and
the Go version; a build from a working tree says `dev`. To verify a download:

```bash
sha256sum -c SHA256SUMS --ignore-missing
gh attestation verify wisp_v0.1.0_linux_amd64.tar.gz --repo willysnow/wisp
```

## Licence and provenance

Contributions are under BSD-3-Clause, matching the project and OpenCanary.

Several protocol *behaviours* here were studied from OpenCanary, which is a
legitimate thing to do — but do not copy its code, or any other project's,
into this one. If you are porting an idea, port the idea and write the Go
yourself. If a contribution does include third-party code, say so in the pull
request so its licence and attribution can be handled properly.
