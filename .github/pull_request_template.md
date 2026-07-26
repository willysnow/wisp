## What this changes

<!-- And why. The why is the part a reviewer cannot recover from the diff. -->

## How it was verified

<!--
Which tests, and anything you exercised by hand. For a protocol module, the
client you tripped it with is the most useful line here.
-->

## Checklist

- [ ] `gofmt -l .` is silent, `go vet ./...` and `go test ./...` pass
- [ ] New behaviour that must never regress has a test that says so in its name
- [ ] No new dependency, or the pull request explains why the standard library
      could not cover it
- [ ] Still builds with `CGO_ENABLED=0` for every target in CI, including
      32-bit
- [ ] Docs updated where they now say something untrue — README, the example
      configs, and the roadmap

For a new protocol module, the full checklist is in
[CONTRIBUTING.md](../CONTRIBUTING.md).

<!--
Never paste real captured events, ingest tokens, or console passwords into a
pull request. Redact them the way you would a password.
-->
