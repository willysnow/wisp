# syntax=docker/dockerfile:1

# Two images from one file:
#
#   docker build --target sensor  -t wisp/sensor  .
#   docker build --target console -t wisp/console .
#
# Both are distroless: no shell, no package manager, nothing to pivot into. The
# sensor is the container most likely to be attacked on purpose, so it carries
# the least.

# --platform=$BUILDPLATFORM keeps the builder native and lets Go do the
# cross-compiling, so a multi-architecture build costs one compile per target
# instead of emulating an arm64 machine to run the compiler on.
FROM --platform=$BUILDPLATFORM golang:1.25-alpine AS build

WORKDIR /src

# Dependencies first — they change far less often than the code, so this layer
# survives most rebuilds.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Set by BuildKit; empty outside it, which Go reads as "this machine".
ARG TARGETOS
ARG TARGETARCH

# Stamped into the binaries so a deployed sensor can say what it is. Defaults
# to dev: an unstamped build must not claim to be a release.
ARG VERSION=dev

# CGO off is not a size optimisation. The SQLite driver is pure Go precisely so
# the binaries stay static and cross-compilable; enabling cgo would undo the
# property this whole project is built on.
ENV CGO_ENABLED=0

RUN GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath \
        -ldflags="-s -w -X github.com/willysnow/wisp/internal/build.Version=${VERSION}" \
        -o /out/wispd ./cmd/wispd && \
    GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath \
        -ldflags="-s -w -X github.com/willysnow/wisp/internal/build.Version=${VERSION}" \
        -o /out/wisp-console ./cmd/wisp-console

# An empty directory to copy in with the right ownership. A named volume
# mounted at /data inherits the image's ownership for that path, which is how
# the non-root user ends up able to write to it without a chown on the host.
RUN mkdir -p /out/data


# ---------------------------------------------------------------------------
# Console: the aggregation server. Keep /data — it holds the database, the
# operator accounts, and any certificate.
# ---------------------------------------------------------------------------
FROM gcr.io/distroless/static-debian12:nonroot AS console

COPY --from=build /out/wisp-console /usr/local/bin/wisp-console
COPY --from=build --chown=65532:65532 /out/data /data
# Publishing an image is a binary redistribution, and BSD-3-Clause asks for the
# notice to travel with it.
COPY LICENSE NOTICE /

WORKDIR /data
USER nonroot
EXPOSE 8000

# The image has no curl and no shell, so the console probes itself. Add
# `-insecure` to the arguments when the console terminates its own TLS with a
# self-signed certificate.
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD ["/usr/local/bin/wisp-console", "healthcheck", "-url", "http://127.0.0.1:8000/healthz"]

ENTRYPOINT ["/usr/local/bin/wisp-console"]
CMD ["-addr", ":8000", "-db", "/data/wisp-console.db", "-config", "/data/console.yaml"]


# ---------------------------------------------------------------------------
# Sensor: the honeypot itself, and the default build target.
#
# Run it with host networking on Linux. Published ports work, but Docker's
# proxying can rewrite the client's address to the bridge gateway — and a
# sensor that records 172.17.0.1 as the source of every intrusion has thrown
# away the one field an operator acts on. On Docker Desktop (macOS/Windows)
# that rewriting always happens.
#
# Keep /data. It holds the SSH host key and the decoy TLS certificates, and
# material that changes on every restart identifies the box as a honeypot to
# anyone who connects twice.
# ---------------------------------------------------------------------------
FROM gcr.io/distroless/static-debian12:nonroot AS sensor

COPY --from=build /out/wispd /usr/local/bin/wispd
COPY --from=build --chown=65532:65532 /out/data /data
COPY LICENSE NOTICE /

WORKDIR /data
USER nonroot

# Documentation only — and deliberately the unprivileged defaults, so the
# container needs no added capabilities. Redirect the real ports to these at
# the firewall.
EXPOSE 2222/tcp 2323/tcp 2121/tcp 6379/tcp 8080/tcp 8931/tcp 11434/tcp 6443/tcp
EXPOSE 6969/udp 1123/udp

ENTRYPOINT ["/usr/local/bin/wispd"]
CMD ["-config", "/data/wisp.yaml"]
