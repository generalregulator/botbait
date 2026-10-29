# syntax=docker/dockerfile:1.7

############################
# Stage 1: build a static binary
############################
FROM golang:1.24-alpine AS builder

# CA bundle for HTTPS (Telegram API) and a non-root account that we copy into
# the final image. busybox adduser: -D no password, -H no home, -S system.
RUN apk add --no-cache ca-certificates \
 && addgroup -g 10001 -S appuser \
 && adduser -u 10001 -S -D -H -G appuser -s /sbin/nologin appuser

WORKDIR /src
COPY go.mod ./
# The project is dependency-free (standard library only), so there is nothing
# to download and the supply-chain surface is the Go toolchain itself.
COPY cmd ./cmd
COPY internal ./internal

ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath \
      -ldflags="-s -w -X main.version=${VERSION}" \
      -o /out/honeypot ./cmd/honeypot

# Writable runtime directories, created here because `scratch` has no shell.
RUN mkdir -p /out/rootfs/app/captured_payloads /out/rootfs/app/data

############################
# Stage 2: empty image
############################
FROM scratch

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /etc/passwd /etc/passwd
COPY --from=builder /etc/group  /etc/group
COPY --from=builder --chown=10001:10001 /out/rootfs/app /app
COPY --from=builder /out/honeypot /honeypot

# Unprivileged user (UID/GID 10001). All default ports are >1024, so no
# CAP_NET_BIND_SERVICE is needed; privileged host ports (23, 80...) are mapped
# by the container runtime instead (see docker-compose.yml).
USER 10001:10001
WORKDIR /app

ENV HP_PAYLOAD_DIR=/app/captured_payloads \
    HP_LOG_DIR=/app/data \
    HP_METRICS_ADDR=127.0.0.1:9100

EXPOSE 5555 7547 2323 8088 8081 8080

# No curl in scratch: the binary probes its own loopback health endpoint.
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD ["/honeypot", "-healthcheck"]

ENTRYPOINT ["/honeypot"]
