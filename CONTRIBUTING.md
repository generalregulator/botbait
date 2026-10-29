# Contributing

Thanks for helping. The project is small on purpose: standard library only, one
static binary, and a hard rule that **nothing an attacker sends is ever
executed**.

## Ground rules

1. **Stay low-interaction.** No real shell, no `os/exec`, no outbound
   connections on behalf of the attacker. The shell emulator interprets
   commands against an in-memory file system and returns canned output.
2. **Bound everything attacker-controlled**: bytes, count, depth, time. Every new
   loop or buffer needs a limit and a test that hits it.
3. **No new dependencies** without a strong reason (the supply chain of a
   honeypot is part of its threat model).
4. **No offensive code.** Exploits, scanners, attack automation and anything
   that helps attack third parties will be rejected. Test fixtures use
   harmless stand-ins (`ELF` magic + filler), never real malware.
5. **No secrets or data** in commits: tokens, `.env`, JSONL logs, captured
   payloads. `.gitignore` covers them; check your diff anyway.

## Development

```bash
go version          # 1.24+
make check          # gofmt + go vet + go test -race ./...
make build          # bin/honeypot
make lint           # staticcheck-style extras if installed (optional)
make vuln           # govulncheck (optional)
```

Run locally without Docker (high ports, no root):

```bash
HP_PORTS=15555,17547,12323 HP_TELNET_PORTS=12323 HP_LOG_DIR=./data \
HP_PAYLOAD_DIR=./captured_payloads HP_DOWNLOAD_ENABLED=false \
go run ./cmd/honeypot
```

## Layout

See [docs/TECHNICAL_REPORT.md](docs/TECHNICAL_REPORT.md), section 16. Each package has unit tests; `internal/e2e` drives the
real listeners over sockets and is the place for cross-cutting regression tests.

## Pull requests

* Keep PRs focused; describe the *why*.
* Add or update tests. Fuzz-style inputs (truncated frames, lying lengths,
  huge counts) are especially valuable.
* Update `CHANGELOG.md` (Unreleased section) and any documentation touched.
* Commit messages: imperative mood, short subject, body explains motivation.

## Contributing a device profile

Profiles are plain JSON, no code needed. Read [`docs/PROFILES.md`](docs/PROFILES.md),
copy a built-in profile from `internal/profile/builtin/`, and open a
*Device profile contribution* issue or PR. `go test ./internal/profile`
validates the schema.

## Reporting security issues

Privately, see [`SECURITY.md`](SECURITY.md).
