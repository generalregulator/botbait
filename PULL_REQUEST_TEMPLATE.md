## What and why

<!-- One or two sentences. Link the issue if there is one. -->

## Checklist

- [ ] `make check` passes (gofmt, vet, `go test -race ./...`)
- [ ] New behaviour has tests (unit, and e2e if it crosses a socket)
- [ ] No new third-party dependencies (stdlib only) — or the need is justified here
- [ ] Attacker-controlled input stays bounded (size, count, time) and is never executed
- [ ] Docs updated (README / `docs/` / `.env.example` / `CHANGELOG.md`)
- [ ] No real malware, credentials, tokens or captured data in the diff
