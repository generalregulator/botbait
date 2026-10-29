.PHONY: all build test race vet fmt check lint vuln cover profiles docker up down logs init-dirs report clean

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

all: check build

build:
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=$(VERSION)" -o bin/honeypot ./cmd/honeypot

test:
	go test -count=1 ./...

race:
	go test -race -count=1 ./...

vet:
	go vet ./...

fmt:
	gofmt -w .

# What CI should run.
check: vet race
	@test -z "$$(gofmt -l .)" || (echo "gofmt needed:"; gofmt -l .; exit 1)

# Optional extras (not required by CI): staticcheck and govulncheck, if installed.
lint:
	@command -v staticcheck >/dev/null && staticcheck ./... || echo "staticcheck not installed (go install honnef.co/go/tools/cmd/staticcheck@latest)"

vuln:
	@command -v govulncheck >/dev/null && govulncheck ./... || echo "govulncheck not installed (go install golang.org/x/vuln/cmd/govulncheck@latest)"

cover:
	go test -count=1 -coverprofile=coverage.out ./... && go tool cover -func=coverage.out | tail -1

profiles: build
	@for p in $$(./bin/honeypot -list-profiles); do ./bin/honeypot -check-profile $$p || exit 1; done

docker:
	docker compose build

# The container runs as UID 10001: the bind-mounted directories must be writable by it.
init-dirs:
	mkdir -p captured_payloads data
	sudo chown -R 10001:10001 captured_payloads data
	chmod 750 captured_payloads data

up: init-dirs
	docker compose up -d --build

down:
	docker compose down

logs:
	docker compose logs -f --tail=100 honeypot

report:
	cd analysis && python3 -m venv .venv && . .venv/bin/activate && pip install -q -r requirements.txt && \
	python load_events.py ../data --db ../data/honeypot.sqlite

clean:
	rm -rf bin coverage.out
