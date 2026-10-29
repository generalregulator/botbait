#!/usr/bin/env bash
# Rename the Go module path so that `go install` and imports work from GitHub.
#
#   scripts/rename-module.sh github.com/<user>/iot-honeypot
#
# Rewrites go.mod, every import in *.go, and the repository URL placeholders in
# CITATION.cff and .github/ISSUE_TEMPLATE/config.yml (OWNER -> <user>).
set -euo pipefail

new="${1:-}"
if [[ ! "$new" =~ ^github\.com/[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$ ]]; then
  echo "usage: $0 github.com/<user>/<repo>" >&2
  exit 2
fi
cd "$(dirname "$0")/.."

old="$(awk '/^module /{print $2; exit}' go.mod)"
if [[ "$old" == "$new" ]]; then
  echo "module already $new"
  exit 0
fi
user="${new#github.com/}"
user="${user%%/*}"

# Go sources and go.mod
grep -rl --include='*.go' --include='go.mod' -- "\"$old/" . "go.mod" 2>/dev/null | sort -u | while read -r f; do
  sed -i "s#\"$old/#\"$new/#g" "$f"
done
sed -i "s#^module $old\$#module $new#" go.mod

# Docs / metadata placeholders
for f in CITATION.cff .github/ISSUE_TEMPLATE/config.yml README.md docs/TECHNICAL_REPORT.md; do
  [[ -f "$f" ]] && sed -i "s#github.com/OWNER/#github.com/$user/#g; s#/OWNER/#/$user/#g" "$f"
done

go build ./... && go vet ./... >/dev/null
echo "module renamed: $old -> $new"
echo "next: go test -race ./... && git add -A && git commit"
