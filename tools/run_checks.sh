#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "$0")/.." && pwd)"

cd "$repo_dir"
python -m pytest -q
python -m ruff check aais tests

cd "$repo_dir/typescript"
npm run check

cd "$repo_dir/go"
aais_go_cache="${AAIS_GO_CACHE:-/tmp/aais-go-cache}"
aais_go_mod_cache="${AAIS_GO_MOD_CACHE:-/tmp/aais-go-mod}"
env GOCACHE="$aais_go_cache" GOMODCACHE="$aais_go_mod_cache" go test ./...
env GOCACHE="$aais_go_cache" GOMODCACHE="$aais_go_mod_cache" go vet ./...

cd "$repo_dir/rust"
cargo fmt --check
cargo test
cargo clippy --all-targets -- -D warnings

cd "$repo_dir/java"
mvn -q verify
