#!/bin/sh
# build/m0/build.sh — M0 build script (Linux/macOS). Mirrors build.ps1.
#
# Usage: sh build/m0/build.sh [--skip-tests] [--release]
# Env: C2_CLIENT_LISTEN / C2_OPERATOR_LISTEN / C2_OPERATOR_USER / C2_CLIENT_ADDR
#      (runtime injection only; no secrets baked into binaries)

set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
OUT="$ROOT/build/m0/bin"
mkdir -p "$OUT"

SKIP_TESTS=0
RELEASE=0
for arg in "$@"; do
  case "$arg" in
    --skip-tests) SKIP_TESTS=1 ;;
    --release) RELEASE=1 ;;
    *) echo "unknown arg: $arg" >&2; exit 2 ;;
  esac
done

fails=0
run() { # run <name> <dir> <cmd...>
  name=$1; dir=$2; shift 2
  echo "== $name =="
  ( cd "$dir" && "$@" ) || { echo "FAILED: $name" >&2; fails=$((fails+1)); }
}

echo "== cargo build (offline) =="
cd "$ROOT/src/m0/client-rust"
if [ "$RELEASE" = 1 ]; then cargo build --release --offline; else cargo build --offline; fi
if [ "$SKIP_TESTS" = 0 ]; then cargo test --offline || fails=$((fails+1)); fi
PROFILE=debug; [ "$RELEASE" = 1 ] && PROFILE=release
if [ -f "$ROOT/src/m0/client-rust/target/$PROFILE/c2client" ]; then
  cp "$ROOT/src/m0/client-rust/target/$PROFILE/c2client" "$OUT/c2client"
elif [ -f "$ROOT/src/m0/client-rust/target/$PROFILE/c2client.exe" ]; then
  cp "$ROOT/src/m0/client-rust/target/$PROFILE/c2client.exe" "$OUT/c2client.exe"
fi
cd "$ROOT"

for m in server-go operator-go builder; do
  case "$m" in
    server-go)   out=c2server ;;
    operator-go) out=c2operator ;;
    builder)     out=c2builder ;;
  esac
  run "go build ($m)" "$ROOT/src/m0/$m" go build -trimpath -ldflags "-s -w" -o "$OUT/$out" .
  if [ "$SKIP_TESTS" = 0 ]; then
    run "go vet ($m)" "$ROOT/src/m0/$m" go vet ./...
    run "go test ($m)" "$ROOT/src/m0/$m" go test ./...
  fi
done

echo
ls -l "$OUT"
if [ "$fails" -gt 0 ]; then echo "$fails build step(s) FAILED" >&2; exit 1; fi
echo "M0 build OK"
