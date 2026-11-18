#!/bin/sh
# Build + regression for the BDC2 v1 operator TUI (Linux/macOS host).
# Outputs dist/c2tui.exe (windows/amd64) and dist/c2tui-linux-amd64.
set -eu
cd "$(dirname "$0")"
VER="${1:-1.0.0}"

echo "[i] go test ./..."
go test ./...

mkdir -p dist
export CGO_ENABLED=0

echo "[i] building dist/c2tui.exe (windows/amd64)"
GOOS=windows GOARCH=amd64 go build -trimpath \
  -ldflags "-s -w -X main.version=${VER}" -o dist/c2tui.exe .

echo "[i] building dist/c2tui-linux-amd64 (linux/amd64)"
GOOS=linux GOARCH=amd64 go build -trimpath \
  -ldflags "-s -w -X main.version=${VER}" -o dist/c2tui-linux-amd64 .

echo "[ok] version ${VER}"
ls -l dist
