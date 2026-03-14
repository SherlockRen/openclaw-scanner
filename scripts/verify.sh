#!/usr/bin/env bash
set -euo pipefail

echo "[verify] gofmt"
gofmt -w ./cmd ./internal

echo "[verify] go vet"
go vet ./...

echo "[verify] go test"
go test ./...

echo "[verify] go build"
go build ./...

echo "[verify] done"
