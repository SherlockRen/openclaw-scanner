# clawscanner

[中文文档 (Chinese README)](./README.zh-CN.md)

`clawscanner` is a Go-based internal asset scanner for OpenClaw environments.
It provides fast TCP port probing and OpenClaw fingerprint detection with JSON reporting.

## Features

- **Target input**
  - Single host/IP: `192.168.1.10`
  - CIDR: `192.168.1.0/24`
  - URL input normalization: `https://10.0.0.8` (hostname extracted automatically)
  - Multiple targets: comma-separated
- **Port scanning**
  - Default ports: `18789,19001,443,80,8080,8443`
  - Custom port list/range: `--ports 80,443,8080` or `--ports 8000-8100`
  - Configurable concurrency: `--threads` (default: `100`)
  - Configurable TCP timeout: `--timeout` seconds (default: `5`)
- **OpenClaw fingerprinting (open ports only)**
  - HTML/body markers (`openclaw/moltbot/clawdbot`)
  - HTTP headers (`Server` / `X-Powered-By`)
  - Health API (`/api/v1/health`)
  - Favicon mmh3 matching (default hash: `-1172715710`)
  - Aggregated by `target + port` with confidence escalation for multiple hits
- **Reporting & output**
  - Colorized terminal progress + summary tables
  - JSON report output to file (`-o`) or stdout (when omitted)
  - Each finding includes `target`, optional `port`, and optional `accessUrl`

## Quick Start

### Build

```bash
go build -o clawscanner ./cmd/clawscanner
```

### Run

```bash
./clawscanner 192.168.1.0/24 --ports 80,443,8080 -o results.json
```

### Example (URL target)

```bash
./clawscanner https://137.184.38.179 --ports 443 -o results.json
```

## CLI Usage

```bash
clawscanner <target|cidr> [--ports 18789,8080,3000] [--threads 100] [--timeout 5] [-o results.json]
```

### Flags

- `--ports`: custom ports list/range
- `--threads`: concurrency for probing (default `100`)
- `--timeout`: TCP dial timeout in seconds (default `30`)
- `-o`: JSON output file path
- `--quiet`: disable progress logs and pretty terminal summary
- `--requester`, `--scope`, `--time-window`, `--source`: authorization metadata

## Output Schema (JSON)

Top-level fields:

- `schemaVersion`
- `taskMeta` (`taskId`, timestamps, status, targetCount, portCount)
- `summary` (`findingCount`)
- `findings[]`

Finding fields include:

- `findingId`, `findingType`, `severity`, `ruleId`
- `target`, optional `port`, optional `accessUrl`
- `evidencePattern`, `evidenceMasked`
- `confidence`, `requiresManualReview`, `falsePositiveState`, `recommendation`

## Development

### Verify

```bash
./scripts/verify.sh
```

This runs:

1. `gofmt -w ./cmd ./internal`
2. `go vet ./...`
3. `go test ./...`
4. `go build ./...`

## Project Structure

- `cmd/clawscanner/main.go` — CLI entry and terminal output
- `internal/discovery/` — target parsing and TCP/HTTP service discovery
- `internal/vulnscan/` — OpenClaw fingerprinting and detection helpers
- `internal/models/result.go` — report data models
- `internal/output/json.go` — JSON report writer

## Notes

- Fingerprint checks are executed **only for open ports** returned by scanning.
- TLS probing currently uses permissive verification mode to improve practical asset identification coverage.
