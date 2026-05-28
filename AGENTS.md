# Codex Notes

## Project Shape

Security Watch CLI has two runtime entrypoints, both written in Go:

- `cmd/sec-watch/` — core scanner binary. Runs trivy or osv-scanner, fetches CISA KEV and NVD feeds, caches results, and emits `status` output.
- `cmd/sec-watch-local/` — wrapper binary for local directory and local branch scans. Calls `sec-watch` as a subprocess.

Shared logic lives under `internal/`:

| Package | Purpose |
|---|---|
| `config` | Env var loading, XDG paths, defaults |
| `cache` | JSON status cache read/write |
| `scanner` | Trivy and osv-scanner execution + JSON parsing |
| `feeds` | CISA KEV and NVD HTTP fetch + keyword matching |
| `report` | Text and HTML report generation (replaces the old `.jq` files) |
| `status` | TTY detection, output formatting |

Runtime reports and scan state are written under
`${XDG_CACHE_HOME:-$HOME/.cache}/sec-watch`; user watch configuration
lives at `${XDG_CONFIG_HOME:-$HOME/.config}/sec-watch/watch.json`.

The old `share/sec-watch/*.jq` files are no longer used — their logic is
inlined into the Go packages. The old `bin/sec-watch` (bash) and
`bin/sec-watch-local` (Python) are superseded but retained on the branch for
reference until the Go binaries are installed.

## Build

```bash
CGO_ENABLED=0 go build -ldflags="-s -w" -o bin-out/sec-watch ./cmd/sec-watch
CGO_ENABLED=0 go build -ldflags="-s -w" -o bin-out/sec-watch-local ./cmd/sec-watch-local
```

Both produce fully static binaries with no runtime dependencies on `jq`,
`curl`, or `gzip`.

## Local Workflow

- No package manager setup needed beyond `go mod tidy`.
- Before handing off changes, verify:

  ```bash
  go build ./...
  go vet ./...
  ```

## Cache Format

The cache file is `$CACHE_DIR/status.json` (JSON). The old bash `.env` format
is no longer used; the first run after upgrading will do a fresh scan.

## Testing Notes

- `sec-watch` shells out to `trivy` or `osv-scanner` for dependency scanning;
  both are optional (falls back gracefully).
- To avoid touching the real user cache while testing, set `XDG_CACHE_HOME`
  to a temp dir and `SEC_WATCH_FORCE=1`.
- Network-backed feed checks (CISA KEV, NVD) require internet access; skip by
  setting `SEC_WATCH_PUBLIC_FEEDS=`.

## Conventions

- All JSON parsing uses `encoding/json` with typed structs — no jq subprocess.
- HTTP fetches use `net/http` with a 25-second timeout.
- Keep `CGO_ENABLED=0` for distribution builds.
- Do not commit generated artifacts: `bin-out/`, `bin/__pycache__/`, reports, logs.
