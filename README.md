# Security Watch CLI

Security Watch CLI scans local project files for security signals on Linux
workstations.

It reports:

- local project dependency vulnerabilities from Trivy or OSV Scanner
- direct vs transitive (indirect) classification for each vulnerability
- the direct dependency chain that pulls in each transitive vulnerable package
- optional registry lookups (PyPI, npm) to check if a newer version of that
  direct dep resolves the issue
- optional public watch-feed matches from CISA KEV and NVD Recent

## Requirements

- Go 1.26 or newer (build only — the compiled binary has no runtime dependencies)
- `trivy` or `osv-scanner` for dependency scanning

## Install

Clone the repo and build both binaries:

```bash
git clone <repo-url> sec-watch
cd sec-watch
CGO_ENABLED=0 go build -ldflags="-s -w" -o ~/.local/bin/sec-watch ./cmd/sec-watch
CGO_ENABLED=0 go build -ldflags="-s -w" -o ~/.local/bin/sec-watch-local ./cmd/sec-watch-local
```

Make sure `~/.local/bin` is on your `PATH`. Verify:

```bash
sec-watch defaults-env
```

Install Trivy (recommended scanner):

```bash
# Fedora / RHEL
sudo dnf install trivy

# or via the official install script
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b ~/.local/bin
```

Optionally install a keyword watch config:

```bash
mkdir -p ~/.config/sec-watch
cp config/watch.example.json ~/.config/sec-watch/watch.json
# edit ~/.config/sec-watch/watch.json to add your keywords
```

## Usage

Run a scan from the default projects directory (`~/Projects`):

```bash
sec-watch-local
```

Scan a specific local directory:

```bash
sec-watch-local /path/to/project
```

Scan a local Git branch without changing your working tree:

```bash
sec-watch-local /path/to/repo --branch main
```

Scan a remote GitHub repo (clone first):

```bash
git clone --depth=1 https://github.com/org/repo /tmp/repo-scan
sec-watch-local /tmp/repo-scan
```

Machine-readable JSON output:

```bash
sec-watch-local --json
```

Debug mode — prints effective scanner settings and internal scan milestones:

```bash
sec-watch-local --debug --progress-interval 1
```

Check defaults and current configuration:

```bash
sec-watch defaults-env
```

## Transitive dependency analysis

For each vulnerability, sec-watch classifies the affected package as **direct**
or **indirect** (transitive). Indirect findings include:

- which direct dependency or dependencies pull in the vulnerable package (the
  "via" chain, resolved by BFS through the lockfile dependency graph)
- a registry lookup against PyPI or npm for each direct parent to find whether
  its latest release constrains the transitive dep to a fixed version

Example text report output:

```
1. CRITICAL CVE-2026-42208 (CVSS 9.8)
   Package: litellm 1.83.0 [indirect]
   Fix: needs litellm >= 1.83.7
   Via: orchestrator-core 5.0.1 — latest 5.0.2 still allows unfixed litellm (>=1.80.0)
   Target: uv.lock
   ...
```

If the latest release of the direct dep does require a fixed version, the advice
will say so and name the version to upgrade to. If the package is private and not
on the public registry, that is noted too.

Registry lookups add a few seconds to each scan. Set
`SEC_WATCH_REGISTRY_LOOKUP=0` to disable them for offline or faster runs.

## Configuration

All defaults can be overridden via environment variables:

| Variable | Default | Description |
|---|---|---|
| `SEC_WATCH_PROJECTS_DIR` | `~/Projects` | Root directory to scan |
| `SEC_WATCH_PROJECTS` | *(all)* | Comma-separated project name filter |
| `SEC_WATCH_ECOSYSTEMS` | `npm,yarn,pnpm,pip,poetry,uv,python-pkg` | Dependency ecosystems to include |
| `SEC_WATCH_PUBLIC_FEEDS` | `cisa-kev,nvd-recent` | Public CVE feeds to query |
| `SEC_WATCH_RECENT_DAYS` | `7` | Lookback window for "recent" changes |
| `SEC_WATCH_TTL` | `1800` | Cache TTL in seconds |
| `SEC_WATCH_CONFIG` | `~/.config/sec-watch/watch.json` | Watch config path |
| `SEC_WATCH_REGISTRY_LOOKUP` | `1` | Set to `0` to skip PyPI/npm lookups |
| `SEC_WATCH_FORCE` | `0` | Set to `1` to bypass the cache |
| `SEC_WATCH_DEBUG` | `0` | Set to `1` for debug output |

The `sec-watch-local` wrapper also accepts flags and `SEC_WATCH_LOCAL_*` overrides:

```bash
# Scan a different projects root
SEC_WATCH_PROJECTS_DIR=~/Code sec-watch-local

# Filter to specific ecosystems
sec-watch-local --ecosystems npm,pip

# Disable public feeds
sec-watch-local --public-feeds ''

# Override recent-days lookback
sec-watch-local --recent-days 14
```

### Watch config

Public-feed keyword matching is configured in `~/.config/sec-watch/watch.json`:

```json
{
  "lookback_days": 14,
  "keywords": [
    "openssh",
    "openssl",
    "linux kernel",
    "node.js"
  ]
}
```

The `keywords` list is matched case-insensitively against CVE IDs, vendor
names, product names, and descriptions in both CISA KEV and NVD. A starter
template is at `config/watch.example.json`.

## Reports

Each scan writes reports to `~/.cache/sec-watch/`:

| File | Description |
|---|---|
| `dependency-report.txt` | Terminal-formatted findings with CVSS details and via chain |
| `dependency-report.html` | Sortable HTML table with indirect badge and fix/via column |
| `dependency-report.json` | Raw Trivy output |

Both the text and HTML reports mark transitive packages with an `[indirect]`
label. The HTML report's **Fix / Via** column shows the fix version and the
direct dep chain inline. Tables can be sorted by clicking any column header.

`sec-watch-local` run artefacts are kept under `~/.cache/sec-watch-local/jobs/`
for post-scan inspection.

## Development

Build and verify:

```bash
go build ./...
go vet ./...
```

To test without touching the real cache:

```bash
XDG_CACHE_HOME=$(mktemp -d) SEC_WATCH_FORCE=1 sec-watch status
```
