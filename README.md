# Security Watch CLI

Security Watch CLI scans local project files for security signals on Linux
workstations.

It reports:

- local project dependency vulnerabilities from Trivy or OSV Scanner
- optional public watch-feed matches from manual CVEs, CISA KEV, and NVD Recent

## Requirements

- Python 3.10 or newer
- Bash, `jq`, `curl`, and `gzip`
- `trivy` or `osv-scanner` for dependency scanning

Install these runtime packages with your system package manager:

```text
trivy jq curl
```

## Usage

Run a scan from the shared projects directory:

```bash
bin/sec-watch-local
```

With no path, the CLI starts from `~/Projects`. To scan a specific local
directory:

```bash
bin/sec-watch-local /path/to/project
```

To scan a local Git branch without changing your working tree:

```bash
bin/sec-watch-local /path/to/repo --branch main
```

Normal output prints progress to stderr and a summary to stdout. JSON mode keeps
stdout machine-readable until the final result:

```bash
bin/sec-watch-local --json
```

Debug mode prints effective scanner settings and internal scanner milestones:

```bash
bin/sec-watch-local --debug --progress-interval 1
```

## Configuration

Defaults are centralized in:

```bash
bin/sec-watch defaults-env
```

Default values:

- `SEC_WATCH_PROJECTS_DIR=$HOME/Projects`
- `SEC_WATCH_PROJECTS=` scans all projects under the selected directory
- `SEC_WATCH_ECOSYSTEMS=npm,yarn,pnpm,pip,poetry,uv,python-pkg`
- `SEC_WATCH_PUBLIC_FEEDS=manual,cisa-kev,nvd-recent`
- `SEC_WATCH_RECENT_DAYS=7`
- `SEC_WATCH_CONFIG=${XDG_CONFIG_HOME:-$HOME/.config}/sec-watch/watch.json`

Every `SEC_WATCH_*` value can be overridden in the environment. The local CLI
also accepts matching flags or `SEC_WATCH_LOCAL_*` overrides:

```bash
SEC_WATCH_PROJECTS_DIR=~/Code bin/sec-watch-local
SEC_WATCH_LOCAL_ECOSYSTEMS=npm,pip bin/sec-watch-local
bin/sec-watch-local --public-feeds ''
bin/sec-watch-local --debug
```

Manual watch entries and public-feed keywords live in:

```text
~/.config/sec-watch/watch.json
```

This repo includes a starter template:

```text
config/watch.example.json
```

## Reports

The local CLI stores each run under:

```text
~/.cache/sec-watch-local/jobs/
```

Each scan writes report paths in the final output:

```text
dependency-report.html
dependency-report.txt
dependency-report.json
```

`dependency-report.txt` is formatted for terminal reading with short finding
blocks. Trivy reports include CVSS score, attack vector, attack complexity,
privileges, and user interaction. The HTML tables can be sorted by clicking
column headers.

## Development

There is no package manager or build step for the CLI branch. Before handing off
changes, run:

```bash
bash -n bin/sec-watch
python3 -m py_compile bin/sec-watch-local
git diff --check
```
