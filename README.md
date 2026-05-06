# Security Watch

Security Watch is a local GNOME Shell extension and scanner helper for Fedora workstations.

It shows a top-bar security count using:

- Fedora security advisories from `dnf5 advisory`
- local project dependency vulnerabilities from Trivy
- optional public watch feeds: manual CVEs, CISA KEV, and NVD Recent

It can also notify when selected categories increase and rescan after dependency lockfiles change.

## Requirements

- Fedora Workstation with GNOME Shell 50
- `dnf5`
- `trivy`
- `jq`
- `curl`
- `glib-compile-schemas`

Install the runtime packages:

```bash
sudo dnf install trivy jq curl glib2
```

## Install

```bash
./install.sh
```

Then log out and back in, or restart GNOME Shell if your session supports it.

Enable the extension:

```bash
gnome-extensions enable sec-watch@local
```

Open preferences:

```bash
gnome-extensions prefs sec-watch@local
```

## Configuration

The GNOME preferences page controls:

- project root directory
- selected projects
- enabled dependency ecosystems
- enabled public vulnerability feeds
- notification categories
- scan interval
- lockfile change watching

Manual watch entries and public-feed keywords live in:

```text
~/.config/sec-watch/watch.json
```

This repo includes a starter template at:

```text
config/watch.example.json
```

## Reports

Generated reports are written to:

```text
~/.cache/sec-watch/dependency-report.html
~/.cache/sec-watch/dependency-report.txt
~/.cache/sec-watch/dependency-report.json
```

Trivy reports include CVSS score, attack vector, attack complexity, privileges,
and user interaction columns. The HTML tables can be sorted by clicking the
column headers.

They are not tracked by git.

Sanitized example reports are tracked for reference:

```text
examples/dependency-report.html
examples/dependency-report.txt
```

## Web Server

The `sec-watch-web` branch also includes a FastAPI wrapper for scanning a Git
repository and branch from a browser or JSON client.

Install `uv` if it is not already available, then sync the Python server
dependencies:

```bash
uv --version
uv sync
```

Run it locally:

```bash
uv run bin/sec-watch-server
```

For LAN access, bind to a LAN address and set a token:

```bash
SEC_WATCH_WEB_TOKEN='change-me' uv run bin/sec-watch-server --host 0.0.0.0
```

LAN clients can pass the token as `X-Sec-Watch-Token`, `Authorization: Bearer
...`, or `?token=...`. JSON clients can start a scan with `POST /scans` and
poll `GET /api/scans/<id>`.

The server accepts Git URLs and existing local Git repository paths. It keeps
repository mirrors and per-scan worktrees under:

```text
~/.cache/sec-watch-web
```

## Local CLI

For a local-files-only scan without the webserver, run:

```bash
bin/sec-watch-local /path/to/project
```

This disables Fedora advisory checks and public watch feeds, then scans only the
local dependency files under the selected directory. To scan a local Git branch
without changing your working tree:

```bash
bin/sec-watch-local /path/to/repo --branch main
```

The CLI stores its run cache and reports under:

```text
~/.cache/sec-watch-local
```

## Development

After changing the schema:

```bash
glib-compile-schemas extension/schemas
```

After installing local changes:

```bash
./install.sh
gnome-extensions disable sec-watch@local
gnome-extensions enable sec-watch@local
```

For extension code changes on Wayland, use a nested GNOME Shell instead of
logging out of the real desktop:

```bash
bin/sec-watch-dev-shell
```

Wayland sessions cannot restart the logged-in GNOME Shell process. The helper
installs the extension, starts a nested Wayland Shell, and enables the extension
inside that nested session so each run gets a fresh extension process. On GNOME
49 and later, Fedora may need `mutter-devel` installed for the nested
development kit.
