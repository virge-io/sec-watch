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

They are not tracked by git.

Sanitized example reports are tracked for reference:

```text
examples/dependency-report.html
examples/dependency-report.txt
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

On Wayland, logging out and back in is often the cleanest way to reload extension code.
