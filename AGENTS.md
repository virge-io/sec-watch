# Codex Notes

## Project Shape

Security Watch CLI has two runtime entrypoints:

- `bin/sec-watch-local`: Python CLI wrapper for local directory and local branch scans.
- `bin/sec-watch`: Bash scanner/helper that emits `status` output and `defaults-env`.

Runtime reports and scan state are written under
`${XDG_CACHE_HOME:-$HOME/.cache}/sec-watch-local`; user watch configuration
lives at `${XDG_CONFIG_HOME:-$HOME/.config}/sec-watch/watch.json`.

## Local Workflow

- There is no package manager or build step.
- Before handing off shell-script changes, run:

  ```bash
  bash -n bin/sec-watch
  ```

- Before handing off Python CLI changes, run:

  ```bash
  python3 -m py_compile bin/sec-watch-local
  ```

## Testing Notes

- `bin/sec-watch` may call `trivy`, `osv-scanner`, `curl`, `gzip`, and `jq` depending on the environment and selected feeds.
- To avoid touching the real user cache while testing the helper, set a temporary `XDG_CACHE_HOME` and usually `SEC_WATCH_FORCE=1`.
- The helper accepts `status` and `defaults-env`. Unknown commands should exit with status `2`.
- Network-backed feed checks are best treated as integration behavior; keep local validation focused on syntax and deterministic parsing/filtering changes.

## Conventions

- Keep Bash changes portable to Fedora's standard Bash and coreutils.
- Quote paths carefully because project directories can contain spaces.
- Do not commit generated runtime artifacts such as reports, cache files, logs, or Python `__pycache__` directories.
- Keep README user-facing. Put implementation caveats and agent workflow notes here.
