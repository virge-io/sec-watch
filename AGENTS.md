# Codex Notes

## Project Shape

Security Watch is a local Fedora/GNOME Shell 50 project with two main parts:

- `extension/`: GNOME Shell extension UI, preferences, metadata, and GSettings schema.
- `bin/sec-watch`: Bash scanner/helper that emits Argos-style menu output plus `status` and `lockfiles` modes.

The extension invokes `~/.local/bin/sec-watch`, which is installed by `install.sh`. Runtime reports and scan state are written under `${XDG_CACHE_HOME:-$HOME/.cache}/sec-watch`; user watch configuration lives at `${XDG_CONFIG_HOME:-$HOME/.config}/sec-watch/watch.json`.

## Local Workflow

- There is no package manager or general build step in this repo.
- After editing `extension/schemas/org.gnome.shell.extensions.sec-watch.gschema.xml`, run:

  ```bash
  glib-compile-schemas extension/schemas
  ```

- Before handing off shell-script changes, run:

  ```bash
  bash -n install.sh bin/sec-watch bin/sec-watch-dev-shell
  ```

- For a local install/reload cycle on X11, use:

  ```bash
  ./install.sh
  gnome-extensions disable sec-watch@local
  gnome-extensions enable sec-watch@local
  ```

- For extension code changes on Wayland, prefer:

  ```bash
  bin/sec-watch-dev-shell
  ```

  The helper enables `sec-watch@local` inside the nested D-Bus session. GJS
  cannot unload already-imported extension modules, and Wayland sessions cannot
  restart the logged-in GNOME Shell process. On Fedora GNOME 49+,
  `gnome-shell --devkit` may require the `mutter-devel` package.

## Testing Notes

- `bin/sec-watch` may call `dnf5`, `dnf`, `trivy`, `osv-scanner`, `curl`, `gzip`, and `jq` depending on the environment and selected feeds.
- To avoid touching the real user cache while testing the helper, set a temporary `XDG_CACHE_HOME` and usually `SEC_WATCH_FORCE=1`.
- The helper accepts `argos`, `status`, and `lockfiles`. Unknown commands should exit with status `2`.
- Network-backed feed checks are best treated as integration behavior; keep local validation focused on syntax, schema compilation, and deterministic parsing/filtering changes.

## Conventions

- Keep Bash changes portable to Fedora's standard Bash and coreutils. Quote paths carefully because project directories can contain spaces.
- Preserve the existing GJS style in `extension/*.js`: ES modules, 4-space indentation, semicolons, and GNOME Shell 50 APIs.
- Do not commit generated runtime artifacts such as reports, cache files, logs, or `extension/schemas/gschemas.compiled`.
- Keep README user-facing. Put implementation caveats and agent workflow notes here.
