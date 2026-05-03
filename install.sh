#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXTENSION_DIR="$HOME/.local/share/gnome-shell/extensions/sec-watch@local"
BIN_DIR="$HOME/.local/bin"
CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/sec-watch"

mkdir -p "$EXTENSION_DIR/schemas" "$BIN_DIR" "$CONFIG_DIR"

install -m 0644 "$ROOT/extension/extension.js" "$EXTENSION_DIR/extension.js"
install -m 0644 "$ROOT/extension/prefs.js" "$EXTENSION_DIR/prefs.js"
install -m 0644 "$ROOT/extension/metadata.json" "$EXTENSION_DIR/metadata.json"
install -m 0644 "$ROOT/extension/schemas/org.gnome.shell.extensions.sec-watch.gschema.xml" \
  "$EXTENSION_DIR/schemas/org.gnome.shell.extensions.sec-watch.gschema.xml"
install -m 0755 "$ROOT/bin/sec-watch" "$BIN_DIR/sec-watch"

if [[ ! -f "$CONFIG_DIR/watch.json" ]]; then
  install -m 0644 "$ROOT/config/watch.example.json" "$CONFIG_DIR/watch.json"
fi

glib-compile-schemas "$EXTENSION_DIR/schemas"

echo "Installed Security Watch."
echo "Enable with: gnome-extensions enable sec-watch@local"
echo "Open prefs:  gnome-extensions prefs sec-watch@local"

