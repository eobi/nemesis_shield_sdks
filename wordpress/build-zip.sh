#!/usr/bin/env bash
# Build the distributable Nemesis Shield plugin zip for WordPress.org review upload.
# Contains ONLY the runtime plugin folder (nemesis-shield/) — never tests, Docker,
# dev scripts, or the assets/ folder (assets are committed to SVN /assets/, not the zip).
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
slug="nemesis-shield"
ver="$(grep -m1 'Stable tag:' "$here/$slug/readme.txt" | sed -E 's/.*Stable tag:[[:space:]]*//')"
out="$here/${slug}.zip"

# Re-sync the vendored PHP SDK so the shipped lib matches ../php exactly.
if [ -x "$here/sync-lib.sh" ]; then "$here/sync-lib.sh" >/dev/null 2>&1 || true; fi

rm -f "$out"
# Zip the plugin dir at repo-relative path so the archive expands to nemesis-shield/…
( cd "$here" && zip -rq "$out" "$slug" \
    -x "$slug/tests/*" \
    -x "*/.DS_Store" \
    -x "*/.git/*" )

echo "built $out  (v$ver)"
unzip -l "$out" | sed -n '1,40p'
