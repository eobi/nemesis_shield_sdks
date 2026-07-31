#!/usr/bin/env bash
# Sync the canonical PHP SDK into the plugin's bundled lib/. A WordPress plugin
# must be self-contained (users install just the plugin folder), so we vendor a
# copy of the PHP SDK rather than reference ../php at runtime. Run this whenever
# the PHP SDK changes.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
src="$here/../php"
dst="$here/nemesis-shield/lib"
mkdir -p "$dst"
cp "$src/NemesisShield.php" "$src/NemesisShieldLLM.php" "$src/ml_weights.json" "$dst/"
echo "synced php/ -> $dst"
