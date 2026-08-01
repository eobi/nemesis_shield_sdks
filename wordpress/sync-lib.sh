#!/usr/bin/env bash
# Sync ONLY the shared ML model into the plugin's bundled lib/. The plugin ships its own
# WordPress-native classes (NemesisShieldWP.php, NemesisShieldLLM.php) that use the WP HTTP API and
# Transients instead of the generic PHP SDK's cURL/file I/O, so those are hand-maintained here and are
# NOT copied from ../php. Only ml_weights.json must stay byte-identical to the shared model (the LLM
# classifier's parity depends on it). Run this whenever the shared model changes.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
src="$here/../php"
dst="$here/nemesis-shield/lib"
mkdir -p "$dst"
cp "$src/ml_weights.json" "$dst/"
echo "synced ml_weights.json -> $dst"
