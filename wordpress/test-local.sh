#!/usr/bin/env bash
# Launch a REAL WordPress locally with the Nemesis Shield plugin already active, so you can click
# through the settings screen, test with your real install token, and run the Plugin Check plugin.
#
# No Docker and no MySQL: this uses wp-now (WordPress Playground) with a bundled SQLite database.
# The first run downloads WordPress core. Press Ctrl-C to stop; state is discarded on exit.
#
# Needs Node (npx). For the automated real-WordPress + MariaDB test instead, use ./tests/e2e.sh.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"

if ! command -v npx >/dev/null 2>&1; then
  echo "npx (Node.js) is required. Install Node, or use the Docker path: ./tests/e2e.sh" >&2
  exit 1
fi

cat <<'NOTE'
Starting a local WordPress with Nemesis Shield mounted (wp-now + SQLite)…

Once it prints a URL (usually http://localhost:8881):
  1. Open the URL and log in (wp-now auto-creates admin / password).
  2. Settings -> Nemesis Shield: paste your install token from https://shield.nemesislabs.xyz
     (or leave it blank to just exercise the UI). Browse the site to generate observed behaviors.
  3. Run Plugin Check: Plugins -> Add New -> search "Plugin Check" -> install + activate,
     then Tools -> Plugin Check -> select "Nemesis Shield" -> Check it.

Press Ctrl-C to stop.
NOTE

cd "$here/nemesis-shield"   # run from the plugin dir so wp-now mounts it as a plugin

# wp-now is being superseded by @wp-playground/cli. wp-now still works and is the simplest (run from a
# plugin dir and it mounts + activates the plugin); set NS_PLAYGROUND=1 to use the newer CLI instead.
if [ "${NS_PLAYGROUND:-0}" = "1" ]; then
  exec npx --yes @wp-playground/cli@latest server --mount="$here/nemesis-shield:/wordpress/wp-content/plugins/nemesis-shield" --plugin=nemesis-shield
fi
exec npx --yes @wp-now/wp-now start
