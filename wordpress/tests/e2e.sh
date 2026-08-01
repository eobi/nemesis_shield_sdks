#!/usr/bin/env bash
# End-to-end test of the Nemesis Shield plugin inside a REAL WordPress, over real
# HTTP: install WP → activate the plugin → learn in observe mode → approve the
# learned shapes → flip to enforce → confirm approved traffic passes and
# off-baseline / scanner requests get a 403 blocked_by_nemesis_shield.
#
# Requires Docker. Run from the wordpress/ dir:  ./tests/e2e.sh
set -euo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"
cd "$here"

BASE="http://localhost:8080"
SHARED="$here/tests/.e2e"
# Shape oracle = the canonical PHP SDK (pure buildSketch, no WP funcs). The plugin ships WP-native
# classes, but their shape math is byte-identical to this, so it is the right oracle.
SDK="$here/../php/NemesisShield.php"
dc() { docker compose "$@"; }
wpcli() { docker compose run --rm -T wpcli wp "$@"; }

# --- shape oracle: compute the exact shape the plugin will report for a request
shape_of() { php -r 'require $argv[1]; echo NemesisShield::buildSketch($argv[2],$argv[3],[],false,0)["shape"];' "$SDK" "$1" "$2"; }
set_policy() { # mode  [shape=allow ...]  as a JSON policy file the mock serves
  local mode="$1"; shift
  local shapes="{}"
  if [ "$#" -gt 0 ]; then
    shapes="{"; local sep=""
    for s in "$@"; do shapes="$shapes$sep\"$s\":\"allow\""; sep=","; done
    shapes="$shapes}"
  fi
  printf '{"mode":"%s","policy":{"shapes":%s,"knownBad":[]}}' "$mode" "$shapes" > "$SHARED/policy.json"
}
# The plugin caches the compiled policy in a WordPress transient (2s TTL). Clear it via wp-cli so a
# policy change (observe -> enforce) takes effect immediately instead of waiting out the TTL.
clear_sdk_cache() { wpcli transient delete --all >/dev/null 2>&1 || true; }
status_of() { curl -s -o /dev/null -w '%{http_code}' "$BASE$1"; }

pass=0; fail=0
ok() { if [ "$1" = "$2" ]; then pass=$((pass+1)); echo "  ✓ $3 (got $1)"; else fail=$((fail+1)); echo "  ✗ $3 (expected $2, got $1)"; fi; }

echo "▸ booting WordPress + MariaDB + mock Shield…"
mkdir -p "$SHARED"; : > "$SHARED/record.ndjson"; set_policy observe
dc up -d db wp mock

echo "▸ waiting for WordPress…"
for _ in $(seq 1 60); do
  code="$(curl -s -o /dev/null -w '%{http_code}' "$BASE/" || true)"
  [ "$code" != "000" ] && break; sleep 2
done

echo "▸ installing WordPress + activating the plugin…"
wpcli core install --url="$BASE" --title="Nemesis E2E" \
  --admin_user=admin --admin_password=admin --admin_email=admin@example.com --skip-email >/dev/null
wpcli rewrite structure '/%postname%/' >/dev/null
wpcli plugin activate nemesis-shield >/dev/null
echo "  plugin: $(wpcli plugin get nemesis-shield --field=status)"

echo ""
echo "▸ 1 · learn (observe mode)"
set_policy observe; clear_sdk_cache
for p in "/" "/?page_id=2" "/sample-page/"; do status_of "$p" >/dev/null; done
sleep 1
n="$(grep -c . "$SHARED/record.ndjson" 2>/dev/null || echo 0)"
ok "$([ "$n" -ge 3 ] && echo ok || echo no)" "ok" "observed ≥3 requests ($n sketches recorded)"
grep -q '"route":"\\/sample-page\\/"' "$SHARED/record.ndjson" && echo "  ✓ learned route /sample-page/" || echo "  · (route detail)"

echo ""
echo "▸ 2 · enforce"
S_HOME="$(shape_of GET /)"
S_PAGE="$(shape_of GET /sample-page/)"
set_policy enforce "$S_HOME" "$S_PAGE"; clear_sdk_cache
ok "$(status_of '/')" "200" "approved GET / passes"
ok "$(status_of '/sample-page/')" "200" "approved GET /sample-page/ passes"
ok "$(status_of '/wp-config.php.bak')" "403" "scanner probe /wp-config.php.bak blocked"
ok "$(status_of '/nemesis-scan-xyz')" "403" "off-baseline path blocked"
body="$(curl -s "$BASE/nemesis-scan-xyz")"
echo "$body" | grep -q blocked_by_nemesis_shield && echo "  ✓ 403 body is blocked_by_nemesis_shield" || echo "  ✗ block body"

echo ""
echo "▸ 3 · fail-open (mock down)"
dc stop mock >/dev/null 2>&1; clear_sdk_cache
foc="$(status_of '/nemesis-scan-xyz')" # reaches WP (404), the point is it is NOT blocked (403)
if [ "$foc" != "403" ]; then pass=$((pass+1)); echo "  ✓ off-baseline reaches WP, not blocked, when Shield is unreachable (got $foc)";
else fail=$((fail+1)); echo "  ✗ still blocked with Shield down (got $foc)"; fi
dc start mock >/dev/null 2>&1

echo ""
echo "────────────────────────────────────"
if [ "$fail" -eq 0 ]; then echo "ALL $pass E2E CHECKS PASSED"; else echo "$fail FAILED, $pass passed"; fi
echo "(teardown: docker compose down -v)"
[ "$fail" -eq 0 ]
