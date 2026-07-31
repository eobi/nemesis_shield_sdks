#!/usr/bin/env bash
# LIVE cross-language CVE demo (deep). Starts a mock Shield + four REAL app servers
# (Python/PHP/Go/Node), each guarded by its Nemesis Shield SDK. Learns an 8-route baseline from real
# traffic, flips to enforce, then over real HTTP proves:
#   • SPECIFICITY  — a false-positive battery of legit variation still passes (200)
#   • COVERAGE     — a large CVE-pattern attack corpus is blocked (403) on every app
#   • GLOBAL INTEL — a knownBad shape is blocked with reason "global threat intelligence"
#   • SAFE-UNLOCK  — the login/admin break-glass paths pass through even though off-baseline
# One learned baseline defends all four languages (cross-language shape parity).
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
tmp="$(mktemp -d)"

export NEMESIS_TOKEN="nsk_demo"
export NEMESIS_ENDPOINT="http://127.0.0.1:8800/api/v1/sketches"
export NEMESIS_MOCK_POLICY="$tmp/policy.json"
export NEMESIS_MOCK_RECORD="$tmp/record.ndjson"
: > "$NEMESIS_MOCK_RECORD"
echo '{"mode":"observe","policy":{"shapes":{},"knownBad":[]}}' > "$NEMESIS_MOCK_POLICY"

pids=()
cleanup() { for p in "${pids[@]:-}"; do kill "$p" 2>/dev/null; done; rm -rf "$tmp"; }
trap cleanup EXIT

echo "▸ building the Go demo app…"
( cd "$here/goapp" && GOPROXY=off GOFLAGS=-mod=mod go build -o app . ) || { echo "go build failed"; exit 1; }

echo "▸ starting mock Shield + 4 real app servers…"
php -S 127.0.0.1:8800 "$here/mock-shield.php" >/dev/null 2>&1 & pids+=($!)
PORT=8801 python3 "$here/app_python.py"           >/dev/null 2>&1 & pids+=($!)
php -S 127.0.0.1:8802 "$here/app_php.php"          >/dev/null 2>&1 & pids+=($!)
PORT=8803 "$here/goapp/app"                        >/dev/null 2>&1 & pids+=($!)
PORT=8804 node "$here/app_node.mjs"                >/dev/null 2>&1 & pids+=($!)

APPS=("python:8801" "php:8802" "go:8803" "node:8804")

st()   { local m="$1" p="$2" a="$3" port="$4"; local args=(-s -o /dev/null -w '%{http_code}' -X "$m"); [ "$a" = "1" ] && args+=(-H "Authorization: Bearer x"); curl "${args[@]}" "http://127.0.0.1:$port$p" 2>/dev/null || echo 000; }
body() { local m="$1" p="$2" a="$3" port="$4"; local args=(-s -X "$m"); [ "$a" = "1" ] && args+=(-H "Authorization: Bearer x"); curl "${args[@]}" "http://127.0.0.1:$port$p" 2>/dev/null; }

echo -n "▸ waiting for apps"
for ap in "${APPS[@]}"; do port="${ap#*:}"; for _ in $(seq 1 50); do [ "$(st GET / 0 "$port")" != "000" ] && break; sleep 0.2; done; echo -n " ${ap%%:*}✓"; done
echo

# ---- learn the baseline (8 routes) on every app, in observe mode ---------------------------------
echo "▸ learning an 8-route baseline from real traffic (observe mode)…"
LEARN=(
  "GET|/|0" "GET|/products/12345|0" "GET|/products/12345/reviews|0"
  "GET|/search?q=shoes|0" "GET|/catalog?category=men&page=2|0"
  "GET|/users/3f2504e0-4f89-11d3-9a0c-0305e82c3301|0"
  "POST|/api/orders|1" "GET|/account|1"
)
for ap in "${APPS[@]}"; do port="${ap#*:}"; for _ in 1 2; do for r in "${LEARN[@]}"; do IFS='|' read -r m p a <<<"$r"; st "$m" "$p" "$a" "$port" >/dev/null; done; done; done
sleep 3

shapes=$(grep -o '"shape":"[0-9a-f]*"' "$NEMESIS_MOCK_RECORD" | sed 's/.*:"//;s/"//' | sort -u)
allow="{"; sep=""; for s in $shapes; do allow="$allow$sep\"$s\":\"allow\""; sep=","; done; allow="$allow}"
# a knownBad shape (global threat intel) for POST /xmlrpc.php — never in this app's baseline
KB=$(node --input-type=module -e "import {buildSketch} from '$root/node/lib/shape.js'; process.stdout.write(buildSketch({method:'POST',path:'/xmlrpc.php'}).shape)")
echo "  approved $(echo "$shapes" | grep -c .) baseline shapes; 1 knownBad shape ($KB) added to global intel"

echo "{\"mode\":\"enforce\",\"policy\":{\"shapes\":$allow,\"knownBad\":[\"$KB\"]}}" > "$NEMESIS_MOCK_POLICY"
echo "▸ flipped to ENFORCE — waiting for all apps to pull the policy…"
sleep 3

# ---- test matrix: "kind|method|path|auth|label"  (SECTION|title for headers) ---------------------
# kind: legit/unlock => expect 200 · attack/knownbad => expect 403
ROWS=(
  "SECTION|SPECIFICITY — legit variation must PASS (200)"
  "legit|GET|/|0|GET / (home)"
  "legit|GET|/products/42|0|GET /products/42  (diff id)"
  "legit|GET|/products/987654/reviews|0|GET /products/{int}/reviews"
  "legit|GET|/search?q=boots|0|GET /search?q=boots  (diff value)"
  "legit|GET|/catalog?category=women&page=5|0|GET /catalog?category&page  (diff values)"
  "legit|GET|/catalog?page=3&category=kids|0|GET /catalog  (param order swapped)"
  "legit|GET|/users/550e8400-e29b-41d4-a716-446655440000|0|GET /users/{uuid}  (diff uuid)"
  "legit|POST|/api/orders|1|POST /api/orders  (authed)"
  "legit|GET|/account|1|GET /account  (authed)"

  "SECTION|EXPOSURE / FORCED BROWSING — block (403)"
  "attack|GET|/.env|0|/.env  secret-file exposure"
  "attack|GET|/.git/config|0|/.git/config  source leak"
  "attack|GET|/wp-config.php.bak|0|/wp-config.php.bak"
  "attack|GET|/.aws/credentials|0|/.aws/credentials"
  "attack|GET|/.ssh/id_rsa|0|/.ssh/id_rsa"
  "attack|GET|/phpmyadmin/|0|/phpmyadmin/"
  "attack|GET|/server-status|0|/server-status (Apache)"
  "attack|GET|/backup.zip|0|/backup.zip"

  "SECTION|PATH TRAVERSAL / LFI — block (403)"
  "attack|GET|/cgi-bin/.%2e/.%2e/etc/passwd|0|traversal (CVE-2021-41773)"
  "attack|GET|/%2e%2e%2f%2e%2e%2fetc%2fpasswd|0|encoded ../../etc/passwd"
  "attack|GET|/..%252f..%252fetc%252fpasswd|0|double-encoded (CVE-2021-42013)"
  "attack|GET|/catalog?category=../../../../etc/passwd&page=2|0|LFI via param value"

  "SECTION|KNOWN-CVE APP ENDPOINTS — block (403)"
  "attack|GET|/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php|0|PHPUnit RCE (CVE-2017-9841)"
  "attack|GET|/_ignition/execute-solution|0|Laravel Ignition (CVE-2021-3129)"
  "attack|GET|/solr/admin/cores|0|Apache Solr admin"
  "attack|GET|/manager/html|0|Tomcat manager"
  "attack|GET|/actuator/heapdump|0|Spring Actuator heapdump"
  "attack|GET|/wp-json/wp/v2/users|0|WP REST user-enum"
  "attack|GET|/api/jsonws/invoke|0|Liferay (CVE-2020-7961)"
  "attack|GET|/telescope/requests|0|Laravel Telescope leak"

  "SECTION|INJECTION PAYLOADS (path/param) — block (403)"
  "attack|GET|/?author=1|0|WordPress user-enum ?author=1"
  "attack|GET|/search?q=%27+OR+1%3D1--|0|SQLi in param (kind change)"
  "attack|GET|/search?q=x&cmd=id|0|param injection (extra param)"
  "attack|GET|/products/1%27+OR+%271%27%3D%271|0|SQLi in path segment"
  "attack|GET|/catalog?category=men&page=2&debug=1|0|extra param on known route"
  "attack|GET|/search?q=%3Cscript%3Ealert(1)%3C/script%3E|0|XSS payload (kind change)"
  "attack|GET|/?x=%24%7Bjndi%3Aldap%3A//x%7D|0|Log4Shell in query param"
  "attack|GET|/%24%7Bjndi%3Aldap%3A//x%7D|0|Log4Shell in path"
  "attack|GET|/?redirect=http%3A%2F%2F169.254.169.254%2F|0|SSRF param (metadata)"

  "SECTION|METHOD / AUTH ANOMALIES — block (403)"
  "attack|DELETE|/|0|HTTP method tampering (DELETE /)"
  "attack|PUT|/products/1|0|HTTP method tampering (PUT)"
  "attack|GET|/api/orders|0|broken auth (unauth → authed route)"
  "attack|GET|/account|0|broken auth (unauth → /account)"
  "attack|GET|/users/1|0|IDOR (int where uuid learned)"

  "SECTION|GLOBAL THREAT INTEL (knownBad) — block (403)"
  "knownbad|POST|/xmlrpc.php|0|POST /xmlrpc.php  (knownBad shape)"

  "SECTION|SAFE-UNLOCK break-glass — pass through (200)"
  "unlock|POST|/login|0|/login  (never blocked)"
  "unlock|GET|/wp-login.php|0|/wp-login.php  (never blocked)"
  "unlock|GET|/wp-admin/options.php|0|/wp-admin  (never blocked)"
)

printf "\n\033[1m%-44s %-7s %-7s %-7s %-7s\033[0m\n" "request" "python" "php" "go" "node"
pass=0; fail=0
for row in "${ROWS[@]}"; do
  if [[ "$row" == SECTION\|* ]]; then
    printf "\033[1;36m── %s\033[0m\n" "${row#SECTION|}"; continue
  fi
  IFS='|' read -r kind m p a label <<< "$row"
  want=200; [[ "$kind" == attack || "$kind" == knownbad ]] && want=403
  line=$(printf "%-44s" "$label")
  for ap in "${APPS[@]}"; do
    code=$(st "$m" "$p" "$a" "${ap#*:}")
    if [ "$code" = "$want" ]; then mark="\033[32m✓$code\033[0m"; pass=$((pass+1)); else mark="\033[31m✗$code\033[0m"; fail=$((fail+1)); fi
    line="$line $(printf '%-15b' "$mark")"
  done
  echo -e "$line"
done

# ---- reason inspection: off-baseline vs global-intel (deeper than status codes) ------------------
echo -e "\n\033[1;36m── REASON inspection (why it blocked)\033[0m"
r_off=$(body GET /.env 0 8802 | sed -n 's/.*"reason":"\([^"]*\)".*/\1/p')
r_kb=$(body POST /xmlrpc.php 0 8802 | sed -n 's/.*"reason":"\([^"]*\)".*/\1/p')
echo "  /.env         → \"$r_off\""
echo "  /xmlrpc.php   → \"$r_kb\""
[ "$r_off" = "off-baseline: unapproved behavior" ] && { echo "  ✓ off-baseline reason correct"; pass=$((pass+1)); } || { echo "  ✗ off-baseline reason"; fail=$((fail+1)); }
[ "$r_kb" = "global threat intelligence" ] && { echo "  ✓ knownBad reason correct (global threat intelligence)"; pass=$((pass+1)); } || { echo "  ✗ knownBad reason"; fail=$((fail+1)); }

echo
echo "──────────────────────────────────────────────────────────────────────────────"
tot=$((pass+fail))
if [ "$fail" -eq 0 ]; then
  echo -e "\033[32m\033[1mALL $tot LIVE CHECKS PASSED\033[0m"
  echo "specificity (legit passes) · coverage (attacks blocked) · global intel · safe-unlock — on 4 real apps"
else
  echo -e "\033[31m\033[1m$fail/$tot FAILED\033[0m, $pass passed"
fi
exit $([ "$fail" -eq 0 ] && echo 0 || echo 1)
