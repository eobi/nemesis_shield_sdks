#!/usr/bin/env bash
# Deterministic behaviour test for the Nemesis Shield WordPress plugin. Starts a
# local mock Shield, runs the plugin's gate/observe logic through it, asserts it
# learns the right shapes and blocks off-baseline requests, then tears down.
# No Docker, no WordPress install needed — just PHP. The Docker e2e (tests/e2e.sh)
# covers the real WordPress path.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
port="${NS_PORT:-8791}"
tmp="$(mktemp -d)"

export NEMESIS_MOCK_POLICY="$tmp/policy.json"
export NEMESIS_MOCK_RECORD="$tmp/record.ndjson"
export NEMESIS_TOKEN="nsk_test_token"
export NEMESIS_ENDPOINT="http://127.0.0.1:$port/api/v1/sketches"
export TMPDIR="$tmp"

: > "$NEMESIS_MOCK_RECORD"
echo '{"mode":"observe","policy":{"shapes":{},"knownBad":[]}}' > "$NEMESIS_MOCK_POLICY"

php -S "127.0.0.1:$port" "$here/tests/mock-shield.php" >/dev/null 2>&1 &
mock=$!
trap 'kill "$mock" 2>/dev/null || true; rm -rf "$tmp"' EXIT

# wait for the mock to accept connections
for _ in $(seq 1 40); do
  if curl -s "http://127.0.0.1:$port/" -d '{}' >/dev/null 2>&1; then break; fi
  sleep 0.1
done

php "$here/tests/run.php"
echo ""
php "$here/tests/login-test.php"
echo ""
php "$here/tests/scanner-test.php"
