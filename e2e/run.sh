#!/usr/bin/env bash
# Build every language container and run parity + live round-trip in each, collecting per-service logs.
#
# Token: supply the disposable test-app bearer token either as $NEMESIS_TOKEN, or point
#        $NEMESIS_TOKEN_FILE at a file whose SECOND line is the token. It is passed to the
#        containers via the environment only - never baked into an image or committed.
#
# Usage:  ./run.sh              # build + run all services
#         ./run.sh node python  # build + run only the named services
set -uo pipefail
cd "$(dirname "$0")"

if [ -z "${NEMESIS_TOKEN:-}" ] && [ -n "${NEMESIS_TOKEN_FILE:-}" ]; then
  NEMESIS_TOKEN="$(sed -n '2p' "$NEMESIS_TOKEN_FILE")"
fi
if [ -z "${NEMESIS_TOKEN:-}" ]; then
  echo "ERROR: set NEMESIS_TOKEN or NEMESIS_TOKEN_FILE (token on line 2)." >&2
  exit 2
fi
export NEMESIS_TOKEN

SERVICES=("$@")
mkdir -p results

echo ">> building images..."
docker compose build "${SERVICES[@]}" || { echo "build failed"; exit 1; }

echo ">> running containers..."
# Run each service to completion, capturing its combined log.
if [ ${#SERVICES[@]} -eq 0 ]; then
  SERVICES=(node python ruby go rust php java dotnet)
fi
for svc in "${SERVICES[@]}"; do
  echo "==================== $svc ===================="
  docker compose run --rm "$svc" 2>&1 | tee "results/$svc.log"
done

echo ">> done. per-service logs in e2e/results/"
