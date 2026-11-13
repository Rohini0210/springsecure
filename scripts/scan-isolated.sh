#!/usr/bin/env bash
# SpringSecure — scan in a disposable environment (v1.0.1).
#
# Starts the throwaway stack from docker-compose.yml, runs the scanner
# against it, then destroys the stack AND its volumes, so one scan cannot
# influence the next (no leftover database rows, no reused state).
#
# Usage:
#   scripts/scan-isolated.sh [target] [base-url]
#     target   — file or directory to scan (default: ./examples)
#     base-url — base URL of the running app (default: http://localhost:8080)
#
# Requires: docker (with `docker compose`). If Docker is not installed this
# script exits with a clear error instead of pretending to run.
# The stack is destroyed even if the scan fails (trap on EXIT).

set -euo pipefail

cd "$(dirname "$0")/.."

TARGET="${1:-./examples}"
BASE_URL="${2:-http://localhost:8080}"

if ! command -v docker >/dev/null 2>&1; then
    echo "error: docker is not installed; cannot start the disposable stack." >&2
    echo "Install Docker, or run the scan directly: node cli.js \"$TARGET\" --url \"$BASE_URL\" -f json -o results/scan.json" >&2
    exit 1
fi

cleanup() {
    echo "Destroying disposable stack and volumes..."
    docker compose down -v
}
trap cleanup EXIT

echo "Starting disposable stack..."
docker compose up -d

echo "Waiting for the app to become healthy..."
for _ in $(seq 1 60); do
    if curl -fsS "${BASE_URL}/health" >/dev/null 2>&1; then
        echo "App is up at ${BASE_URL}."
        break
    fi
    sleep 1
done
curl -fsS "${BASE_URL}/health" >/dev/null || {
    echo "error: app did not become healthy at ${BASE_URL} within 60s." >&2
    docker compose logs
    exit 1
}

mkdir -p results
echo "Scanning ${TARGET} (dynamic verification against ${BASE_URL})..."
node cli.js "$TARGET" --url "$BASE_URL" -f json -o results/scan.json

echo "Scan complete: results/scan.json"
# trap destroys the stack and its volumes on exit.
