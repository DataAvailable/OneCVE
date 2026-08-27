#!/usr/bin/env bash
set -Eeuo pipefail

api_pid=""
web_pid=""

shutdown() {
    if [[ -n "$api_pid" ]]; then
        kill -TERM "$api_pid" 2>/dev/null || true
    fi
    if [[ -n "$web_pid" ]]; then
        kill -TERM "$web_pid" 2>/dev/null || true
    fi
    wait 2>/dev/null || true
}
trap shutdown TERM INT EXIT

cd /app
python -m uvicorn nspa.webapp.api:app --host 0.0.0.0 --port 8000 &
api_pid=$!

cd /app/web
node node_modules/vinext/dist/cli.js start --hostname 0.0.0.0 --port 3000 &
web_pid=$!

wait -n "$api_pid" "$web_pid"
status=$?
exit "$status"
