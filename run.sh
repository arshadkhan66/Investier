#!/usr/bin/env bash
# Start the Investier server.
set -e
cd "$(dirname "$0")"
PORT="${PORT:-8000}"
exec python3 -m uvicorn app.main:app --host 0.0.0.0 --port "$PORT" "$@"
