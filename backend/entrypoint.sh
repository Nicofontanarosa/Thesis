#!/usr/bin/env bash
set -e
PORT="${PORT:-10000}"
# Avvia uvicorn con host 0.0.0.0 sulla porta assegnata
exec uvicorn app:app --host 0.0.0.0 --port "$PORT" --workers 1
