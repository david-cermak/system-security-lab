#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

make -s

HOST="${MQTT_HOST:-127.0.0.1}"
PORT="${MQTT_PORT:-1883}"
TOPIC="${MQTT_TOPIC:-mqtt_mini_selftest/$(date +%s)}"
MSG="${MQTT_MSG:-hello-from-mini-client}"

OUT="$(mktemp)"
trap 'rm -f "$OUT"' EXIT

"$ROOT/mqtt_sub" -h "$HOST" -p "$PORT" -t "$TOPIC" >"$OUT" 2>&1 &
SUB_PID=$!

sleep 0.4

"$ROOT/mqtt_pub" -h "$HOST" -p "$PORT" -t "$TOPIC" -m "$MSG"

sleep 0.6
kill -TERM "$SUB_PID" 2>/dev/null || true
wait "$SUB_PID" 2>/dev/null || true

if ! grep -Fxq "$MSG" "$OUT"; then
  echo "expected payload line '$MSG' on stdout, got:" >&2
  cat "$OUT" >&2
  exit 1
fi

echo "ok: pub/sub exchanged '$MSG' on topic '$TOPIC'"
