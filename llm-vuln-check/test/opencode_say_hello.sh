#!/usr/bin/env bash
# Integration check: `opencode run` with default model prints a greeting (hello/hi).
#
# Skips (exit 0) when `opencode` is not on PATH.
# Optional: OPENCODE_TEST_MODEL=provider/model to override the default.
#
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP"

if ! command -v opencode >/dev/null 2>&1; then
	echo "skip: opencode not in PATH"
	exit 0
fi

OUT="$TMP/out.txt"
cd "$ROOT"

run_args=(run --dir "$TMP")
if [[ -n "${OPENCODE_TEST_MODEL:-}" ]]; then
	run_args+=(-m "$OPENCODE_TEST_MODEL")
fi
run_args+=("say hello")

set +e
opencode "${run_args[@]}" >"$OUT" 2>&1
ec=$?
set -e

if [[ "$ec" -ne 0 ]]; then
	echo "opencode run failed (exit $ec). Output:" >&2
	cat "$OUT" >&2
	exit "$ec"
fi

if ! grep -Eiq '(hello|\bhi\b)' "$OUT"; then
	echo "expected output to contain hello or hi; got:" >&2
	cat "$OUT" >&2
	exit 1
fi

echo "OK: opencode_say_hello (output matches hello|hi)"
