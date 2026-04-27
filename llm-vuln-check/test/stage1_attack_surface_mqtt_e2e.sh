#!/usr/bin/env bash
# E2E: stage 1 (attack surface) with real agent (default AGENT_BACKEND=opencode) against
# mqtt-mini-client. Requires `opencode` on PATH and network/credentials as your opencode install
# needs. Skips with exit 0 when opencode is missing unless LLM_VULN_REQUIRE_OPENCODE=1.
#
# Validates: pipeline guardrails on each AS*.md + combined content vs
# test/expected/mqtt-mini-client/stage1_as_combined.regex (planted vulns from VULNS.md).
#
# Optional: MODEL_AS=provider/model, RUN_DIR=fixed dir, same as run.sh.
#
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SPEC="$ROOT/test/expected/mqtt-mini-client/stage1_as_combined.regex"
MQTT="$(cd "$ROOT/../mqtt-mini-client" && pwd)"

if [[ ! -d "$MQTT" || ! -f "$MQTT/mqtt_client.cpp" ]]; then
	echo "missing mqtt-mini-client at $MQTT (expected sibling of llm-vuln-check)" >&2
	exit 1
fi

if ! command -v opencode >/dev/null 2>&1; then
	if [[ "${LLM_VULN_REQUIRE_OPENCODE:-}" == 1 ]]; then
		echo "LLM_VULN_REQUIRE_OPENCODE=1 but opencode not in PATH" >&2
		exit 1
	fi
	echo "skip: opencode not in PATH (set LLM_VULN_REQUIRE_OPENCODE=1 to fail instead of skip)"
	exit 0
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

export RUN_DIR="${RUN_DIR:-$TMP/run}"
export AGENT_BACKEND="${AGENT_BACKEND:-opencode}"
# Empty MODEL_AS lets opencode pick its configured default (avoids invalid short slugs).
export MODEL_AS="${MODEL_AS-}"
mkdir -p "$RUN_DIR/logs"

echo "== stage1 E2E: target=$MQTT RUN_DIR=$RUN_DIR AGENT_BACKEND=$AGENT_BACKEND"
"$ROOT/run.sh" stage1 "$MQTT"

shopt -s nullglob
as_paths=("$RUN_DIR/AS/AS"*.md)
shopt -u nullglob
((${#as_paths[@]} >= 2)) || {
	echo "expected at least 2 AS*.md for non-trivial coverage, got ${#as_paths[@]}" >&2
	exit 1
}

combined="$TMP/combined_as.md"
: >"$combined"
for f in "${as_paths[@]}"; do
	printf '\n\n### %s\n\n' "$(basename "$f")" >>"$combined"
	cat "$f" >>"$combined"
done

echo "== combined expectations: $SPEC"
local_line=0
while IFS= read -r line || [[ -n "$line" ]]; do
	((++local_line))
	trimmed="${line#"${line%%[![:space:]]*}"}"
	[[ -z "$trimmed" ]] && continue
	[[ "$trimmed" == \#* ]] && continue
	if ! grep -E -q "$trimmed" "$combined"; then
		echo "combined AS output did not match required pattern (line $local_line of spec): $trimmed" >&2
		exit 1
	fi
done <"$SPEC"

echo "OK: stage1_attack_surface_mqtt_e2e (${#as_paths[@]} AS files, opencode)"
