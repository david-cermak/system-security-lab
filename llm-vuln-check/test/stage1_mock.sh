#!/usr/bin/env bash
# Stage 1 with mock backend: six AS*.md + guardrails + AS_FILES ordering.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

export RUN_DIR="$TMP/run"
export AGENT_BACKEND=mock
mkdir -p "$RUN_DIR/logs"

TARGET="$TMP/fake-libssh"
mkdir -p "$TARGET/src"

# shellcheck source=../lib/guardrail.sh
source "$ROOT/lib/guardrail.sh"
# shellcheck source=../lib/agent.sh
source "$ROOT/lib/agent.sh"
# shellcheck source=../lib/stages.sh
source "$ROOT/lib/stages.sh"

echo "== stage_attack_surface (mock)"
stage_attack_surface "$TARGET"

shopt -s nullglob
paths=("$RUN_DIR/AS/AS"*.md)
shopt -u nullglob
((${#paths[@]} == 6)) || {
	echo "expected 6 AS*.md, got ${#paths[@]}" >&2
	exit 1
}

[[ "${AS_FILES[*]}" == "AS1.md AS2.md AS3.md AS4.md AS5.md AS6.md" ]] || {
	echo "unexpected AS_FILES: ${AS_FILES[*]}" >&2
	exit 1
}

echo "== expected primary paths from README stage-1 bullets"
declare -A seen=()
for key in \
	hybrid_mlkem.c \
	sftp.c \
	sftpserver.c \
	pki.c \
	pki_sk.c \
	kex-gss.c; do
	seen[$key]=0
done

for f in "${paths[@]}"; do
	for key in "${!seen[@]}"; do
		if grep -q "$key" "$f"; then
			seen[$key]=1
		fi
	done
done

for key in "${!seen[@]}"; do
	((${seen[$key]} == 1)) || {
		echo "no AS file mentions expected path fragment: $key" >&2
		exit 1
	}
done

grep -q '\[mock\]' "$RUN_DIR/logs/stage1_attack_surface.log"

echo "OK: stage1 mock tests passed"
