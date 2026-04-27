#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"

usage() {
	echo "usage: run.sh m1-smoke" >&2
	echo "       run.sh stage1 <target-source-dir>" >&2
	echo "       run.sh audit-one <run-dir> <AS-basename>   # e.g. AS1.md (stage 2, one surface)" >&2
	echo "       RUN_DIR=/path/to/run ./run.sh m1-smoke   # optional fixed run directory" >&2
	exit 1
}

cmd="${1:-}"
[[ "$cmd" == m1-smoke || "$cmd" == stage1 || "$cmd" == audit-one ]] || usage

RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
RUN_DIR="${RUN_DIR:-$ROOT/runs/$RUN_ID}"
export RUN_DIR

# shellcheck source=lib/agent.sh
source "$ROOT/lib/agent.sh"
# shellcheck source=lib/stages.sh
source "$ROOT/lib/stages.sh"

if [[ "$cmd" == audit-one ]]; then
	RUN_DIR_ARG="${2:?usage: run.sh audit-one <run-dir> <AS-basename>}"
	AS_BASENAME="${3:?usage: run.sh audit-one <run-dir> <AS-basename>}"
	if [[ "$RUN_DIR_ARG" == /* ]]; then
		RUN_DIR="$RUN_DIR_ARG"
	else
		RUN_DIR="$ROOT/$RUN_DIR_ARG"
	fi
	RUN_DIR="$(cd "$RUN_DIR" && pwd)"
	export RUN_DIR
	mkdir -p "$RUN_DIR/reports" "$RUN_DIR/logs"
	# MODEL_AUDIT unset → opencode uses its configured default (provider/model).
	# Set e.g. MODEL_AUDIT=anthropic/claude-sonnet-4-20250514 to override.
	: "${MODEL_AUDIT:=}"
	stage_audit_surface_one "$AS_BASENAME"
	echo "Done. Report: $RUN_DIR/reports/Report_${AS_BASENAME}  log: $RUN_DIR/logs/audit_${AS_BASENAME%.md}.log"
	exit 0
fi

if [[ "$cmd" == m1-smoke ]]; then
	mkdir -p "$RUN_DIR/logs"
	stage_m1_smoke "$ROOT"
	echo "Done. Output: $RUN_DIR/smoke.md  log: $RUN_DIR/logs/m1_smoke.log"
	exit 0
fi

TARGET="${2:?usage: run.sh stage1 <target-source-dir>}"
mkdir -p "$RUN_DIR"/{AS,reports,assessments,logs}
# Unset → default slug; empty string → opencode CLI default (-m omitted). See lib/backends/opencode.sh.
MODEL_AS="${MODEL_AS-claude-sonnet-4}"
stage_attack_surface "$TARGET"
echo "Done. AS directory: $RUN_DIR/AS"
printf '  %s\n' "${AS_FILES[@]}"
