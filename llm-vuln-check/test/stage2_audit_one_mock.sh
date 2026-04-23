#!/usr/bin/env bash
# Stage 2 (single AS) with mock backend: Report_AS*.md + report guardrail.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RUN_SAMPLE="$ROOT/runs/20260423T104429Z"
export AGENT_BACKEND=mock

[[ -f "$RUN_SAMPLE/AS/AS1.md" ]] || {
	echo "missing fixture: $RUN_SAMPLE/AS/AS1.md" >&2
	exit 1
}

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
RUN_DIR="$TMP/run"
mkdir -p "$RUN_DIR/AS" "$RUN_DIR/reports" "$RUN_DIR/logs"
cp "$RUN_SAMPLE/AS/AS1.md" "$RUN_DIR/AS/AS1.md"
export RUN_DIR

# shellcheck source=../lib/guardrail.sh
source "$ROOT/lib/guardrail.sh"

echo "== audit-one AS1.md (mock), surface copied from $RUN_SAMPLE/AS/AS1.md"
(
	cd "$ROOT"
	./run.sh audit-one "$RUN_DIR" AS1.md
)

REPORT="$RUN_DIR/reports/Report_AS1.md"
[[ -f "$REPORT" ]] || {
	echo "expected report missing: $REPORT" >&2
	exit 1
}

check_markdown "$REPORT" "$ROOT/guardrails/report.regex"

grep -q '\[mock\].*stage2 audit' "$RUN_DIR/logs/audit_AS1.log" || {
	echo "expected mock stage2 log line in audit_AS1.log" >&2
	exit 1
}

grep -q 'src/hybrid_mlkem\.c' "$REPORT" || {
	echo "expected report to reference path from AS1 card" >&2
	exit 1
}

echo "OK: stage2 audit-one mock tests passed"
