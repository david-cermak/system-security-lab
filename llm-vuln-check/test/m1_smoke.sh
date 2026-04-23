#!/usr/bin/env bash
# M1 integration test: mock backend + guardrail + negative check_markdown case.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

export RUN_DIR="$TMP/run"
export AGENT_BACKEND=mock
mkdir -p "$RUN_DIR/logs"

# shellcheck source=../lib/guardrail.sh
source "$ROOT/lib/guardrail.sh"
# shellcheck source=../lib/agent.sh
source "$ROOT/lib/agent.sh"
# shellcheck source=../lib/stages.sh
source "$ROOT/lib/stages.sh"

echo "== happy path: stage_m1_smoke with mock backend"
stage_m1_smoke "$ROOT"
[[ -f "$RUN_DIR/smoke.md" ]]
grep -q 'M1 smoke' "$RUN_DIR/smoke.md"
grep -q '\[mock\]' "$RUN_DIR/logs/m1_smoke.log"

echo "== guardrail rejects file missing required heading"
echo '# wrong' >"$TMP/bad.md"
if check_markdown "$TMP/bad.md" "$ROOT/guardrails/m1_smoke.regex"; then
	echo "expected check_markdown to fail" >&2
	exit 1
fi

echo "== guardrail rejects forbidden TODO"
cat >"$TMP/todo.md" <<'EOF'
# M1 smoke
## Summary
Fixed markdown for pipeline plumbing test.
TODO later
status: **pass**
EOF
if check_markdown "$TMP/todo.md" "$ROOT/guardrails/m1_smoke.regex"; then
	echo "expected forbidden TODO to fail" >&2
	exit 1
fi

echo "OK: m1_smoke tests passed"
