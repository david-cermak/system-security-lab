# stage_m1_smoke ROOT
# M1: single no-op agent step + guardrail (proves plumbing).
stage_m1_smoke() {
	local root="$1"
	local out="$RUN_DIR/smoke.md"
	RUN_AGENT_LOG=m1_smoke run_agent \
		"$root/prompts/m1_smoke.md" \
		"$out" \
		"$root/guardrails/m1_smoke.regex" \
		"${MODEL_SMOKE:-}"
}

# stage_attack_surface TARGET
# M2 stage 1: agent emits AS/AS{i}.md; guardrail each file. Sets global AS_FILES (basenames).
# Requires: RUN_DIR, sourced from repo root (for prompts path).
stage_attack_surface() {
	local target="$1"
	local root
	root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

	if [[ -z "${RUN_DIR:-}" ]]; then
		echo "stage_attack_surface: RUN_DIR is not set" >&2
		return 1
	fi
	if [[ ! -d "$target" ]]; then
		echo "stage_attack_surface: target is not a directory: $target" >&2
		return 1
	fi

	mkdir -p "$RUN_DIR/AS" "$RUN_DIR/logs"

	AS_FILES=()
	RUN_AGENT_SKIP_GUARDRAIL=1 \
		RUN_AGENT_LOG=stage1_attack_surface \
		run_agent \
		"$root/prompts/01_attack_surface.md" \
		"$RUN_DIR/AS/_raw.md" \
		"$root/guardrails/attack_surface.regex" \
		"${MODEL_AS:-}" \
		"$target" || return 1

	local spec="$root/guardrails/attack_surface.regex"
	shopt -s nullglob
	local paths=("$RUN_DIR/AS/AS"*.md)
	shopt -u nullglob
	if ((${#paths[@]} == 0)); then
		echo "stage_attack_surface: no AS*.md under $RUN_DIR/AS" >&2
		return 1
	fi

	local sorted line
	sorted="$(printf '%s\n' "${paths[@]}" | sort -V)"
	paths=()
	while IFS= read -r line || [[ -n "$line" ]]; do
		[[ -n "$line" ]] && paths+=("$line")
	done <<<"$sorted"

	local f base
	AS_FILES=()
	for f in "${paths[@]}"; do
		check_markdown "$f" "$spec" || return 1
		base="$(basename "$f")"
		AS_FILES+=("$base")
	done
	return 0
}

# stage_audit_surface_one AS_BASENAME
# M3 stage 2 (single surface): AS/AS{i}.md → reports/Report_{i}.md + report.regex guardrail.
# Requires: RUN_DIR, repo root via lib path. AS_BASENAME e.g. AS1.md
stage_audit_surface_one() {
	local as_basename="$1"
	local root
	root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

	if [[ -z "${RUN_DIR:-}" ]]; then
		echo "stage_audit_surface_one: RUN_DIR is not set" >&2
		return 1
	fi
	if [[ -z "$as_basename" ]]; then
		echo "stage_audit_surface_one: missing AS basename (e.g. AS1.md)" >&2
		return 1
	fi
	local as_path="$RUN_DIR/AS/$as_basename"
	if [[ ! -f "$as_path" ]]; then
		echo "stage_audit_surface_one: attack surface file not found: $as_path" >&2
		return 1
	fi

	mkdir -p "$RUN_DIR/reports" "$RUN_DIR/logs"

	local report_path="$RUN_DIR/reports/Report_${as_basename}"
	local log_tag
	log_tag="audit_${as_basename%.md}"

	RUN_AGENT_LOG="$log_tag" run_agent \
		"$root/prompts/02_audit_surface.md" \
		"$report_path" \
		"$root/guardrails/report.regex" \
		"${MODEL_AUDIT:-}" \
		"$as_path" || return 1
	return 0
}
