_LLM_VULN_LIB="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=guardrail.sh
source "$_LLM_VULN_LIB/guardrail.sh"

# _render_prompt INPUT_FILE RENDERED_FILE OUTPUT_FILE [EXTRA_CONTEXT...]
# Copies INPUT_FILE to RENDERED_FILE while expanding placeholders so the agent never
# has to derive concrete names/paths itself. Supported tokens:
#
#   {{OUTPUT_FILE}}        absolute OUTPUT_FILE
#   {{OUTPUT_BASENAME}}    basename of OUTPUT_FILE (e.g. "Report_AS1.md" or "_raw.md")
#   {{CONTEXT_FILE}}       absolute path of the first EXTRA_CONTEXT arg (empty if none)
#   {{CONTEXT_BASENAME}}   basename of CONTEXT_FILE            (e.g. "AS1.md")
#   {{CONTEXT_STEM}}       basename minus the last .ext        (e.g. "AS1")
#   {{OUTPUT_DIR}}         dirname of OUTPUT_FILE (e.g. .../AS or .../reports)
#   {{RUN_DIR}}            absolute RUN_DIR
#
# Safe: substitutes via bash parameter expansion, not sed, so slashes in paths are fine.
_render_prompt() {
	local input_file="$1"
	local rendered_file="$2"
	local output_file="$3"
	shift 3

	local context_file="${1:-}"
	local output_basename="${output_file##*/}"
	local output_dir="${output_file%/*}"
	local context_basename="${context_file##*/}"
	local context_stem="${context_basename%.*}"
	local run_dir="${RUN_DIR:-}"

	local body
	body="$(<"$input_file")"
	body="${body//\{\{OUTPUT_FILE\}\}/$output_file}"
	body="${body//\{\{OUTPUT_BASENAME\}\}/$output_basename}"
	body="${body//\{\{OUTPUT_DIR\}\}/$output_dir}"
	body="${body//\{\{CONTEXT_FILE\}\}/$context_file}"
	body="${body//\{\{CONTEXT_BASENAME\}\}/$context_basename}"
	body="${body//\{\{CONTEXT_STEM\}\}/$context_stem}"
	body="${body//\{\{RUN_DIR\}\}/$run_dir}"
	printf '%s\n' "$body" >"$rendered_file"
}

# run_agent PROMPT_FILE OUTPUT_FILE EXIT_CRITERIA_FILE MODEL [EXTRA_CONTEXT...]
#
#   PROMPT_FILE         markdown file with the task for the agent (may contain {{...}} tokens)
#   OUTPUT_FILE         file the agent MUST create (absolute path)
#   EXIT_CRITERIA_FILE  regex-per-line file used by the guardrail after the run
#   MODEL               model slug for backends that support it (empty = opencode CLI default)
#   EXTRA_CONTEXT       optional paths (passed to backend only)
#
# Requires: RUN_DIR set (for logs). Optional: RUN_AGENT_LOG (log basename, default: agent).
# Optional: RUN_AGENT_SKIP_GUARDRAIL=1 skips check_markdown on OUTPUT_FILE (e.g. stage 1 writes AS/*.md).
#
# Returns 0 on success, non-zero on backend failure OR guardrail failure.
run_agent() {
	local prompt_file="$1"
	local output_file="$2"
	local criteria_file="$3"
	local model="$4"
	shift 4

	if [[ -z "${RUN_DIR:-}" ]]; then
		echo "run_agent: RUN_DIR is not set" >&2
		return 1
	fi

	local backend="${AGENT_BACKEND:-opencode}"
	local root
	root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
	local backend_script="$root/lib/backends/${backend}.sh"
	if [[ ! -f "$backend_script" ]]; then
		echo "run_agent: unknown AGENT_BACKEND '$backend' (missing $backend_script)" >&2
		return 1
	fi

	# shellcheck source=/dev/null
	source "$backend_script"

	local log_file="$RUN_DIR/logs/${RUN_AGENT_LOG:-agent}.log"
	mkdir -p "$(dirname "$log_file")" "$(dirname "$output_file")"

	local rendered
	rendered="$(mktemp)"
	_render_prompt "$prompt_file" "$rendered" "$output_file" "$@"

	# Backends / logs may want the repo template path (rendered file is a temp path).
	export RUN_AGENT_PROMPT_TEMPLATE="$prompt_file"

	local rc=0
	backend_run "$rendered" "$output_file" "$model" "$log_file" "$@" || rc=$?
	unset RUN_AGENT_PROMPT_TEMPLATE
	rm -f "$rendered"
	((rc == 0)) || return "$rc"

	if [[ "${RUN_AGENT_SKIP_GUARDRAIL:-}" == 1 ]]; then
		return 0
	fi
	check_markdown "$output_file" "$criteria_file" || return 1
	return 0
}
