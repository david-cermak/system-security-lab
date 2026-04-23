# backend_run PROMPT_FILE OUTPUT_FILE MODEL LOG_FILE [EXTRA_CONTEXT...]
# Invokes opencode run; agent must write OUTPUT_FILE. Stdout/stderr -> LOG_FILE.
#
# CLI notes (opencode run, v1.14+):
#   - Working directory: --dir PATH (not --cwd).
#   - A message is REQUIRED. `opencode run -f FILE` alone errors with
#     "You must provide a message or a command".
#   - Stdin is accepted as the message: `opencode run < message.md` works.
#   - `-f` is declared as an array option (yargs) so it greedily absorbs subsequent
#     positional args — passing the message as a positional after `-f` causes
#     "File not found: …" errors. We therefore deliver the prompt via stdin only.
#
# Working directory (--dir):
#   Pipeline outputs live under RUN_DIR, but the code under review is usually elsewhere
#   (e.g. libssh-0.12.0). Prefer AGENT_WORKDIR if set; else the first extra_context path
#   that is a directory (stage 1 passes the target tree); else RUN_DIR.
backend_run() {
	local prompt_file="$1"
	local output_file="$2"
	local model="$3"
	local log_file="$4"
	shift 4

	mkdir -p "$(dirname "$log_file")"

	local workdir="${RUN_DIR:-.}"
	if [[ -n "${AGENT_WORKDIR:-}" ]]; then
		workdir="$AGENT_WORKDIR"
	else
		local ctx
		for ctx in "$@"; do
			if [[ -d "$ctx" ]]; then
				workdir="$ctx"
				break
			fi
		done
	fi
	if [[ ! -d "$workdir" ]]; then
		{
			echo "backend opencode: working directory is not a directory: $workdir"
		} >>"$log_file"
		echo "backend opencode: working directory is not a directory: $workdir" >&2
		return 1
	fi
	workdir="$(cd "$workdir" && pwd)"

	local composed
	composed="$(mktemp)"
	{
		cat "$prompt_file"
		echo
		echo "---"
		echo "You MUST write the final deliverable to this exact path:"
		echo "$output_file"
		echo
		echo "Exit criteria (regex, one per line) are in the guardrail spec passed to the orchestrator."
		echo
		echo "Tool working directory for this run (\`opencode --dir\`): $workdir"
		if (($# > 0)); then
			echo
			echo "Additional context paths (read-only hints):"
			local p
			for p in "$@"; do
				echo "  $p"
			done
		fi
	} >"$composed"

	if ! command -v opencode >/dev/null 2>&1; then
		rm -f "$composed"
		{
			echo "backend opencode: 'opencode' not found in PATH"
		} >>"$log_file"
		echo "backend opencode: 'opencode' not found in PATH" >&2
		return 127
	fi

	local ec=0
	local -a cmd=(opencode run)
	# Omit -m to use opencode's default model (e.g. build · claude-opus-4.6).
	[[ -n "$model" ]] && cmd+=(-m "$model")
	cmd+=(--dir "$workdir")
	# Deliver the full prompt via stdin; see CLI notes above.
	"${cmd[@]}" <"$composed" >>"$log_file" 2>&1 || ec=$?
	rm -f "$composed"
	return "$ec"
}
