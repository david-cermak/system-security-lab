# check_markdown OUTPUT_FILE REGEX_SPEC
#   REGEX_SPEC: newline-separated; empty lines skipped;
#   lines starting with '#' (after leading whitespace) are comments;
#   lines starting with '!' (after leading whitespace) are forbidden patterns (must NOT match);
#   every other non-empty line is a required pattern (must match at least once).
#
# Exits non-zero on first violation and prints which pattern failed.
check_markdown() {
	local file="$1"
	local spec="$2"

	if [[ ! -f "$file" ]]; then
		echo "check_markdown: missing file: $file" >&2
		return 1
	fi
	if [[ ! -f "$spec" ]]; then
		echo "check_markdown: missing spec: $spec" >&2
		return 1
	fi

	local line trimmed pattern
	while IFS= read -r line || [[ -n "$line" ]]; do
		trimmed="${line#"${line%%[![:space:]]*}"}"
		[[ -z "$trimmed" ]] && continue
		[[ "$trimmed" == \#* ]] && continue
		if [[ "$trimmed" == !* ]]; then
			pattern="${trimmed#!}"
			pattern="${pattern#"${pattern%%[![:space:]]*}"}"
			[[ -z "$pattern" ]] && continue
			if grep -E -q "$pattern" "$file"; then
				echo "check_markdown: forbidden pattern matched in $file: $pattern" >&2
				return 1
			fi
		else
			pattern="$trimmed"
			if ! grep -E -q "$pattern" "$file"; then
				echo "check_markdown: required pattern not found in $file: $pattern" >&2
				return 1
			fi
		fi
	done < "$spec"
	return 0
}
