# backend_run PROMPT_FILE OUTPUT_FILE MODEL LOG_FILE [EXTRA_CONTEXT...]
# M1: writes fixed smoke.md content. Stage 1: when OUTPUT_FILE is .../AS/_raw.md, emits AS1..ASn
# matching the libssh-0.12.0 surfaces from README (mock-only deterministic output).
#
# For easy debugging, the log file gets three sections per invocation:
#   1. [mock] header with file paths, model, extra context
#   2. ===== INPUT PROMPT ===== : verbatim prompt (+ per-context-file dumps)
#   3. ===== OUTPUT ($output_file) ===== : verbatim output the mock wrote
# Set MOCK_QUIET=1 to suppress the dump (keeps the [mock] header only).
backend_run() {
	local prompt_file="$1"
	local output_file="$2"
	local model="$3"
	local log_file="$4"
	shift 4

	mkdir -p "$(dirname "$output_file")" "$(dirname "$log_file")"
	{
		echo "[mock] prompt_template=${RUN_AGENT_PROMPT_TEMPLATE:-$prompt_file} rendered_prompt=$prompt_file output_file=$output_file model=$model"
		echo "[mock] extra_context:" "$@"
	} >>"$log_file"

	_mock_dump_input "$prompt_file" "$log_file" "$@"

	case "$output_file" in
	*/AS/_raw.md)
		_mock_stage1_attack_surface "$output_file" "$log_file" "$@"
		_mock_dump_output "$output_file" "$log_file"
		return 0
		;;
	*/reports/Report_*.md)
		_mock_stage2_audit "$output_file" "$log_file" "$@"
		_mock_dump_output "$output_file" "$log_file"
		return 0
		;;
	esac

	cat >"$output_file" <<'EOF'
# M1 smoke

Fixed markdown for pipeline plumbing test.

## Summary

ok

status: **pass**
EOF
	_mock_dump_output "$output_file" "$log_file"
	return 0
}

# _mock_dump_input PROMPT_FILE LOG_FILE [EXTRA_CONTEXT...]
# Writes the prompt file + each extra-context file (if it exists) into LOG_FILE,
# bracketed by clear markers. Non-existent context entries are recorded as such.
_mock_dump_input() {
	local prompt_file="$1"
	local log_file="$2"
	shift 2
	[[ "${MOCK_QUIET:-0}" == 1 ]] && return 0

	{
		echo
		echo "===== INPUT PROMPT ($prompt_file) ====="
		if [[ -f "$prompt_file" ]]; then
			cat "$prompt_file"
		else
			echo "[mock] prompt file not found: $prompt_file"
		fi
		echo "===== END INPUT PROMPT ====="

		local c
		for c in "$@"; do
			echo
			echo "===== INPUT CONTEXT ($c) ====="
			if [[ -f "$c" ]]; then
				cat "$c"
			elif [[ -d "$c" ]]; then
				echo "[mock] context is a directory; listing:"
				(cd "$c" && ls -1) || true
			else
				echo "[mock] context not found: $c"
			fi
			echo "===== END INPUT CONTEXT ====="
		done
	} >>"$log_file"
}

# _mock_dump_output OUTPUT_FILE LOG_FILE
_mock_dump_output() {
	local output_file="$1"
	local log_file="$2"
	[[ "${MOCK_QUIET:-0}" == 1 ]] && return 0

	{
		echo
		echo "===== OUTPUT ($output_file) ====="
		if [[ -f "$output_file" ]]; then
			cat "$output_file"
		else
			echo "[mock] output file not written: $output_file"
		fi
		echo "===== END OUTPUT ====="
	} >>"$log_file"
}

_mock_stage1_attack_surface() {
	local output_file="$1"
	local log_file="$2"
	shift 2
	local as_dir
	as_dir="$(dirname "$output_file")"
	echo "[mock] stage1: writing AS*.md under $as_dir" >>"$log_file"

	cat >"$output_file" <<'EOF'
AS1.md
AS2.md
AS3.md
AS4.md
AS5.md
AS6.md
EOF

	_write_as_card "$as_dir/AS1.md" \
		"PQ / hybrid ML-KEM key exchange" \
		"src/hybrid_mlkem.c" \
		"New hybrid KEX parses peer public material and drives post-quantum shared secret derivation; memory-safety and downgrade edges matter."

	_write_as_card "$as_dir/AS2.md" \
		"SFTP client ID/group resolution" \
		"src/sftp.c" \
		"sftp_get_users_groups_by_id() adds client-side parsing and credential mapping that may trust server-supplied identifiers."

	_write_as_card "$as_dir/AS3.md" \
		"SFTP server open / truncate handling" \
		"src/sftpserver.c" \
		"SSH_FXF_TRUNC handling in process_open changes file lifecycle on the server; correctness bugs become authorization or data-loss issues."

	_write_as_card "$as_dir/AS4.md" \
		"SSH signature sign/verify (ssh-sig)" \
		"src/pki.c" \
		"sshsig_sign() / sshsig_verify() implement a new signing profile; parser and algorithm-choice bugs affect authentication boundaries."

	_write_as_card "$as_dir/AS5.md" \
		"Security key (FIDO / U2F) integration" \
		"src/pki_sk.c" \
		"pki_sk.c and sk_usbhid.c handle hardware-backed keys; USB HID framing and callback parsing are untrusted input surfaces."

	_write_as_card "$as_dir/AS6.md" \
		"GSSAPI key exchange" \
		"src/kex-gss.c" \
		"GSSAPI KEX adds OID/token negotiation paths; spurious or oversized tokens stress allocators and state machines."
}

_write_as_card() {
	local path="$1"
	local title="$2"
	local relpath="$3"
	local rationale="$4"
	mkdir -p "$(dirname "$path")"
	cat >"$path" <<EOF
---
title: $title
paths:
  - $relpath
rationale: $rationale
---

# $title

## Scope

- Primary: \`$relpath\`
- Review call paths from KEX/auth into this compilation unit.

## Notes

Mock agent output for pipeline stage 1 (deterministic).
EOF
}

# Stage 2 audit: deterministic Report_*.md from first AS context file.
_mock_stage2_audit() {
	local output_file="$1"
	local log_file="$2"
	shift 2
	local as_file="${1:-}"
	echo "[mock] stage2 audit: output=$output_file as_file=${as_file:-"(none)"}" >>"$log_file"

	local relpath=""
	if [[ -n "$as_file" && -f "$as_file" ]]; then
		relpath="$(grep -E '^[[:space:]]+-[[:space:]]+src/' "$as_file" | head -1 | sed -E 's/^[[:space:]]+-[[:space:]]+//')"
	fi
	[[ -z "$relpath" ]] && relpath="src/unknown.c"

	local title="Mock audit"
	if [[ -n "$as_file" && -f "$as_file" ]]; then
		title="$(grep -E '^title:' "$as_file" | head -1 | sed -E 's/^title:[[:space:]]+//')"
		[[ -z "$title" ]] && title="Mock audit"
	fi

	cat >"$output_file" <<EOF
# Report — $title

## Summary

Mock stage-2 audit for this surface. Parser and handshake edges around \`$relpath\` are the focus;
output is deterministic for pipeline tests.

## Location

- Primary: \`$relpath\`
- Related entry points described in the attack-surface card.

## Impact

A defect in parsing or shared-secret handling could weaken confidentiality or integrity of the
channel for peers using this KEX or surface.

## Reproduction

1. Build the target with this code path enabled.
2. Exercise the handshake or API surface with edge-case lengths and algorithm negotiation.

## Suggested fix

Add strict bounds checks before copying peer material; reject ambiguous or undersized payloads
early. Align error handling with surrounding KEX code.

status: **reviewed**
EOF
}
